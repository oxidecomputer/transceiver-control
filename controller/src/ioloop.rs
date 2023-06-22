// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Implementation of the main IO loop logic.

use crate::messages::*;
use crate::probes;
use crate::Error;
use crate::NUM_ALLOWED_ERROR_MESSAGES;
use crate::NUM_OUTSTANDING_REQUESTS;
use slog::debug;
use slog::error;
use slog::trace;
use slog::Logger;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::SocketAddrV6;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::interval;
use tokio::time::Duration;
use tokio::time::Interval;
use transceiver_messages::message;
use transceiver_messages::message::Header;
use transceiver_messages::message::Message;
use transceiver_messages::message::MessageBody;
use transceiver_messages::message::MessageKind;
use transceiver_messages::message::ProtocolError;
use transceiver_messages::MAX_PACKET_SIZE;

// A POD type holding the data we need for the main I/O loop. See `IoLoop::run`
// for details.
#[derive(Debug)]
pub(crate) struct IoLoop {
    log: Logger,
    socket: UdpSocket,
    peer_addr: SocketAddrV6,
    n_retries: usize,
    resend: Interval,
    // Channel on which we receive outgoing requests from `Controller`. These
    // are pulled and sent over the UDP socket to the SP, possibly retrying.
    outgoing_request_rx: mpsc::Receiver<OutstandingHostRequest>,

    // The current outstanding request from `outgoing_request_tx`, if any.
    outstanding_request: Option<OutstandingHostRequest>,

    // The channel on which we dispatch incoming requests from the SP, to the
    // request handler. The items sent include a send-half for our
    // `outgoing_response_rx`.
    incoming_request_tx: mpsc::Sender<SpRequest>,

    // The channel on which we wait for outgoing responses from the request
    // handler. These are sent on the UDP socket to the SP.
    outgoing_response_rx: mpsc::Receiver<Result<Option<HostRpcResponse>, Error>>,

    // A sender for `outgoing_response_rx`.
    //
    // This is never used, but we need to maintain a send-half to
    // `outgoing_response_rx` so that receiving on it does not immediately
    // return errors.
    outgoing_response_tx: mpsc::Sender<Result<Option<HostRpcResponse>, Error>>,
}

impl IoLoop {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        log: Logger,
        socket: UdpSocket,
        peer_addr: SocketAddrV6,
        n_retries: Option<usize>,
        retry_interval: Duration,
        outgoing_request_rx: mpsc::Receiver<OutstandingHostRequest>,
        incoming_request_tx: mpsc::Sender<SpRequest>,
    ) -> Self {
        let (outgoing_response_tx, outgoing_response_rx) = mpsc::channel(NUM_OUTSTANDING_REQUESTS);
        Self {
            log,
            socket,
            peer_addr,
            n_retries: n_retries.unwrap_or(usize::MAX),
            resend: interval(retry_interval),
            outgoing_request_rx,
            outstanding_request: None,
            incoming_request_tx,
            outgoing_response_rx,
            outgoing_response_tx,
        }
    }

    // Send an outgoing response.
    async fn send_outgoing_response(&mut self, response: HostRpcResponse, tx_buf: &mut [u8]) {
        let data_start = hubpack::serialize(tx_buf, &response.message).unwrap();
        let msg_size = if let Some(data) = &response.data {
            let data_end = data_start + data.len();
            tx_buf[data_start..data_end].copy_from_slice(data);
            data_end
        } else {
            data_start
        };
        match self
            .socket
            .send_to(&tx_buf[..msg_size], &self.peer_addr)
            .await
        {
            Err(e) => {
                error!(
                    self.log,
                    "failed to send outgoing response";
                    "peer" => ?self.peer_addr,
                    "reason" => ?e,
                );
            }
            Ok(n_bytes) => {
                assert_eq!(n_bytes, msg_size);
                trace!(
                    self.log,
                    "sent outgoing response";
                    "peer" => ?self.peer_addr,
                    "message" => ?response.message,
                );
                probes::packet__sent!(|| {
                    let peer = IpAddr::V6(*self.peer_addr.ip());
                    (peer, n_bytes as u64, tx_buf.as_ptr())
                });
                probes::message__sent!(|| {
                    let peer = IpAddr::V6(*self.peer_addr.ip());
                    (peer, &response.header, &response.message)
                });
            }
        }
    }

    // Send an outgoing request.
    //
    // Panics if there is no outstanding request.
    async fn send_outgoing_request(&mut self, tx_buf: &mut [u8]) {
        // Safety: Serialization can only fail in a few constrained
        // circumstances, such as a buffer overrun or unsupported types. None of
        // those apply here, so we just unwrap in that direction.
        let mut request = self.outstanding_request.as_mut().unwrap();

        // Serialize the header first.
        //
        // As we serialize in data, we need to keep track of two things:
        //
        // - Where we currently are writing data into
        // - The full size of the _packet_.
        let mut packet_size = 0;
        let header_size = hubpack::serialize(tx_buf, &request.request.header).unwrap();
        packet_size += header_size;

        // Serialize the message next, after the header.
        let msg_size =
            hubpack::serialize(&mut tx_buf[packet_size..], &request.request.message).unwrap();
        packet_size += msg_size;

        // Copy in the data, if any.
        let data_size = if let Some(data) = &request.request.data {
            tx_buf[packet_size..][..data.len()].copy_from_slice(data);
            data.len()
        } else {
            0
        };
        packet_size += data_size;

        // Send the entire TX buffer on the wire.
        match self
            .socket
            .send_to(&tx_buf[..packet_size], &self.peer_addr)
            .await
        {
            Err(e) => {
                error!(
                    self.log,
                    "failed to send outgoing request";
                    "peer" => ?self.peer_addr,
                    "reason" => ?e,
                );

                // We also need to fail the request right away.
                //
                // Retrying here is almost certainly going to fail again,
                // without additional intervention by the caller. For example,
                // if the interface we're sending packets over disappeared,
                // we'll never be able to recover without rebinding the UDP
                // socket.
                self.outstanding_request
                    .take()
                    .expect("verified as Some(_) above")
                    .response_tx
                    .send(Err(Error::Io(e)))
                    .expect("failed to send response on channel");
                return;
            }
            Ok(n_bytes) => {
                assert_eq!(n_bytes, packet_size);
                trace!(
                    self.log,
                    "sent outgoing request";
                    "peer" => ?self.peer_addr,
                    "message" => ?request.request.message,
                );
                probes::packet__sent!(|| {
                    let peer = IpAddr::V6(*self.peer_addr.ip());
                    (peer, n_bytes as u64, tx_buf.as_ptr())
                });
                probes::message__sent!(|| {
                    let peer = IpAddr::V6(*self.peer_addr.ip());
                    (peer, &request.request.header, &request.request.message)
                });
                self.resend.reset();
            }
        }
        // Increment the number of attempts, regardless of whether we could
        // successfully send the request or not. The error could be on "our"
        // side, e.g. an IP address or interface went away, but that should
        // still be considered an attempt. Otherwise, we may retry indefinitely.
        request.n_retries += 1;
    }

    // Send a `message::ErrorMessage` to the peer, with the included error type.
    async fn send_protocol_error(
        &self,
        peer: &SocketAddr,
        header: Header,
        err: ProtocolError,
        tx_buf: &mut [u8],
    ) {
        let message = Message::from(err);
        // Serialize the header, followed by the message itself.
        let header_len = hubpack::serialize(tx_buf, &header).unwrap();
        let msg_len = hubpack::serialize(&mut tx_buf[header_len..], &message).unwrap();
        let serialized_len = header_len + msg_len;
        match self.socket.send_to(&tx_buf[..serialized_len], peer).await {
            Err(e) => {
                error!(
                    self.log,
                    "failed to send protocol error";
                    "reason" => ?e,
                    "peer" => peer
                );
            }
            Ok(n_bytes) => {
                debug!(
                    self.log,
                    "sent protocol error";
                    "peer" => ?self.peer_addr,
                    "message" => ?message,
                );
                probes::packet__sent!(|| {
                    let peer = IpAddr::V6(*self.peer_addr.ip());
                    (peer, n_bytes as u64, tx_buf.as_ptr())
                });
                probes::message__sent!(|| {
                    let peer = IpAddr::V6(*self.peer_addr.ip());
                    (peer, &header, &message)
                });
                assert_eq!(n_bytes, serialized_len);
            }
        }
    }

    // Handle a request from the SP, dispatching it to our request queue.
    async fn handle_sp_request(
        &mut self,
        peer: &SocketAddr,
        header: Header,
        rx_buf: &[u8],
        tx_buf: &mut [u8],
    ) {
        match hubpack::deserialize(rx_buf) {
            Ok((message, _remainder)) => {
                probes::message__received!(|| (peer.ip(), &header, &message));
                debug!(
                    self.log,
                    "SP request message received";
                    "peer" => peer,
                    "message" => ?message,
                );
                let request = SpRpcRequest {
                    header,
                    message,
                    data: None,
                };
                let item = SpRequest {
                    request,
                    response_tx: self.outgoing_response_tx.clone(),
                };
                self.incoming_request_tx
                    .send(item)
                    .await
                    .expect("failed to dispatch incoming request on handler channel");
                debug!(self.log, "sent incoming SP request on handler channel");
            }
            Err(e) => {
                error!(
                    self.log,
                    "failed to deserialize SP request";
                    "peer" => peer,
                    "message_kind" => ?header.message_kind,
                );
                probes::bad__message!(|| {
                    (
                        peer.ip(),
                        format!("failed to deserialize SP request: {e:?}"),
                    )
                });
                let response_header = Header::new(header.message_id, MessageKind::Error);
                self.send_protocol_error(
                    peer,
                    response_header,
                    ProtocolError::Serialization,
                    tx_buf,
                )
                .await;
            }
        }
    }

    async fn handle_sp_error(&mut self, peer: &SocketAddr, header: Header, rx_buf: &[u8]) {
        match hubpack::deserialize::<Message>(rx_buf) {
            Ok((message, _)) => {
                let MessageBody::Error(err) = message.body else {
                    error!(
                        self.log,
                        "mismatch between header message kind and message";
                        "peer" => peer,
                        "header_version" => header.version(),
                        "message_id" => header.message_id,
                        "message_kind" => ?header.message_kind,
                        "message" => ?message,
                    );
                    probes::bad__message!(|| (
                        peer.ip(),
                        format!(
                            "mismatched header and message kinds, \
                            header = {:?}, message = {:?}",
                            header.message_kind,
                            message.kind(),
                        ),
                    ));
                    self.increment_faulty_message_count();
                    return;
                };

                probes::message__received!(|| (peer.ip(), &header, &message));
                debug!(
                    self.log,
                    "SP error message received";
                    "peer" => peer,
                    "message" => ?message,
                );

                // If this is for our outstanding request, possibly fail it.
                self.increment_faulty_message_count();
                self.fail_matching_outstanding_request(&header, err).await;
            }
            Err(e) => {
                // We've failed to deserialize an error message from the peer.
                //
                // Fail any matching oustanding request.
                error!(
                    self.log,
                    "failed to deserialize error message from peer";
                    "peer" => peer,
                    "header_version" => header.version(),
                    "message_id" => header.message_id,
                    "message_kind" => ?header.message_kind,
                );
                probes::bad__message!(|| (
                    peer.ip(),
                    format!("failed to deserialize error message: {e:?}")
                ));

                self.increment_faulty_message_count();
                self.fail_matching_outstanding_request(&header, ProtocolError::Serialization)
                    .await;
            }
        }
    }

    // Increment our allowed failure counter if we have an outstanding request.
    fn increment_faulty_message_count(&mut self) {
        if let Some(request) = self.outstanding_request.as_mut() {
            request.n_error_messages += 1;
            debug!(
                self.log,
                "noting faulty message";
                "n_error_messages" => request.n_error_messages,
            );
        }
    }

    // Helper method to fail an oustanding request with a protocol error.
    //
    // This:
    //
    // - Checks if we have an outstanding request, and returns if not
    // - Returns if that message ID doesn't match the header message ID.
    // - Then takes the outstanding request away, and injects the provided `err`
    // on its response channel.
    async fn fail_matching_outstanding_request(&mut self, header: &Header, err: ProtocolError) {
        if let Some(request) = &self.outstanding_request {
            if request.request.header.message_id != header.message_id {
                return;
            }
        } else {
            return;
        };
        self.outstanding_request
            .take()
            .expect("verified as Some(_) above")
            .response_tx
            .send(Err(Error::Protocol(err)))
            .expect("failed to send response on channel");
    }

    // Handle a response from the SP, possibly for our outstanding request.
    async fn handle_sp_response(&mut self, peer: &SocketAddr, header: Header, rx_buf: &[u8]) {
        if self.outstanding_request.is_none() {
            // Without an outstanding request, this message is an error.
            // However, we avoid blaming the peer. Using UDP as the transport
            // means it's feasible we receive a response twice, or one is so
            // delayed that we've retried the request. That's not really a
            // protocol error, it's just inherent in our choice of transport.
            //
            // Drop the message.
            probes::bad__message!(|| {
                (
                    peer.ip(),
                    "received response without an outstanding request",
                )
            });
            debug!(
                self.log,
                "receive response without an outstanding request";
                "peer" => peer,
                "header_version" => header.version(),
                "message_id" => header.message_id,
                "message_kind" => ?header.message_kind,
            );
            return;
        };

        // Deserialize the message itself.
        //
        // If that fails, we first check if this seems to have been meant for
        // an outstanding request by checking the ID. If so, we send back an
        // error on the outstanding request's response channel.
        let (message, remainder) = match hubpack::deserialize::<Message>(rx_buf) {
            Ok((message, remainder)) => {
                probes::message__received!(|| (peer.ip(), &header, &message));
                trace!(
                    self.log,
                    "SP response message received";
                    "peer" => peer,
                    "message" => ?message,
                );
                (message, remainder)
            }
            Err(e) => {
                error!(
                    self.log,
                    "failed to deserialize SP response";
                    "peer" => peer,
                    "header_version" => header.version(),
                    "message_id" => header.message_id,
                    "message_kind" => ?header.message_kind,
                    "reason" => ?e,
                );
                probes::bad__message!(|| { (peer.ip(), format!("deserialization failed: {e:?}")) });
                // Which kind of error we send depends on the version.
                //
                // If we fail to deserialize a message with a version less than
                // `MIN`, we presume that's actually a version-mismatch error.
                // If the version is greater than `MIN`, because we've committed
                // to compatibility, we _should_ be able to deserialize it. That
                // means this is really a deserialization error, like a bad
                // buffer or corrupt packet. The version is the first octet of
                // the message body.
                let message_version = rx_buf[0];
                let err = if message_version < message::version::inner::MIN {
                    ProtocolError::VersionMismatch {
                        expected: message::version::inner::CURRENT,
                        actual: message_version,
                    }
                } else {
                    ProtocolError::Serialization
                };
                self.increment_faulty_message_count();
                self.fail_matching_outstanding_request(&header, err).await;
                return;
            }
        };

        // Sanity check that we get the same kind of response from the SP as
        // indicated in the header.
        let response = match message.body {
            MessageBody::SpResponse(response) => response,
            _ => {
                // TODO-correctness: It's not clear what to do here. Sending a
                // protocol error to the peer seems reasonable, but the software
                // running there is clearly buggy. For now, let's avoid doing
                // anything.
                let kind = message.kind();
                probes::bad__message!(|| (
                    peer.ip(),
                    format!(
                        "header message kind and actual message do not \
                        match, header = {:?} message = {:?}",
                        header.message_kind, kind,
                    )
                ));
                error!(
                    self.log,
                    "header message kind and actual message do not match";
                    "peer" => peer,
                    "message_id" => header.message_id,
                    "message_kind" => ?header.message_kind,
                    "message" => ?kind,
                );

                // Inject an error message back to response channel, if we have
                // one. We don't expect a useful reply here, in the absence of
                // an update on the SP.
                self.fail_matching_outstanding_request(&header, ProtocolError::WrongMessage)
                    .await;
                return;
            }
        };

        // This is a response, possibly for our outstanding request.
        //
        // Note that we can't take the message now, since the
        // response may not actually correspond to our outstanding
        // request. We take the request later if needed.
        let maybe_response = if let Some(request) = &self.outstanding_request {
            // Check if this is for our current outstanding request.
            let outstanding_message_id = request.request.header.message_id;
            if outstanding_message_id == header.message_id {
                // We have a valid response!
                //
                // Collect any trailing data that is supposed to exist, and
                // return it. Note that we _also_ need to collect any trailing
                // error data.
                let expected_data_len = response.expected_data_len();
                let expected_error_len = response.expected_error_data_len();
                let response = match (expected_data_len, expected_error_len) {
                    (None, None) => Ok(SpRpcResponse {
                        header,
                        message,
                        data: None,
                    }),
                    (dl, el) => {
                        let expected_len = dl.unwrap_or(0) + el.unwrap_or(0);
                        if remainder.len() < expected_len {
                            error!(
                                self.log,
                                "message did not contain expected data";
                                "expected_len" => expected_len,
                                "actual_len" => remainder.len(),
                                "peer" => peer,
                            );
                            let err = ProtocolError::WrongDataSize {
                                expected: u32::try_from(expected_len).unwrap(),
                                actual: u32::try_from(remainder.len()).unwrap(),
                            };
                            probes::bad__message!(|| (peer.ip(), format!("{:?}", err)));

                            // Note that we're intentionally _not_ sending a
                            // `ProtocolError` here.
                            //
                            // We've received an invalid message from the SP,
                            // but it's unlikely this will help anything. In
                            // particular, we already know that the SP software
                            // is misbehaving, and we can log or report that
                            // fact to the host. It's not obvious what the SP
                            // would do in addition, and it certainly can't
                            // start sending valid messages without an update.

                            // We also need to fail the outstanding request
                            // here.
                            let err = ProtocolError::WrongDataSize {
                                expected: u32::try_from(expected_len).unwrap(),
                                actual: u32::try_from(remainder.len()).unwrap(),
                            };
                            Err(Error::Protocol(err))
                        } else {
                            let data = Some(remainder[..expected_len].to_vec());
                            trace!(
                                self.log,
                                "received trailing data";
                                "data" => ?data,
                                "n_bytes" => expected_len,
                            );
                            Ok(SpRpcResponse {
                                header,
                                message,
                                data,
                            })
                        }
                    }
                };
                Some(response)
            } else {
                probes::bad__message!(|| {
                    (peer.ip(), "response for request that is not outstanding")
                });
                debug!(
                    self.log,
                    "received response for message that is not outstanding";
                    "message" => ?message,
                    "outstanding_message_id" => outstanding_message_id,
                    "peer" => peer,
                );
                None
            }
        } else {
            unreachable!("Outstanding request checked above");
        };

        // If we have a valid response, take out the outstanding
        // message and forward the response on its channel.
        if let Some(response) = maybe_response {
            self.outstanding_request
                .take()
                .expect("verified as Some(_) above")
                .response_tx
                .send(response)
                .expect("failed to send response on channel");
        }
    }

    // Main IO loop for communicating with the SP.
    //
    // This task is responsible for accepting messages from the host for delivery to
    // the SP (outgoing) and those from the SP to the host (incoming). The outgoing
    // messages are accepted from two channels:
    //
    // - `self.outgoing_request_rx` receives messages from the `Controller`
    // object itself, as part of the implementation of its public API.
    // - `self.outgoing_response_rx` receives messages from the
    // `request_handler` used to construct the `Controller`, and delivers the
    // host's desired responses to a SP request.
    //
    // These are serialized and sent over the contained UDP socket to the multicast
    // address defined in `transceiver_messages::ADDR`.
    //
    // This task also listens for incoming messages on the UDP socket from the SP.
    // These are deserialized and sanity checked. (Obvious failures result in an
    // error being sent back immediately.) Assuming they seem reasonable, then they
    // are dispatched as follows:
    //
    // - Requests from the SP are sent on `self.incoming_request_tx`. Responses
    // to those incoming requests are received back by this loop on a oneshot
    // channel, which is contained in the `SpRequest` items sent on
    // `self.incoming_request_tx`.
    //
    // - Responses to our own initiated requests are sent back on a `oneshot`
    // channel, that is sent in the data on `outgoing_request_tx`.
    pub(crate) async fn run(mut self) {
        let mut rx_buf = [0; MAX_PACKET_SIZE];
        let mut tx_buf = [0; MAX_PACKET_SIZE];

        loop {
            tokio::select! {
                // Poll for outgoing requests, but only if we don't already _have_
                // an outstanding request.
                maybe_request = self.outgoing_request_rx.recv(), if self.outstanding_request.is_none() => {

                    // We only get `None` if the sender is closed, meaning the task
                    // holding that side exited. Nothing else will come down this
                    // channel, and things are likely borked. Bail out.
                    let request = match maybe_request {
                        Some(r) => r,
                        None => {
                            debug!(self.log, "outgoing response channel closed, exiting");
                            return;
                        }
                    };
                    trace!(self.log, "received outgoing request"; "request" => ?request);

                    // Store the outstanding request, sanity-checking that we really
                    // didn't have a prior one.
                    let old = self.outstanding_request.replace(request);
                    assert!(
                        old.is_none(),
                        "dequeued a new request while one is already outstanding!",
                    );
                    self.send_outgoing_request(&mut tx_buf).await;
                }

                // If we _do_ have an outstanding request, we need to resend it
                // periodically until we get a response. Wait for up to the resend
                // interval of inactivity, and then possibly retry.
                _ = self.resend.tick(), if self.outstanding_request.is_some() => {
                    let (n_retries, n_error_messages) = {
                        let req = self.outstanding_request.as_ref().unwrap();
                        (req.n_retries, req.n_error_messages)
                    };
                    let at_retry_limit = n_retries >= self.n_retries;
                    let at_error_limit = n_error_messages >= NUM_ALLOWED_ERROR_MESSAGES;

                    if !at_retry_limit && !at_error_limit {
                        debug!(self.log, "timed out without response, retrying");
                        self.send_outgoing_request(&mut tx_buf).await;
                        continue;
                    }

                    // We're failing the request, for one of two reasons. So
                    // always remove it.
                    //
                    // Safety: This branch is only taken if the request is `Some(_)`.
                    let old = self.outstanding_request.take().unwrap();
                    if at_retry_limit {
                        error!(
                            self.log,
                            "failed to send message within retry limit";
                            "limit" => self.n_retries,
                        );
                        old.response_tx.send(Err(Error::MaxRetries(n_retries))).unwrap();
                        continue;
                    }
                    if at_error_limit {
                        error!(
                            self.log,
                            "received too many faulty messages";
                            "limit" => NUM_ALLOWED_ERROR_MESSAGES,
                        );
                        old.response_tx.send(Err(Error::MaxFaultMessages(n_error_messages))).unwrap();
                        continue;
                    }
                }

                // Poll for outgoing responses we need to send.
                maybe_response = self.outgoing_response_rx.recv() => {
                    let response = match maybe_response {
                        Some(r) => r,
                        None => {
                            debug!(self.log, "outgoing response channel closed, exiting");
                            return;
                        }
                    };
                    match response {
                        Ok(Some(r)) => {
                            trace!(
                                self.log,
                                "received outgoing response";
                                "message" => ?r.message,
                            );
                            self.send_outgoing_response(r, &mut tx_buf).await;
                        }
                        Ok(None) => {
                            trace!(
                                self.log,
                                "request handler explicitly dropped message"
                            );
                        }
                        Err(e) => {
                            error!(
                                self.log,
                                "request handler failed";
                                "error" => ?e
                            );
                        }
                    }
                }

                // Poll for incoming packets.
                res = self.socket.recv_from(&mut rx_buf) => {
                    let (n_bytes, peer) = match res {
                        Err(e) => {
                            error!(self.log, "I/O error receiving UDP packet: {e:?}");
                            self.increment_faulty_message_count();
                            continue;
                        }
                        Ok((n_bytes, peer)) => {
                            trace!(
                                self.log,
                                "packet received";
                                "n_bytes" => n_bytes,
                                "peer" => peer,
                            );
                            probes::packet__received!(|| {
                                (peer.ip(), n_bytes as u64, rx_buf.as_ptr())
                            });
                            (n_bytes, peer)
                        }
                    };

                    // The portion of `rx_buf` which contains the actual message
                    // from the peer.
                    let msg_buf = &rx_buf[..n_bytes];

                    let (header, remainder) = match hubpack::deserialize::<Header>(msg_buf) {
                        Err(e) => {
                            // Failed to deserialize the header. This is most
                            // unexpected.
                            error!(
                                self.log,
                                "failed to deserialize message header";
                                "peer" => peer,
                                "n_bytes" => n_bytes,
                                "reason" => ?e,
                            );
                            probes::bad__message!(|| (
                                peer.ip(), "failed to deserialize header: {e:?}",
                            ));
                            self.increment_faulty_message_count();
                            continue;
                        }
                        Ok(m) => m,
                    };

                    // Handle the message based on its kind.
                    match header.message_kind {
                        MessageKind::HostRequest | MessageKind::HostResponse => {
                            error!(
                                self.log,
                                "received invalid message kind";
                                "peer" => peer,
                                "message_kind" => ?header.message_kind,
                            );
                            probes::bad__message!(|| {
                                (peer.ip(), format!("invalid message kind: {:?}", header.message_kind))
                            });
                            self.increment_faulty_message_count();

                            // Inform the peer that they sent us a bogus
                            // message.
                            self.send_protocol_error(
                                &peer,
                                header,
                                ProtocolError::WrongMessage,
                                &mut tx_buf,
                            ).await;
                        }
                        MessageKind::Error => self.handle_sp_error(
                                &peer,
                                header,
                                remainder,
                            ).await,
                        MessageKind::SpRequest => self.handle_sp_request(
                                &peer,
                                header,
                                remainder,
                                &mut tx_buf
                            ).await,
                        MessageKind::SpResponse => self.handle_sp_response(
                                &peer,
                                header,
                                remainder,
                            ).await,
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::messages::HostRpcRequest;
    use crate::messages::OutstandingHostRequest;
    use crate::test_utils;
    use crate::test_utils::Channels;
    use crate::test_utils::SocketPair;
    use crate::Error;
    use hubpack::SerializedSize;
    use std::mem::size_of;
    use tokio::sync::oneshot;
    use transceiver_messages::message::Header;
    use transceiver_messages::message::HostRequest;
    use transceiver_messages::message::HwError;
    use transceiver_messages::message::Message;
    use transceiver_messages::message::MessageBody;
    use transceiver_messages::message::MessageKind;
    use transceiver_messages::message::ProtocolError;
    use transceiver_messages::message::SpResponse;
    use transceiver_messages::message::Status;
    use transceiver_messages::ModuleId;
    use transceiver_messages::MAX_PACKET_SIZE;

    // Check that we correctly handle the happy case:
    //
    // - Send a request into the IO Loop
    // - That's sent on the UDP socket
    // - The SP sends the IO Loop the expected response and version
    // - The IO Loop hands that back to the oneshot reply channel.
    #[tokio::test]
    async fn test_handle_sp_response_to_outstanding_request() {
        let sockets = test_utils::socket_pair().await;
        let host_address = sockets.host_address();
        let sp_address = sockets.sp_address();
        let SocketPair { host, sp } = sockets;
        let Channels {
            outgoing_request_tx,
            outgoing_request_rx,
        } = test_utils::channels();
        let ioloop = test_utils::test_io_loop(host, sp_address, outgoing_request_rx);
        let _io_task = tokio::spawn(ioloop.run());

        // Send a request.
        let (response_tx, response_rx) = oneshot::channel();
        let modules = ModuleId(0b1);
        let request = HostRpcRequest {
            header: Header::new(0, MessageKind::HostRequest),
            message: Message::new(MessageBody::HostRequest(HostRequest::Status(modules))),
            data: None,
        };
        let outstanding_request = OutstandingHostRequest {
            request: request.clone(),
            n_retries: 0,
            n_error_messages: 0,
            response_tx,
        };
        outgoing_request_tx.send(outstanding_request).await.unwrap();

        // Deserialize the message. We don't really _need_ this, since we know
        // what the reply should be, but it's a helpful sanity check.
        let mut rx_buf = [0u8; MAX_PACKET_SIZE];
        let (_, peer) = sp.recv_from(&mut rx_buf).await.unwrap();
        assert_eq!(peer, host_address);
        let (deser_header, remainder) = hubpack::deserialize(&rx_buf).unwrap();
        assert_eq!(request.header, deser_header);
        let (deser_message, _trailing) = hubpack::deserialize(&remainder).unwrap();
        assert_eq!(request.message, deser_message);

        // The host asked for the status of a single module. Send it back,
        // indicating no errors. Note that we also need to send the actual
        // status bits back for this module.
        let reply_message = Message::new(MessageBody::SpResponse(SpResponse::Status {
            modules,
            failed_modules: ModuleId::empty(),
        }));
        let reply_header = Header::new(request.header.message_id, MessageKind::SpResponse);
        let mut tx_buf = [0u8; MAX_PACKET_SIZE];
        let mut n_bytes = hubpack::serialize(&mut tx_buf, &reply_header).unwrap();
        n_bytes += hubpack::serialize(&mut tx_buf[n_bytes..], &reply_message).unwrap();
        let status = Status::empty();
        n_bytes += hubpack::serialize(&mut tx_buf[n_bytes..], &status).unwrap();
        let n_sent = sp.send_to(&tx_buf[..n_bytes], host_address).await.unwrap();
        assert_eq!(n_sent, n_bytes);

        // Wait for the response on our channel.
        let response = response_rx.await.unwrap().unwrap();
        assert_eq!(response.header, reply_header);
        assert_eq!(response.message, reply_message);
        assert_eq!(response.data, Some(vec![status.bits()]));
    }

    // Check that we correctly detect when an SP response is missing trailing
    // data about the errors on some modules.
    #[tokio::test]
    async fn test_handle_sp_response_to_outgoing_request_missing_error_data() {
        let sockets = test_utils::socket_pair().await;
        let host_address = sockets.host_address();
        let sp_address = sockets.sp_address();
        let SocketPair { host, sp } = sockets;
        let Channels {
            outgoing_request_tx,
            outgoing_request_rx,
        } = test_utils::channels();
        let ioloop = test_utils::test_io_loop(host, sp_address, outgoing_request_rx);
        let _io_task = tokio::spawn(ioloop.run());

        // Send a request.
        let (response_tx, response_rx) = oneshot::channel();
        let modules = ModuleId(0b1);
        let request = HostRpcRequest {
            header: Header::new(0, MessageKind::HostRequest),
            message: Message::new(MessageBody::HostRequest(HostRequest::Status(modules))),
            data: None,
        };
        let outstanding_request = OutstandingHostRequest {
            request: request.clone(),
            n_retries: 0,
            n_error_messages: 0,
            response_tx,
        };
        outgoing_request_tx.send(outstanding_request).await.unwrap();

        // Deserialize the message. We don't really _need_ this, since we know
        // what the reply should be, but it's a helpful sanity check.
        let mut rx_buf = [0u8; MAX_PACKET_SIZE];
        let (_, peer) = sp.recv_from(&mut rx_buf).await.unwrap();
        assert_eq!(peer, host_address);
        let (deser_header, remainder) = hubpack::deserialize(&rx_buf).unwrap();
        assert_eq!(request.header, deser_header);
        let (deser_message, _trailing) = hubpack::deserialize(&remainder).unwrap();
        assert_eq!(request.message, deser_message);

        // The host asked for the status of a single module. Send it back,
        // but indicate that the SP failed to read that status.
        //
        // In this case, the IO Loop code should be looking for _error_ data. We
        // intentionally omit that, to check that the loop handles that case
        // correctly.
        let reply_message = Message::new(MessageBody::SpResponse(SpResponse::Status {
            modules: ModuleId::empty(),
            failed_modules: modules,
        }));
        let reply_header = Header::new(request.header.message_id, MessageKind::SpResponse);
        let mut tx_buf = [0u8; MAX_PACKET_SIZE];
        let mut n_bytes = hubpack::serialize(&mut tx_buf, &reply_header).unwrap();
        n_bytes += hubpack::serialize(&mut tx_buf[n_bytes..], &reply_message).unwrap();
        let n_sent = sp.send_to(&tx_buf[..n_bytes], host_address).await.unwrap();
        assert_eq!(n_sent, n_bytes);

        // Wait for the response on our channel.
        let err_message = response_rx.await.unwrap().unwrap_err();

        // The _message_ should not match. It should be a protocol error,
        // indicating we got the wrong size of data.
        let expected =
            u32::try_from(size_of::<HwError>() * modules.selected_transceiver_count()).unwrap();
        let Error::Protocol(proto_error) = err_message else {
            panic!("Expected a protocol error, found: {:?}", err_message);
        };
        assert_eq!(
            proto_error,
            ProtocolError::WrongDataSize {
                expected,
                actual: 0,
            }
        );
    }

    // Check that the IO Loop catches deserialization errors of the SP
    // responses, and injects an error back to the response channel.
    #[tokio::test]
    async fn test_handle_sp_response_to_outgoing_request_message_serialization_failure() {
        let sockets = test_utils::socket_pair().await;
        let host_address = sockets.host_address();
        let sp_address = sockets.sp_address();
        let SocketPair { host, sp } = sockets;
        let Channels {
            outgoing_request_tx,
            outgoing_request_rx,
        } = test_utils::channels();
        let ioloop = test_utils::test_io_loop(host, sp_address, outgoing_request_rx);
        let _io_task = tokio::spawn(ioloop.run());

        // Send a request.
        //
        // What we do here isn't really relevant, we just need something that
        // will work.
        let (response_tx, response_rx) = oneshot::channel();
        let modules = ModuleId(0b1);
        let request = HostRpcRequest {
            header: Header::new(0, MessageKind::HostRequest),
            message: Message::new(MessageBody::HostRequest(HostRequest::Status(modules))),
            data: None,
        };
        let outstanding_request = OutstandingHostRequest {
            request: request.clone(),
            n_retries: 0,
            n_error_messages: 0,
            response_tx,
        };
        outgoing_request_tx.send(outstanding_request).await.unwrap();

        // Deserialize the message. We don't really _need_ this, since we know
        // what the reply should be, but it's a helpful sanity check.
        let mut rx_buf = [0u8; MAX_PACKET_SIZE];
        let (_, peer) = sp.recv_from(&mut rx_buf).await.unwrap();
        assert_eq!(peer, host_address);
        let (deser_header, remainder) = hubpack::deserialize(&rx_buf).unwrap();
        assert_eq!(request.header, deser_header);
        let (deser_message, _trailing) = hubpack::deserialize(&remainder).unwrap();
        assert_eq!(request.message, deser_message);

        // The host asked for the status of a single module, but we're trying to
        // catch cases where the deserialization of the message itself, not the
        // header, fails. So inject a junk message, that should definitely not
        // deserialize correctly. We'll just do this by putting all the bytes
        // after the header to `0xff`.
        let reply_header = Header::new(request.header.message_id, MessageKind::SpResponse);
        let mut tx_buf = [0xffu8; MAX_PACKET_SIZE];
        let mut n_bytes = hubpack::serialize(&mut tx_buf, &reply_header).unwrap();

        // Send a few more bytes, to make sure the message deserialization
        // fails.
        n_bytes += Message::MAX_SIZE;
        let n_sent = sp.send_to(&tx_buf[..n_bytes], host_address).await.unwrap();
        assert_eq!(n_sent, n_bytes);

        // Wait for the response on our channel.
        let err_message = response_rx.await.unwrap().unwrap_err();
        let Error::Protocol(err) = err_message else {
            panic!("Expected a protocol error");
        };
        assert_eq!(err, ProtocolError::Serialization);
    }

    // Basic test that the IOLoop sends a UDP packet that corresponds to the
    // actual host request sent on the outgoing request channel.
    #[tokio::test]
    async fn test_send_outgoing_request() {
        let sockets = test_utils::socket_pair().await;
        let host_address = sockets.host_address();
        let sp_address = sockets.sp_address();
        let SocketPair { host, sp } = sockets;
        let Channels {
            outgoing_request_tx,
            outgoing_request_rx,
        } = test_utils::channels();
        let ioloop = test_utils::test_io_loop(host, sp_address, outgoing_request_rx);
        let _io_task = tokio::spawn(ioloop.run());

        // Send a request.
        let (response_tx, _response_rx) = oneshot::channel();
        let request = HostRpcRequest {
            header: Header::new(0, MessageKind::HostRequest),
            message: Message::new(MessageBody::HostRequest(HostRequest::Status(ModuleId(0b1)))),
            data: None,
        };
        let outstanding_request = OutstandingHostRequest {
            request: request.clone(),
            n_retries: 0,
            n_error_messages: 0,
            response_tx,
        };
        outgoing_request_tx.send(outstanding_request).await.unwrap();

        // Wait on the UDP socket for this exact request sent down the tube.
        let mut buf = [0u8; MAX_PACKET_SIZE];
        let (n_bytes, peer) = sp.recv_from(&mut buf).await.unwrap();
        assert_eq!(peer, host_address);

        // Deserialize and check header.
        let (deser_header, remainder) = hubpack::deserialize(&buf).unwrap();
        let mut n_bytes_deserialized = buf.len() - remainder.len();
        assert_eq!(request.header, deser_header);

        // Deserialize and check message.
        let (deser_message, trailing) = hubpack::deserialize(&remainder).unwrap();
        n_bytes_deserialized += remainder.len() - trailing.len();
        assert_eq!(request.message, deser_message);

        // Verify there is no trailing data for this message.
        assert_eq!(
            n_bytes, n_bytes_deserialized,
            "Should not have trailing data"
        );
    }

    // Test that we correctly send a protocol error message.
    #[tokio::test]
    async fn test_send_protocol_error() {
        let sockets = test_utils::socket_pair().await;
        let host_address = sockets.host_address();
        let sp_address = sockets.sp_address();
        let SocketPair { host, sp } = sockets;
        let Channels {
            outgoing_request_tx: _,
            outgoing_request_rx,
        } = test_utils::channels();
        let ioloop = test_utils::test_io_loop(host, sp_address, outgoing_request_rx);

        // Send an error message.
        let header = Header::new(0, MessageKind::Error);
        let err = ProtocolError::VersionMismatch {
            expected: 0,
            actual: 1,
        };
        let expected_message = Message::from(err);
        let mut tx_buf = [0u8; MAX_PACKET_SIZE];
        ioloop
            .send_protocol_error(&sp_address, header, err, &mut tx_buf)
            .await;

        // Assert we get the message out the UDP socket.
        let mut rx_buf = [0u8; MAX_PACKET_SIZE];
        let (n_bytes, peer) = sp.recv_from(&mut rx_buf).await.unwrap();
        assert_eq!(peer, host_address);

        // Deserialize and check header.
        let (deser_header, remainder) = hubpack::deserialize(&rx_buf).unwrap();
        let mut n_bytes_deserialized = rx_buf.len() - remainder.len();
        assert_eq!(header, deser_header);

        // Deserialize and check the error message.
        let (deser_message, trailing) = hubpack::deserialize(&remainder).unwrap();
        n_bytes_deserialized += remainder.len() - trailing.len();
        assert_eq!(expected_message, deser_message);

        // Verify there is no trailing data for this message.
        assert_eq!(
            n_bytes, n_bytes_deserialized,
            "Should not have trailing data"
        );
    }

    // Test that we correctly deserialize and inject a protocol error message
    // from the SP onto the response channel.
    #[tokio::test]
    async fn test_handle_sp_error() {
        let sockets = test_utils::socket_pair().await;
        let host_address = sockets.host_address();
        let sp_address = sockets.sp_address();
        let SocketPair { host, sp } = sockets;
        let Channels {
            outgoing_request_tx,
            outgoing_request_rx,
        } = test_utils::channels();
        let ioloop = test_utils::test_io_loop(host, sp_address, outgoing_request_rx);
        let _io_task = tokio::spawn(ioloop.run());

        // Send a request.
        let (response_tx, response_rx) = oneshot::channel();
        let modules = ModuleId(0b1);
        let request = HostRpcRequest {
            header: Header::new(0, MessageKind::HostRequest),
            message: Message::new(MessageBody::HostRequest(HostRequest::Status(modules))),
            data: None,
        };
        let outstanding_request = OutstandingHostRequest {
            request: request.clone(),
            n_retries: 0,
            n_error_messages: 0,
            response_tx,
        };
        outgoing_request_tx.send(outstanding_request).await.unwrap();

        // Deserialize the message. We don't really _need_ this, since we know
        // what the reply should be, but it's a helpful sanity check.
        let mut rx_buf = [0u8; MAX_PACKET_SIZE];
        let (_, peer) = sp.recv_from(&mut rx_buf).await.unwrap();
        assert_eq!(peer, host_address);
        let (deser_header, remainder) = hubpack::deserialize(&rx_buf).unwrap();
        assert_eq!(request.header, deser_header);
        let (deser_message, _trailing) = hubpack::deserialize(&remainder).unwrap();
        assert_eq!(request.message, deser_message);

        // Send a protocol error. This shouldn't happen to this particular
        // message, since it is valid, but we want to exercise the path that
        // injects it back to the caller.
        let err = ProtocolError::VersionMismatch {
            expected: 1,
            actual: 2,
        };
        let reply_message = Message::from(err);
        let reply_header = Header::new(request.header.message_id, MessageKind::Error);
        let mut tx_buf = [0u8; MAX_PACKET_SIZE];
        let mut n_bytes = hubpack::serialize(&mut tx_buf, &reply_header).unwrap();
        n_bytes += hubpack::serialize(&mut tx_buf[n_bytes..], &reply_message).unwrap();
        let n_sent = sp.send_to(&tx_buf[..n_bytes], host_address).await.unwrap();
        assert_eq!(n_sent, n_bytes);

        // Wait for the response on our channel.
        let err_message = response_rx.await.unwrap().unwrap_err();
        let Error::Protocol(proto_error) = err_message else {
            panic!("Expected a protocol error, found: {:?}", err_message);
        };
        assert_eq!(proto_error, err);
    }

    // Test that we correctly inject an error when we hit our faulty message
    // limit.
    #[tokio::test]
    async fn test_handle_faulty_message_limit() {
        let sockets = test_utils::socket_pair().await;
        let host_address = sockets.host_address();
        let sp_address = sockets.sp_address();
        let SocketPair { host, sp } = sockets;
        let Channels {
            outgoing_request_tx,
            outgoing_request_rx,
        } = test_utils::channels();
        let ioloop = test_utils::test_io_loop(host, sp_address, outgoing_request_rx);
        let _io_task = tokio::spawn(ioloop.run());

        // Send a request.
        let (response_tx, response_rx) = oneshot::channel();
        let modules = ModuleId(0b1);
        let request = HostRpcRequest {
            header: Header::new(0, MessageKind::HostRequest),
            message: Message::new(MessageBody::HostRequest(HostRequest::Status(modules))),
            data: None,
        };
        let outstanding_request = OutstandingHostRequest {
            request: request.clone(),
            n_retries: 0,
            n_error_messages: 0,
            response_tx,
        };
        outgoing_request_tx.send(outstanding_request).await.unwrap();

        // We're just always going to inject a completely bogus message, but
        // with the right header.
        for _ in 0..crate::NUM_ALLOWED_ERROR_MESSAGES {
            let mut rx_buf = [0u8; MAX_PACKET_SIZE];
            let (_, peer) = sp.recv_from(&mut rx_buf).await.unwrap();
            assert_eq!(peer, host_address);
            let (deser_header, remainder) = hubpack::deserialize(&rx_buf).unwrap();
            assert_eq!(request.header, deser_header);
            let (deser_message, _trailing) = hubpack::deserialize(&remainder).unwrap();
            assert_eq!(request.message, deser_message);

            // Serialize the header. Let's use a different message ID, so that
            // the host can't just match it up and fail the deserialization.
            let mut tx_buf = [0u8; MAX_PACKET_SIZE];
            let reply_header = Header::new(request.header.message_id + 1, MessageKind::SpResponse);
            let mut n_bytes = hubpack::serialize(&mut tx_buf, &reply_header).unwrap();
            // "Serialize" junk.
            tx_buf[n_bytes..][..Message::MAX_SIZE].fill(0xff);
            n_bytes += Message::MAX_SIZE;
            let n_sent = sp.send_to(&tx_buf[..n_bytes], host_address).await.unwrap();
            assert_eq!(n_sent, n_bytes);
        }

        // Wait for the response on our channel.
        let timed_wait = tokio::time::timeout(std::time::Duration::from_secs(8), response_rx);
        let err_message = timed_wait.await.unwrap().unwrap().unwrap_err();
        let Error::MaxFaultMessages(n) = err_message else {
            panic!("Expected a protocol error, found: {:?}", err_message);
        };
        assert_eq!(n, crate::NUM_ALLOWED_ERROR_MESSAGES);
    }
}
