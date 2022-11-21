// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! A host-side control interface to the SP for managing Sidecar transceivers.

use hubpack::SerializedSize;
use nix::net::if_::if_nametoindex;
use serde::Deserialize;
use serde::Serialize;
use slog::debug;
use slog::error;
use slog::info;
use slog::warn;
use slog::Logger;
use std::future::Future;
use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV6;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::interval;
use tokio::time::Interval;
use transceiver_messages::message;
use transceiver_messages::message::Header;
use transceiver_messages::message::HostRequest;
use transceiver_messages::message::HostResponse;
use transceiver_messages::message::Message;
use transceiver_messages::message::MessageBody;
use transceiver_messages::message::SpResponse;
use transceiver_messages::message::Status;
use transceiver_messages::mgmt::MemoryRead;
use transceiver_messages::Error as MessageError;
use transceiver_messages::ModuleId;
use transceiver_messages::ADDR;
use transceiver_messages::MAX_PAYLOAD_SIZE;
use transceiver_messages::PORT;

#[usdt::provider(provider = "xcvr__ctl")]
mod probes {
    fn packet__received(peer: IpAddr, n_bytes: usize) {}
    fn packet__sent(peer: IpAddr, n_bytes: usize) {}
    fn message__received(peer: IpAddr, message: &Message) {}
    fn message__sent(peer: IpAddr, message: &Message) {}
    fn bad__message(peer: IpAddr, reason: &str) {}
}

/// An error related to managing the transceivers.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Error in transceiver control protocol: {0:?}")]
    Protocol(#[from] transceiver_messages::Error),

    #[error("Network or I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Message type requires data, but none provided")]
    MessageRequiresData,

    #[error("Could not find requested interface")]
    BadInterface(String),

    #[error("Maximum number of retries ({0}) reached without a response")]
    MaxRetries(usize),

    #[error(
        "Read of transceiver module memory failed, \
        one of the requested transceivers may not be present"
    )]
    ReadFailed,

    #[error("Received an unexpected message type in response: {0:?}")]
    UnexpectedMessage(MessageBody),
}

// A request sent from host to SP, possibly with trailing data.
#[derive(Clone, Debug)]
struct HostRpcRequest {
    pub message: Message,
    pub data: Option<Vec<u8>>,
}

// A response sent from SP to host, possibly with trailing data.
#[derive(Clone, Debug)]
#[allow(dead_code)]
struct SpRpcResponse {
    pub message: Message,
    pub data: Option<Vec<u8>>,
}

/// A request sent from SP to host, possibly with trailing data.
#[derive(Clone, Debug)]
pub struct SpRpcRequest {
    pub message: Message,
    pub data: Option<Vec<u8>>,
}

/// A response sent from host to SP, possibly with trailing data.
#[derive(Clone, Debug)]
pub struct HostRpcResponse {
    pub message: Message,
    pub data: Option<Vec<u8>>,
}

// A request from host to SP that has not yet been completed.
#[derive(Debug)]
struct OutstandingHostRequest {
    // The actual request object we're sending. It's stored so that we can
    // resend it if needed.
    request: HostRpcRequest,
    // The number of attempts to submit and process `request`.
    n_retries: usize,
    // The channel on which the eventual reply will be sent.
    response_tx: oneshot::Sender<Result<SpRpcResponse, Error>>,
}

// We limit ourselves to a single outstanding request in either direction at
// this point.
const NUM_OUTSTANDING_REQUESTS: usize = 1;
const RESEND_INTERVAL: Duration = Duration::from_secs(1);
const MAX_PACKET_SIZE: usize = MAX_PAYLOAD_SIZE + Message::MAX_SIZE;

const fn default_retry_interval() -> Duration {
    RESEND_INTERVAL
}

fn default_peer_addr() -> Ipv6Addr {
    Ipv6Addr::from(ADDR)
}

/// Configuration for a `Controller`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    /// The address on which to listen for messages.
    pub address: Ipv6Addr,

    /// The name of the interface on which to listen.
    pub interface: String,

    /// The IPv6 address to use for communication.
    ///
    /// The default is a link-local IPv6 multicast address.
    #[serde(default = "default_peer_addr")]
    pub peer: Ipv6Addr,

    /// The interval on which to retry messages that receive no response.
    #[serde(default = "default_retry_interval")]
    pub retry_interval: Duration,

    /// The number of retries for a message before failing.
    #[serde(default)]
    pub n_retries: Option<usize>,
}

/// A type for controlling transceiver modules on a Sidecar.
#[derive(Debug)]
pub struct Controller {
    _config: Config,
    _iface: u32,
    _log: Logger,
    message_id: AtomicU64,

    // Channel onto which requests from the host to SP are sent.
    //
    // `io_task` owns the receiving end of this, and actually sends out the
    // messages to the SP.
    outgoing_request_tx: mpsc::Sender<OutstandingHostRequest>,

    // The task handling actual network IO with the peer.
    io_task: JoinHandle<()>,

    // The task receiving requests from the peer and calling the user-supplied
    // request handler.
    request_task: JoinHandle<()>,
}

impl Drop for Controller {
    fn drop(&mut self) {
        self.io_task.abort();
        self.request_task.abort();
    }
}

impl Controller {
    /// Create a new transceiver controller.
    ///
    /// `request_handler` is a function that yields responses to SP requests. As
    /// requests over the network are received, they'll be passed into the
    /// handler, and the yielded response forwarded back to the SP.
    pub async fn new<H, F>(config: Config, log: Logger, request_handler: H) -> Result<Self, Error>
    where
        H: Fn(SpRpcRequest) -> F + Send + Sync + 'static,
        F: Future<Output = Result<HostRpcResponse, Error>> + Send,
    {
        if let Err(e) = usdt::register_probes() {
            warn!(log, "failed to register DTrace probes"; "reason" => ?e);
        }

        let iface = if_nametoindex(config.interface.as_str())
            .map_err(|_| Error::BadInterface(config.interface.clone()))?;
        let local_addr = SocketAddrV6::new(config.address, PORT, 0, iface);
        let socket = UdpSocket::bind(local_addr).await?;
        debug!(
            log,
            "bound UDP socket";
            "interface" => &config.interface,
            "local_addr" => ?local_addr,
        );

        // Join the group for the multicast protocol address, so that we can
        // accept requests from the SP in the case it does not have our unicast
        // address.
        let multicast_addr = Ipv6Addr::from(ADDR);
        socket.join_multicast_v6(&multicast_addr, iface)?;
        socket.set_multicast_loop_v6(false)?;
        debug!(
            log,
            "joined IPv6 multicast group";
            "multicast_addr" => ?multicast_addr,
        );

        // Channel for communicating outgoing requests from this object to the
        // I/O loop. Note that the _responses_ from the I/O loop back to this
        // object are sent on a oneshot channel, which is itself placed on this
        // channel when sending the request.
        let (outgoing_request_tx, outgoing_request_rx) = mpsc::channel(NUM_OUTSTANDING_REQUESTS);

        // Channel for communicating outgoing responses from the request-handler
        // task to the I/O loop.
        let (outgoing_response_tx, outgoing_response_rx) = mpsc::channel(NUM_OUTSTANDING_REQUESTS);

        // Channel for communicating incoming requests from the I/O loop to
        // the request-handler task.
        let (incoming_request_tx, incoming_request_rx) = mpsc::channel(NUM_OUTSTANDING_REQUESTS);

        // The multicast peer address for our protocol.
        //
        // We can't both `connect` the socket and still `send_to`, which means
        // we wouldn't be able to send outgoing packets without a unicast
        // adddress. Pass this address to the IO loop, so we can initiate
        // requests.
        let peer_addr = SocketAddrV6::new(config.peer, PORT, 0, iface);

        // The I/O task handles the actual network I/O, reading and writing UDP
        // packets in both directions.
        let io_log = log.new(slog::o!("task" => "io"));
        let io_loop = IoLoop::new(
            io_log,
            socket,
            peer_addr,
            config.n_retries,
            config.retry_interval,
            outgoing_request_rx,
            outgoing_response_rx,
            incoming_request_tx,
        );
        let io_task = tokio::spawn(async move {
            io_loop.run().await;
        });
        debug!(log, "spawned IO task");

        // The request task runs the user-supplied request handler, receiving
        // valid requests from the I/O task and sending valid responses back.
        let request_log = log.new(slog::o!("task" => "request_handler"));
        let request_task = tokio::spawn(async move {
            request_loop(
                request_log,
                // For receiving requests sent from I/O loop.
                incoming_request_rx,
                // For sending responses to I/O loop.
                outgoing_response_tx,
                request_handler,
            )
            .await;
        });
        debug!(log, "spawned request-handler task");

        Ok(Self {
            _config: config,
            _iface: iface,
            _log: log,
            message_id: AtomicU64::new(0),
            outgoing_request_tx,
            io_task,
            request_task,
        })
    }

    // Return a header using the next available message ID.
    fn next_header(&self) -> Header {
        Header {
            version: message::version::V1,
            message_id: self.message_id.fetch_add(1, Ordering::SeqCst),
        }
    }

    /// Report the status of a set of transceiver modules.
    pub async fn status(&self, modules: ModuleId) -> Result<Vec<Status>, Error> {
        let message = Message {
            header: self.next_header(),
            modules,
            body: MessageBody::HostRequest(HostRequest::Status),
        };
        let request = HostRpcRequest {
            message,
            data: None,
        };
        let reply = self.rpc(request).await?;
        Ok(reply
            .data
            .unwrap()
            .into_iter()
            .map(|x| Status::from_bits(x).unwrap())
            .collect())
    }

    /// Read the memory map of a set of transceiver modules.
    ///
    /// `read` contains a description of which memory region to read, including
    /// the page, offset, and length. See [`MemoryRead`] for details.
    ///
    /// Note that the _caller_ is responsible for verifying that the details of
    /// the read are valid, such as that the modules conform to the specified
    /// management interface, and that the page is supported.
    pub async fn read(&self, modules: ModuleId, read: MemoryRead) -> Result<Vec<Vec<u8>>, Error> {
        let message = Message {
            header: self.next_header(),
            modules,
            body: MessageBody::HostRequest(HostRequest::Read(read)),
        };
        let request = HostRpcRequest {
            message,
            data: None,
        };
        let reply = self.rpc(request).await?;

        // If we get back a ReadFailed error, one possibility is that we asked
        // to read a transceiver that's not present.
        let data = match reply.message.body {
            MessageBody::SpResponse(SpResponse::Error(MessageError::ReadFailed(..))) => {
                return Err(Error::ReadFailed);
            }
            MessageBody::SpResponse(SpResponse::Error(e)) => return Err(Error::from(e)),
            MessageBody::SpResponse(SpResponse::Read(_)) => reply.data.unwrap(),
            other => return Err(Error::UnexpectedMessage(other)),
        };

        // We expect data to be a flattened vec of vecs, with the data from each
        // referenced transceiver. Split it into chunks sized by the number of
        // bytes we expected to read.
        let data = data
            .chunks_exact(usize::from(read.len()))
            .map(Vec::from)
            .collect::<Vec<_>>();
        assert_eq!(data.len(), modules.selected_transceiver_count());
        Ok(data)
    }

    // Issue one RPC, possibly retrying, and await the response.
    async fn rpc(&self, request: HostRpcRequest) -> Result<SpRpcResponse, Error> {
        let (response_tx, response_rx) = oneshot::channel();
        let outstanding_request = OutstandingHostRequest {
            request,
            n_retries: 0,
            response_tx,
        };
        self.outgoing_request_tx
            .send(outstanding_request)
            .await
            .unwrap();
        response_rx.await.unwrap()
    }
}

// A POD type holding the data we need for the main I/O loop. See `IoLoop::run`
// for details.
#[derive(Debug)]
struct IoLoop {
    log: Logger,
    socket: UdpSocket,
    peer_addr: SocketAddrV6,
    n_retries: usize,
    resend: Interval,
    outstanding_request: Option<OutstandingHostRequest>,
    outgoing_request_rx: mpsc::Receiver<OutstandingHostRequest>,
    outgoing_response_rx: mpsc::Receiver<HostRpcResponse>,
    incoming_request_tx: mpsc::Sender<SpRpcRequest>,
}

impl IoLoop {
    fn new(
        log: Logger,
        socket: UdpSocket,
        peer_addr: SocketAddrV6,
        n_retries: Option<usize>,
        retry_interval: Duration,
        outgoing_request_rx: mpsc::Receiver<OutstandingHostRequest>,
        outgoing_response_rx: mpsc::Receiver<HostRpcResponse>,
        incoming_request_tx: mpsc::Sender<SpRpcRequest>,
    ) -> Self {
        Self {
            log,
            socket,
            peer_addr,
            n_retries: n_retries.unwrap_or(usize::MAX),
            resend: interval(retry_interval),
            outstanding_request: None,
            outgoing_request_rx,
            outgoing_response_rx,
            incoming_request_tx,
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
        let data_start = hubpack::serialize(tx_buf, &request.request.message).unwrap();
        let msg_size = if let Some(data) = &request.request.data {
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
                    "failed to send outgoing request";
                    "peer" => ?self.peer_addr,
                    "reason" => ?e,
                );
            }
            Ok(n_bytes) => {
                assert_eq!(n_bytes, msg_size);
                debug!(
                    self.log,
                    "sent outgoing request";
                    "peer" => ?self.peer_addr,
                    "message" => ?request.request.message,
                );
                probes::packet__sent!(|| {
                    let peer = IpAddr::V6(*self.peer_addr.ip());
                    (peer, n_bytes)
                });
                probes::message__sent!(|| {
                    let peer = IpAddr::V6(*self.peer_addr.ip());
                    (peer, &request.request.message)
                });

                // Reset the resend timer and increment the number of attempts.
                self.resend.reset();
                request.n_retries += 1;
            }
        }
    }

    async fn send_protocol_error(
        &self,
        peer: &SocketAddr,
        header: Header,
        modules: ModuleId,
        err: MessageError,
        tx_buf: &mut [u8],
    ) {
        let body = MessageBody::HostResponse(HostResponse::Error(err));
        let message = Message {
            header,
            modules,
            body,
        };
        let serialized_len = hubpack::serialize(tx_buf, &message).unwrap();
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
                    (peer, n_bytes)
                });
                probes::message__sent!(|| {
                    let peer = IpAddr::V6(*self.peer_addr.ip());
                    (peer, &message)
                });
                assert_eq!(n_bytes, serialized_len);
            }
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
    // - Requests from the SP are sent to the request handler, via
    // `incoming_request_tx`.
    // - Responses to our own initiated requests are sent back on a `oneshot`
    // channel, that is sent in the data on `outgoing_request_tx`.
    async fn run(mut self) {
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
                    debug!(self.log, "received outgoing request: {request:?}");

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
                    let n_retries = self.outstanding_request.as_ref().unwrap().n_retries;
                    if n_retries < self.n_retries {
                        debug!(self.log, "timed out without response, retrying");
                        self.send_outgoing_request(&mut tx_buf).await;
                    } else {
                        error!(
                            self.log,
                            "failed to send message within {n_retries} retries"
                        );
                        // Safety: This branch is only taken if the request is
                        // `Some(_)`.
                        let old = self.outstanding_request.take().unwrap();
                        old.response_tx.send(Err(Error::MaxRetries(n_retries))).unwrap();
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
                    // TODO-implement
                    debug!(self.log, "outgoing response: {response:?}");
                }

                // Poll for incoming packets.
                res = self.socket.recv_from(&mut rx_buf) => {
                    let (n_bytes, peer) = match res {
                        Err(e) => {
                            error!(self.log, "I/O error receiving UDP packet: {e:?}");
                            continue;
                        }
                        Ok((n_bytes, peer)) => {
                            debug!(
                                self.log,
                                "packet received";
                                "n_bytes" => n_bytes,
                                "peer" => peer,
                            );
                            probes::packet__received!(|| (peer.ip(), n_bytes));
                            (n_bytes, peer)
                        }
                    };

                    // Deserialize the message itself.
                    let (message, remainder): (Message, _) = match hubpack::deserialize(&rx_buf) {
                        Err(e) => {
                            // We've failed to deserialize the message. We'll
                            // not send any failure back to the peer, since we
                            // have no information about what kind of message
                            // this is. However, we'll deserialize the header
                            // (which should never fail) and emit a log message.
                            let (header, _): (Header, _) = hubpack::deserialize(&rx_buf).unwrap();
                            error!(
                                self.log,
                                "failed to deserialize message";
                                "reason" => ?e,
                                "peer" => peer,
                                "n_bytes" => n_bytes,
                                "header" => ?header,
                            );
                            probes::bad__message!(|| {
                                (peer.ip(), format!("deserialization failure: {e:?}"))
                            });
                            continue;
                        }
                        Ok((msg, remainder)) => (msg, remainder),
                    };
                    debug!(
                        self.log,
                        "message from peer";
                        "peer" => peer,
                        "message" => ?message
                    );
                    probes::message__received!(|| (peer.ip(), &message));

                    // Sanity check the protocol version.
                    if message.header.version != message::version::V1 {
                        // If the version does not match, we're choosing to drop
                        // the packet rather than reply with a version mismatch
                        // error. Without a matching version, we can't really
                        // trust the message kind we have deserialized, so won't
                        // be able to reliably send protocol errors.
                        debug!(
                            self.log,
                            "deserialized message with incorrect version";
                            "expected" => message::version::V1,
                            "actual" => message.header.version,
                            "peer" => peer,
                        );
                        probes::bad__message!(|| {
                            (
                                peer.ip(),
                                format!(
                                    "incorrect version: expected {}, actual {}",
                                    message::version::V1,
                                    message.header.version,
                                ),
                            )
                        });
                        continue;
                    }

                    // Sanity check that the message could possibly be meant for us.
                    //
                    // We never expect these message types to be sent to us.
                    if matches!(message.body, MessageBody::HostRequest(_) | MessageBody::HostResponse(_)) {
                        // We need to check the message ID to decide how to
                        // proceed.
                        //
                        // If we have an outstanding request, and this incoming
                        // message matches that ID, we need to fail this
                        // request. Otherwise we'll simply retry the message
                        // again, which will obviously fail in the same way.
                        //
                        // Note that we can always take out of the Option. If it
                        // is None, then we can replace it with None without
                        // worry. If it is Some(_), we want to replace it
                        // anyway when we fail this request.
                        let maybe_outstanding = self.outstanding_request.take();
                        if let Some(request) = maybe_outstanding {
                            if request.request.message.header.message_id ==
                                message.header.message_id {
                                debug!(
                                    self.log,
                                    "received incorrect message type, \
                                    but with message ID that matches our \
                                    outstanding message ID, failing the \
                                    request";
                                    "message" => ?message,
                                    "peer" => peer,
                                );
                                request.response_tx.send(
                                    Err(Error::Protocol(MessageError::ProtocolError))
                                ).unwrap();
                            }
                        } else {
                            // We don't have an outstanding request, so we try
                            // to inform the SP that this message wasn't
                            // supposed to be sent to us.
                            debug!(self.log, "wrong message type"; "peer" => peer);
                            let err = MessageError::ProtocolError;
                            probes::bad__message!(|| (peer.ip(), format!("{:?}", err)));
                            self.send_protocol_error(
                                &peer,
                                message.header,
                                message.modules,
                                err,
                                &mut tx_buf,
                            ).await;
                        }
                    }

                    // Check that we have data, if the message is supposed to
                    // contain it.
                    let expected_len = message.expected_data_len();
                    let data = if expected_len > 0  {
                        if remainder.len() < expected_len {
                            error!(
                                self.log,
                                "message did not contain expected data";
                                "expected_len" => expected_len,
                                "actual_len" => remainder.len(),
                                "peer" => peer,
                            );
                            let err = MessageError::MissingData;
                            probes::bad__message!(|| (peer.ip(), format!("{:?}", err)));
                            self.send_protocol_error(
                                &peer,
                                message.header,
                                message.modules,
                                err,
                                &mut tx_buf,
                            ).await;
                            continue;
                        }
                        Some(remainder[..expected_len].to_vec())
                    } else {
                        None
                    };

                    // If this is a request, let's dispatch to the request handler
                    // channel.
                    if matches!(message.body, MessageBody::SpRequest(_)) {
                        let request = SpRpcRequest {
                            message,
                            data,
                        };
                        self.incoming_request_tx.send(request).await.unwrap();
                        continue;
                    }

                    // This is a response, possibly for our outstanding request.
                    if let Some(request) = self.outstanding_request.take() {
                        // Check if this is for our current outstanding request.
                        if request.request.message.header.message_id != message.header.message_id {
                            debug!(
                                self.log,
                                "received response for message that is not outstanding";
                                "message" => ?message,
                                "outstanding_message_id" => request.request.message.header.message_id,
                                "peer" => peer,
                            );
                            continue;
                        }

                        // We have a valid response!
                        let response = SpRpcResponse { message, data };
                        request.response_tx.send(Ok(response)).unwrap();
                    } else {
                        // We have no outstanding request.
                        //
                        // There are a lot of reasons this might be the case, such
                        // as a duplicate response from the SP for a previous
                        // request. It's not obvious what to do here, but for now,
                        // let's log and drop the message.
                        debug!(
                            self.log,
                            "received response without an outstanding request";
                            "message" => ?message,
                            "peer" => peer,
                        );
                        continue;
                    }
                }
            }
        }
    }
}

async fn request_loop<H, F>(
    log: Logger,
    mut incoming_request_rx: mpsc::Receiver<SpRpcRequest>,
    outgoing_response_tx: mpsc::Sender<HostRpcResponse>,
    request_handler: H,
) where
    H: Fn(SpRpcRequest) -> F + Send + Sync + 'static,
    F: Future<Output = Result<HostRpcResponse, Error>> + Send,
{
    while let Some(incoming_request) = incoming_request_rx.recv().await {
        info!(log, "Incoming request {incoming_request:?}");
        match request_handler(incoming_request).await {
            Ok(response) => outgoing_response_tx.send(response).await.unwrap(),
            Err(e) => error!(log, "request handler failed: {e:?}"),
        }
    }
    debug!(log, "request handler channel closed, exiting");
}
