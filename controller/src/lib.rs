// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! A host-side control interface to the SP for managing Sidecar transceivers.

use hubpack::SerializedSize;
use slog::debug;
use slog::error;
use slog::info;
use slog::warn;
use slog::Logger;
use std::future::Future;
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
use tokio::time::sleep_until;
use tokio::time::Instant;
use transceiver_messages::message;
use transceiver_messages::message::Header;
use transceiver_messages::message::HostRequest;
use transceiver_messages::message::HostResponse;
use transceiver_messages::message::Message;
use transceiver_messages::message::MessageBody;
use transceiver_messages::message::Status;
use transceiver_messages::mgmt::MemoryRead;
use transceiver_messages::Error as MessageError;
use transceiver_messages::ModuleId;
use transceiver_messages::ADDR;
use transceiver_messages::MAX_PAYLOAD_SIZE;
use transceiver_messages::PORT;

/// An error related to managing the transceivers.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Error in transceiver control protocol: {0:?}")]
    Protocol(#[from] transceiver_messages::Error),

    #[error("Network or I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Message type requires data, but none provided")]
    MessageRequiresData,

    #[error("A serialization error occurred: {0}")]
    SerDes(hubpack::Error),
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
    // The channel on which the eventual reply will be sent.
    response_tx: oneshot::Sender<Result<SpRpcResponse, Error>>,
    // The time we last sent the request, used during retries.
    last_sent: Instant,
}

// We limit ourselves to a single outstanding request in either direction at
// this point.
const NUM_OUTSTANDING_REQUESTS: usize = 1;

/// A type for controlling transceiver modules on a Sidecar.
#[derive(Debug)]
pub struct Controller {
    _log: Logger,
    message_id: AtomicU64,

    // Channel onto which requests from the host to SP are sent.
    //
    // `io_task` owns the receiving end of this, and actually sends out the
    // messages to the SP.
    outgoing_request_tx: mpsc::Sender<OutstandingHostRequest>,

    // The task handling actual network IO with the peer.
    io_task: JoinHandle<()>,

    // The task handling actual network IO with the peer.
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
    pub async fn new<H, F>(log: Logger, request_handler: H) -> Result<Self, Error>
    where
        H: Fn(SpRpcRequest) -> F + Send + Sync + 'static,
        F: Future<Output = Result<HostRpcResponse, Error>> + Send,
    {
        // TODO-correctness We probably want to accept a specific address as
        // part of the construction of this object.
        let local_addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, PORT, 0, 0);
        let socket = UdpSocket::bind(local_addr).await?;

        // Make sure we receive addresses sent to the multicast address we use
        // for the protocol, but not those sent by us.
        socket.join_multicast_v6(&Ipv6Addr::from(ADDR), 0)?;
        socket.set_multicast_loop_v6(false)?;

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

        // The I/O task handles the actual network I/O, reading and writing UDP
        // packets in both directions.
        let io_log = log.new(slog::o!("task" => "io"));
        let io_task = tokio::spawn(async move {
            io_loop(
                io_log,
                socket,
                // For receiving requests sent from self.
                outgoing_request_rx,
                // For receiving responses sent from request-handler.
                outgoing_response_rx,
                // For sending requests from network to self.
                incoming_request_tx,
            )
            .await;
        });

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

        Ok(Self {
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
        let _reply = self.rpc(request).await.unwrap();
        todo!();
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
        let reply = self.rpc(request).await.unwrap();
        // We expect data to be a flattened vec of vecs, with the data from each
        // referenced transceiver. Split it into chunks sized by the number of
        // bytes we expected to read.
        let data = reply
            .data
            .unwrap()
            .chunks_exact(usize::from(read.len()))
            .map(Vec::from)
            .collect::<Vec<_>>();
        assert_eq!(data.len(), modules.n_transceivers());
        Ok(data)
    }

    // Issue one RPC, possibly retrying, and await the response.
    async fn rpc(&self, request: HostRpcRequest) -> Result<SpRpcResponse, Error> {
        let (response_tx, response_rx) = oneshot::channel();
        let outstanding_request = OutstandingHostRequest {
            request,
            response_tx,
            last_sent: Instant::now(),
        };
        self.outgoing_request_tx
            .send(outstanding_request)
            .await
            .unwrap();
        response_rx.await.unwrap()
    }
}

const RESEND_INTERVAL: Duration = Duration::from_secs(1);

// Main IO loop for communicating with the SP.
//
// This task is responsible for accepting messages from the host for delivery to
// the SP (outgoing) and those from the SP to the host (incoming). The outgoing
// messages are accepted from two channels:
//
// - `outgoing_request_rx` receives messages from the `Controller` object
// itself, as part of the implementation of its public API.
// - `outgoing_response_rx` receives messages from the `request_handler` used to
// construct the `Controller, and delivers the host's desired responses to SP
// request.
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
// `incoming_request_tx.
// - Responses to our own initiated requests are sent back on a `oneshot`
// channel, that is sent in the data on `outgoing_request_tx`.
async fn io_loop(
    log: Logger,
    socket: UdpSocket,
    mut outgoing_request_rx: mpsc::Receiver<OutstandingHostRequest>,
    mut outgoing_response_rx: mpsc::Receiver<HostRpcResponse>,
    incoming_request_tx: mpsc::Sender<SpRpcRequest>,
) {
    let mut recv_buf = [0u8; MAX_PAYLOAD_SIZE + Message::MAX_SIZE];
    let mut send_buf = recv_buf.clone();
    let peer_addr = SocketAddrV6::new(Ipv6Addr::from(ADDR), PORT, 0, 0);

    // An outstanding request that has not yet been completed.
    //
    // We're accepting requests for submission on `outgoing_request_rx`.
    // However, once we dequeue that, we still want to block further requests
    // from being processed. `tokio::sync::mpsc::Receiver` lacks a peek method,
    // otherwise we'd use that.
    //
    // We dequeue the request and store it here. The main loop below contains
    // if-statements on several of the `tokio::select!` branches, specifically
    // those related to waiting for new messages on `outgoing_request_rx`. The
    // effect is that we only wait for new outgoing responses if we're not
    // currently processing one.
    let mut outstanding_request: Option<OutstandingHostRequest> = None;

    loop {
        // We also need to resend an outstanding request, as long as there is
        // one. This future is recreated on each pass through the loop.
        let retry_timeout = if let Some(req) = &outstanding_request {
            sleep_until(req.last_sent + RESEND_INTERVAL)
        } else {
            // NOTE: This will never be polled, but the future is evaluated in
            // each branch of `tokio::select!`, even if it's eventually disabled
            // by the condition on it.
            sleep_until(Instant::now() + RESEND_INTERVAL)
        };

        tokio::select! {
            // Poll for outgoing requests, but only if we don't already _have_
            // an outstanding request.
            maybe_request = outgoing_request_rx.recv(), if outstanding_request.is_none() => {

                // We only get `None` if the sender is closed, meaning the task
                // holding that side exited. Nothing else will come down this
                // channel, and things are likely borked. Bail out.
                let request = match maybe_request {
                    Some(r) => r,
                    None => {
                        debug!(log, "outgoing response channel closed, exiting");
                        return;
                    }
                };
                debug!(log, "received outgoing request: {request:?}");

                // Store the outstanding request, sanity-checking that we really
                // didn't have a prior one.
                let old = outstanding_request.replace(request);
                assert!(
                    old.is_none(),
                    "dequeued a new request while one is already outstanding!",
                );

                let request = outstanding_request.as_mut().unwrap();
                match send_outgoing_request(&socket, &peer_addr, request, &mut send_buf).await {
                    Ok(n) => debug!(log, "sent message"; "message" => ?request, "n_bytes" => n),
                    Err(e) => error!(log, "failed to send message"; "reason" => ?e),
                }
            }

            // If we _do_ have an outstanding request, we need to resend it
            // periodically until we get a response. Wait for up to the resend
            // interval of inactivity, and then possibly retry.
            _ = retry_timeout, if outstanding_request.is_some() => {
                debug!(log, "timed out without response, retrying");
                let request = outstanding_request.as_mut().unwrap();
                send_outgoing_request(&socket, &peer_addr, request, &mut send_buf).await.unwrap();
                info!(log, "resent message");
            }

            // Poll for outgoing responses we need to send.
            maybe_response = outgoing_response_rx.recv() => {
                let response = match maybe_response {
                    Some(r) => r,
                    None => {
                        debug!(log, "outgoing response channel closed, exiting");
                        return;
                    }
                };
                // TODO-implement
                debug!(log, "outgoing response: {response:?}");
            }

            // Poll for incoming packets.
            res = socket.recv_from(&mut recv_buf) => {
                let (n_bytes, peer) = match res {
                    Err(e) => {
                        error!(log, "I/O error receiving UDP packet: {e:?}");
                        continue;
                    }
                    Ok((n_bytes, peer)) => (n_bytes, peer),
                };

                // Deserialize the message itself.
                let (message, remainder): (Message, _) = match hubpack::deserialize(&recv_buf) {
                    Err(e) => {
                        error!(
                            log,
                            "failed to deserialize message";
                            "reason" => ?e,
                            "peer" => peer,
                            "n_bytes" => n_bytes,
                        );
                        continue;
                    }
                    Ok((msg, remainder)) => (msg, remainder),
                };
                debug!(log, "message from peer"; "peer" => peer, "message" => ?message);

                // Sanity check the protocol version.
                if message.header.version != message::version::V1 {
                    if let Err(e) = send_version_mismatch(&log, &socket, &peer, &message.header, &message.modules).await {
                        error!(
                            log,
                            "failed to send version mismatch";
                            "reason" => ?e,
                            "peer" => peer
                        );
                    }
                    continue;
                }

                // Sanity check that the message could possibly be meant for us.
                //
                // We never expect these message types to be sent to us.
                if matches!(message.body, MessageBody::HostRequest(_) | MessageBody::HostResponse(_)) {
                    warn!(log, "wrong message type"; "peer" => peer);
                    send_protocol_error(&log, &socket, &peer, &message.header, &message.modules).await;
                    continue;
                }

                // Check that we have data, if the message is supposed to
                // contain it.
                let expected_len = message.expected_data_len();
                let data = if expected_len > 0  {
                    if remainder.len() < expected_len {
                        warn!(
                            log,
                            "message did not contain expected data";
                            "expected_len" => expected_len,
                            "actual_len" => remainder.len(),
                            "peer" => peer,
                        );
                        send_protocol_error(&log, &socket, &peer, &message.header, &message.modules).await;
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
                    incoming_request_tx.send(request).await.unwrap();
                    continue;
                }

                // This is a response, possibly for our outstanding request.
                if let Some(request) = outstanding_request.take() {
                    // Check if this is for our current outstanding request.
                    if request.request.message.header.message_id != message.header.message_id {
                        warn!(
                            log,
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
                    warn!(
                        log,
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

async fn send_protocol_error(
    log: &Logger,
    socket: &UdpSocket,
    peer: &SocketAddr,
    header: &Header,
    modules: &ModuleId,
) {
    error!(log, "Protocol error");
    let err = MessageError::ProtocolError;
    let message = Message {
        header: *header,
        modules: *modules,
        body: MessageBody::HostResponse(HostResponse::Error(err)),
    };
    let mut buf = [0u8; Message::MAX_SIZE];
    hubpack::serialize(&mut buf, &message).unwrap();
    match socket.send_to(&buf, peer).await {
        Err(e) => {
            error!(
                log,
                "failed to send protocol error";
                "reason" => ?e,
                "peer" => peer
            );
        }
        Ok(n_bytes) => assert_eq!(n_bytes, Message::MAX_SIZE),
    }
}

async fn send_version_mismatch(
    log: &Logger,
    socket: &UdpSocket,
    peer: &SocketAddr,
    header: &Header,
    modules: &ModuleId,
) -> Result<(), Error> {
    error!(
        log,
        "Mismatched protocol versions";
        "expected" => message::version::V1,
        "actual" => header.version,
    );
    let err = MessageError::VersionMismatch {
        expected: message::version::V1,
        actual: header.version,
    };
    let message = Message {
        header: *header,
        modules: *modules,
        body: MessageBody::HostResponse(HostResponse::Error(err)),
    };
    let mut buf = [0u8; Message::MAX_SIZE];
    hubpack::serialize(&mut buf, &message).unwrap();
    let n_bytes = socket.send_to(&buf, peer).await?;
    assert_eq!(n_bytes, Message::MAX_SIZE);
    Ok(())
}

// Send a request from the host to the SP, returning the number of bytes sent.
async fn send_outgoing_request(
    socket: &UdpSocket,
    peer: &SocketAddrV6,
    request: &mut OutstandingHostRequest,
    buf: &mut [u8],
) -> Result<usize, Error> {
    let mut msg_size = match hubpack::serialize(buf, &request.request.message) {
        Ok(n) => n,
        Err(e) => return Err(Error::SerDes(e)),
    };
    if let Some(data) = &request.request.data {
        buf[msg_size..data.len()].copy_from_slice(data);
        msg_size += data.len();
    }
    let n_bytes = socket.send_to(&buf[..msg_size], peer).await?;
    assert_eq!(n_bytes, msg_size);
    request.last_sent = Instant::now();
    Ok(n_bytes)
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
    loop {
        let incoming_request = incoming_request_rx.recv().await.unwrap();
        info!(log, "Incoming request {incoming_request:?}");
        match request_handler(incoming_request).await {
            Ok(response) => outgoing_response_tx.send(response).await.unwrap(),
            Err(e) => error!(log, "request handler failed: {e:?}"),
        }
    }
}
