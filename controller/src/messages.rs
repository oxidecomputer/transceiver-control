// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Definitions of messages passed between the contoller, SP, IO Loop, and the
//! request-handler channel.

use crate::Error;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use transceiver_messages::message::Header;
use transceiver_messages::message::Message;

/// A request sent from host to SP, possibly with trailing data.
#[derive(Clone, Debug)]
pub(crate) struct HostRpcRequest {
    pub header: Header,
    pub message: Message,
    pub data: Option<Vec<u8>>,
}

/// A response sent from SP to host, possibly with trailing data.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct SpRpcResponse {
    pub header: Header,
    pub message: Message,
    pub data: Option<Vec<u8>>,
}

/// A request sent from SP to host, possibly with trailing data.
#[derive(Clone, Debug)]
pub struct SpRpcRequest {
    pub header: Header,
    pub message: Message,
    pub data: Option<Vec<u8>>,
}

/// A response sent from host to SP, possibly with trailing data.
///
/// This type is the response that the handler for SP requests should generate.
/// They can be sent back on the channel in the delivered [`SpRequest`].
#[derive(Clone, Debug)]
pub struct HostRpcResponse {
    pub header: Header,
    pub message: Message,
    pub data: Option<Vec<u8>>,
}

/// A request from host to SP that has not yet been completed.
#[derive(Debug)]
pub(crate) struct OutstandingHostRequest {
    /// The actual request object we're sending. It's stored so that we can
    /// resend it if needed.
    pub(crate) request: HostRpcRequest,
    /// The number of attempts to submit and process `request`.
    pub(crate) n_retries: usize,
    /// The number of faulty messages that we've received while this request is
    /// outstanding, but which _could not_ positively be identified with this
    /// request.
    ///
    /// For example, we may receive messages which we fail to deserialize, or
    /// explicit error messages from the SP. However, we may not be able to
    /// match those up with our request. If there's a serialization failure,
    /// then the message ID may be garbled. It's also possible the SP sends a
    /// message that can be deserialized, but which somehow garbles _only_ the
    /// message ID field.
    pub(crate) n_error_messages: usize,
    /// The channel on which the eventual reply will be sent.
    pub(crate) response_tx: oneshot::Sender<Result<SpRpcResponse, Error>>,
}

/// A type for communicating requests from the SP to the host and submitting the
/// responses.
///
/// When the `Controller` receives a request from the SP, the message will be
/// placed on the `request_channel` channel provided at construction. The
/// host-side task responsible for processing those requests will receive an
/// `SpRequest` object; generate a response, if needed; and submit that back on
/// the `response_tx` field of this type. The `Controller` will await that
/// response on the receiving end of `response_tx`, and send it back to the SP.
///
/// Note that `response_tx` takes an optional response. If the host wishes to
/// drop the message and do nothing, `None` should be returned. This might be
/// the case, for example, if the message cannot be processed correctly.
#[derive(Debug)]
pub struct SpRequest {
    /// The actual request message received from the host.
    pub request: SpRpcRequest,
    /// A channel on which the response should sent.
    pub response_tx: mpsc::Sender<Result<Option<HostRpcResponse>, Error>>,
}
