// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! A host-side control interface to the SP for managing Sidecar transceivers.
//!
//! The `transceiver-controller` crate provides a high-level interface to
//! manage transceivers on a Sidecar. It uses a UDP protocol to talk to the SP,
//! asking basic questions about the transceivers, and also asking it to perform
//! operations on our behalf. It can be used to control the power of the
//! transceivers; read or write portions of the memory map; decode module data
//! like vendor information; or reset modules. These operations are all
//! available through this library, as well as a command-line tool consuming it,
//! called `xcvradm`.
//!
//! # Controller interface
//!
//! The main type in this crate is the [`Controller`]. This provides a set of
//! operations that can be done on a number of modules. Those modules are
//! addressed by a [`ModuleId`](transceiver_messages::ModuleId).
//!
//! # Results
//!
//! The methods here may all address multiple transceivers. At the same time,
//! those methods are all fallible. To preserve the success _and_ failure
//! information, we can't use a normal Rust [`Result`], which only has success
//! _or_ failure information.
//!
//! Instead, we provide a number of result types to capture all this. The
//! general type for this is the [`ModuleResult`]. That includes:
//!
//! - successful modules
//! - possible data from the operation (which may be nothing)
//! - the modules which failed and the cause of the failure
//!
//! There are specific results for each operation. For example the
//! [`ReadResult`] contains the raw bytes read from each module in the
//! operation, as a `Vec<u8>`. Many operations don't have meaningful data, only
//! a success or error reason. These return an [`AckResult`].
//!
//! # DTrace probes
//!
//! There are several DTrace USDT probes in the `Controller`, mostly around the
//! networking protocol for communicating with the SP. These are all under the
//! DTrace provider `xcvr-ctl`, and the probes are:
//!
//! - `bad-message` fires when a message is received that could not be
//! deserialized or was unexpected, for example violating the protocol. It
//! contains the peer and reason for the failure.
//! - `message-received` fires when a valid message is received, with the peer
//! and actual message as data.
//! - `message-sent` fires when a message is sent, with the peer it's sent to
//! and the actual message as data.
//! - `packet-sent` and `packet-received` fire when any UDP packet is sent and
//! received, with the address and a pointer to the raw data.

#![cfg_attr(not(usdt_stable_asm), feature(asm))]
#![cfg_attr(all(target_os = "macos", not(usdt_stable_asm_sym)), feature(asm_sym))]

mod config;
mod controller;
mod ioloop;
mod messages;
mod results;

pub use crate::config::*;
pub use crate::controller::Controller;
pub use crate::messages::*;
pub use crate::results::*;

use std::net::IpAddr;
pub use transceiver_decode::Error as DecodeError;
pub use transceiver_decode::Identifier;
pub use transceiver_messages::mac::BadMacAddrRange;
pub use transceiver_messages::mac::MacAddrs;
use transceiver_messages::message::Header;
pub use transceiver_messages::message::HwError;
use transceiver_messages::message::Message;
use transceiver_messages::message::MessageBody;
pub use transceiver_messages::message::ProtocolError;
pub use transceiver_messages::message::Status;
pub use transceiver_messages::mgmt;
use transceiver_messages::mgmt::ManagementInterface;
pub use transceiver_messages::InvalidPort;
pub use transceiver_messages::ModuleId;

#[usdt::provider(provider = "xcvr__ctl")]
mod probes {
    fn packet__received(peer: IpAddr, n_bytes: u64, data: *const u8) {}
    fn packet__sent(peer: IpAddr, n_bytes: u64, data: *const u8) {}
    fn message__received(peer: IpAddr, header: &Header, message: &Message) {}
    fn message__sent(peer: IpAddr, header: &Header, message: &Message) {}
    fn bad__message(peer: IpAddr, reason: &str) {}
}

/// An error operating on a transceiver, such as a bad index, hardware failure,
/// or error decoding its memory map.
#[derive(Clone, Copy, Debug, PartialEq, thiserror::Error)]
pub enum TransceiverError {
    #[error("Hardware error accessing module {module_index}: {source}")]
    Hardware {
        module_index: u8,
        #[source]
        source: HwError,
    },

    #[error("Error decoding module data: {0}")]
    Decode(#[from] DecodeError),

    #[error("Module management interface error: {0}")]
    Mgmt(#[from] mgmt::Error),

    #[error("Error addressing Sidecar port: {0}")]
    Port(#[from] InvalidPort),

    #[error(
        "Addressed module with index {module_index} with \
        identifier {identifier:?} does not use the \
        specified management interface {interface:?}"
    )]
    InvalidInterfaceForModule {
        module_index: u8,
        identifier: Identifier,
        interface: ManagementInterface,
    },
}

/// An error related to managing the transceivers.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A failure of the actual messaging protocol, such as a bad message or
    /// version mismatch.
    #[error("Controller protocol error")]
    Protocol(#[from] ProtocolError),

    /// An I/O failure, such as a failure to send a packet on a socket.
    #[error("Network or I/O error")]
    Io(#[from] std::io::Error),

    /// An attempt to send a message that requires data, but none provided.
    #[error("Message type requires data, but none provided")]
    MessageRequiresData,

    /// Network interface is missing or lacks an IPv6 link-local address.
    #[error("Interface not found or lacks correct IPv6 link-local address")]
    BadInterface(String),

    /// Maximum number of retries reached without a response.
    #[error("Maximum number of retries ({0}) reached without a response")]
    MaxRetries(usize),

    /// Maximum number of faulty messages reached without a response.
    #[error("Maximum number of faulty messages ({0}) reached without a response")]
    MaxFaultMessages(usize),

    /// Received a valid message, but that is not the expected response to a
    /// request.
    #[error("Received an unexpected message type in response: {0:?}")]
    UnexpectedMessage(MessageBody),

    /// Attempt to issue a memory write with data that is not the correct
    /// length.
    #[error(
        "Incorrect data length for memory write, \
        expected = {expected} actual = {actual}"
    )]
    InvalidWriteData { expected: usize, actual: usize },

    /// An invalid power state transition, such as going from off directly to
    /// high-power.
    #[error("Invalid power state transition")]
    InvalidPowerStateTransition,

    /// Received a bad MAC address range from the SP.
    #[error("Bad MAC address range")]
    Mac(#[from] BadMacAddrRange),

    /// A failure interacting with a transceiver module.
    #[error("Error interacting with transceiver module")]
    Transceiver(#[from] TransceiverError),
}

impl From<mgmt::Error> for Error {
    fn from(e: mgmt::Error) -> Self {
        Self::from(TransceiverError::from(e))
    }
}

impl From<DecodeError> for Error {
    fn from(e: DecodeError) -> Self {
        Self::from(TransceiverError::from(e))
    }
}

impl From<InvalidPort> for Error {
    fn from(e: InvalidPort) -> Self {
        Self::from(TransceiverError::from(e))
    }
}

/// An allowed power state for the module.
#[derive(Clone, Copy, Debug, PartialEq, clap::ValueEnum)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Serialize, serde::Deserialize, schemars::JsonSchema)
)]
#[cfg_attr(any(feature = "api-traits", test), serde(rename_all = "snake_case"))]
pub enum PowerState {
    /// A module is entirely powered off, using the EFuse.
    Off,

    /// Power is enabled to the module, but module remains in low-power mode.
    ///
    /// In this state, modules will not establish a link or transmit traffic,
    /// but they may be managed and queried for information through their memory
    /// maps.
    Low,

    /// The module is in high-power mode.
    ///
    /// Note that additional configuration may be required to correctly
    /// configure the module, such as described in SFF-8636 rev 2.10a table
    /// 6-10, and that the _host side_ is responsible for ensuring that the
    /// relevant configuration is applied.
    High,
}

/// The power mode of a module.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PowerMode {
    /// The actual power state.
    pub state: PowerState,
    /// Whether the module is configured for software override of power control.
    ///
    /// If the module is in `PowerState::Off`, this can't be determined, and
    /// `None` is returned.
    pub software_override: Option<bool>,
}

impl Default for PowerMode {
    fn default() -> Self {
        Self {
            state: PowerState::Off,
            software_override: None,
        }
    }
}

// We limit ourselves to a single outstanding request in either direction at
// this point.
const NUM_OUTSTANDING_REQUESTS: usize = 1;

// Limit to the number of "faulty" messages we receive, but which we cannot
// positively associate with an outstanding request.
//
// We may receive a response that was _intended_ for an outstanding request, but
// which we don't consider a valid reply. That can happen because of
// deserialization failures; messages of the wrong kind; or a corrupt message ID
// in the received header.
//
// While we can't positively say that this message was intended for our
// outstanding request, we still limit the number of such failures we accept.
// This is to avoid retrying forever, for example when the peer software is
// broken or operating differently than we expect.
const NUM_ALLOWED_ERROR_MESSAGES: usize = 5;

#[cfg(test)]
pub(crate) mod test_utils {
    use crate::ioloop::IoLoop;
    use crate::messages::OutstandingHostRequest;
    use crate::NUM_OUTSTANDING_REQUESTS;
    use slog::Drain;
    use slog::Logger;
    use std::net::Ipv6Addr;
    use std::net::SocketAddr;
    use std::net::SocketAddrV6;
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;

    // A "pair" of UDP sockets.
    //
    // These aren't connected, so it's really just two sockets for the IO Loop
    // and any simulated SP.
    #[derive(Debug)]
    pub(crate) struct SocketPair {
        pub host: UdpSocket,
        pub sp: UdpSocket,
    }

    impl SocketPair {
        pub(crate) fn host_address(&self) -> SocketAddr {
            self.host.local_addr().unwrap()
        }

        pub(crate) fn sp_address(&self) -> SocketAddr {
            self.sp.local_addr().unwrap()
        }
    }

    // Holds channels used to send requests into the IO Loop.
    #[derive(Debug)]
    pub(crate) struct Channels {
        pub outgoing_request_tx: mpsc::Sender<OutstandingHostRequest>,
        pub outgoing_request_rx: mpsc::Receiver<OutstandingHostRequest>,
    }

    // Return a logger suitable for testing.
    pub(crate) fn test_logger() -> Logger {
        let decorator = slog_term::PlainSyncDecorator::new(slog_term::TestStdoutWriter);
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        Logger::root(drain, slog::o!("name" => "test-logger"))
    }

    // Return a localhost socket bound to a random port.
    pub(crate) async fn localhost_socket() -> UdpSocket {
        let sp_address = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0);
        UdpSocket::bind(sp_address).await.unwrap()
    }

    // Return a pair of UDP sockets for the host and SP.
    pub(crate) async fn socket_pair() -> SocketPair {
        let host = localhost_socket().await;
        let sp = localhost_socket().await;
        SocketPair { host, sp }
    }

    // Construct the channels for sending requests into the IO Loop.
    pub(crate) fn channels() -> Channels {
        let (outgoing_request_tx, outgoing_request_rx) =
            mpsc::channel::<OutstandingHostRequest>(NUM_OUTSTANDING_REQUESTS);
        Channels {
            outgoing_request_tx,
            outgoing_request_rx,
        }
    }

    // Construct a test IO Loop object.
    pub(crate) fn test_io_loop(
        socket: UdpSocket,
        peer_addr: SocketAddr,
        outgoing_request_tx: mpsc::Receiver<OutstandingHostRequest>,
    ) -> IoLoop {
        // We can't test this side of things because we can't construct any
        // SpRequest objects, since the enum has no variants. This is a dummy
        // channel.
        let (tx, _rx) = mpsc::channel(NUM_OUTSTANDING_REQUESTS);
        let SocketAddr::V6(peer) = peer_addr else {
            panic!("Should be IPv6 address");
        };
        IoLoop::new(
            test_logger(),
            socket,
            peer,
            None,
            std::time::Duration::from_millis(50),
            outgoing_request_tx,
            tx,
        )
    }
}
