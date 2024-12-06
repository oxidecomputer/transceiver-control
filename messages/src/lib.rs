// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

#![cfg_attr(all(not(test), not(feature = "std")), no_std)]

//! Messaging formats for managing the Sidecar transceiver ports over the
//! network.
//!
//! # Overview
//!
//! This crate allows host software to manage Sidecar transceivers. The message
//! formats are technically transport-agnostic, but the accompanying
//! `transceiver-controller` crate uses UDP. The host software may send messages
//! to the Hubris `transceivers` task, and ask it to operate on the switch ports
//! and transceivers -- such as controlling power; reseting a module; or reading
//! a module's memory map.
//!
//! # Addressing modules
//!
//! Modules are addressed with a bitmask type [`ModuleId`]. This allows the host
//! to operate on many transceivers simultaneously, reducing the number of
//! message exchanges required. The individual bits in `ModuleId` correspond to
//! the logical switch port numbers and the values printed on the front I/O
//! panel. E.g., bit 0 indicates switch port 0, etc. See [`ModuleId`] for more
//! details.
//!
//! # Messages
//!
//! Messaging generally follows a request-response pattern. For example, the
//! host issues a [`HostRequest`](message::HostRequest) and receives an
//! [`SpResponse`](message::SpResponse) indicating the outcome of the request.
//! Most requests include a `ModuleId` to describe the modules to be operated
//! on; and potentially some data describing the operation. For example
//! [`HostRequest::Read`](message::HostRequest::Read) includes a field `read`,
//! which has type [`mgmt::MemoryRead`]. That describes the data in the module
//! memory maps to be read, such as the page of data to read from, the offset,
//! and its length in bytes.
//!
//! Each request message has an expected response message. For
//! `HostRequest::Read`, the response should be
//! [`SpResponse::Read`](message::SpResponse::Read). That echoes back the `read`
//! descriptor used. It also includes two [`ModuleId`]s, which indicate the
//! _successfully-read_ modules and those on which the read _failed_.
//!
//! # Trailing data
//!
//! This crate uses [`hubpack`][1] for serialization. That is an efficient and
//! no-std friendly tool, but is not appropriate for variable-length data. That
//! means it can't be easily used to serialize the results of a read request.
//!
//! When a [`HostRequest::Read`](message::HostRequest::Read) is issued, that may
//! be for a variable amount of data. Similarly, an unknown number of modules
//! may _fail_ to be read. Both of these pieces of data are included as _trailing
//! data_ in a UDP packet containing a message. In the case of a read request,
//! this trailing data contains the actual data as a byte-array. The host is
//! responsible for interpreting it. For errors, the SP serializes one variant
//! of [`HwError`](message::HwError) for each module that fails. This describes
//! the cause of the error in detail.
//!
//! > **Important**: In the case that _both_ success and error data is returned
//! > in a response, success data is serialized **first**, followed immediately by
//! > error data. The length of each can be computed with
//! > [`SpResponse::expected_data_len`](message::SpResponse::expected_data_len)
//! > and
//! > [`SpResponse::expected_error_data_len`](message::SpResponse::expected_error_data_len),
//! > respectively.
//!
//! For the most part, `HostRequest` variants do not contain any trailing data.
//! The exception is [`HostRequest::Write`](message::HostRequest::Write), which
//! contains a trailing array of bytes that are to be written. The length of the
//! array _must_ match the length of the contained [`mgmt::MemoryWrite`]
//! descriptor.
//!
//! > **Important**: The trailing data in a `HostRequest::Write` message is
//! > _broadcast_ to all modules indicate by the message. After a successful
//! > write, every module will contain the requested data in the memory map
//! > location indicated by the write descriptor.
//!
//! # Full message format
//!
//! This crate is designed to work over a UDP transport layer. That means that
//! message delivery is unreliable, including dropped packets, out of order
//! delivery, and redelivery. To mitigate this, we include a
//! [`Header`](message::Header) in every message.
//!
//! Headers include a header-specific version number; a message ID; and a
//! message kind. The message ID is a `u64`, and the values are left entirely
//! up to the message sender. The message kind is one variant of
//! [`MessageKind`](message::MessageKind), and indicates the type of the
//! remaining contents of the packet.
//!
//! The header is fully separate from the remaining message. This is to support
//! partial deserialization of the header, and to allow separate evolution of
//! the internals of the message, while keeping compatibility of the header
//! itself.
//!
//! The [`Header`](message::Header) is followed by a
//! [`Message`](message::Message), which contains a message-specific version
//! number, followed by a variant of [`MessageBody`](message::MessageBody).
//! The variant should match the message kind indicated by the header. Following
//! the body of the message, any trailing success and error data are
//! concatenated.
//!
//! Note that the `Header`, `Message` and trailing data are all concatenated
//! into a single UDP packet. The length of the packet determines the overall
//! length of the message. **There is no separate length field for the
//! message.**
//!
//! ## Example message layout
//!
//!```text
//! <-- Header --><-- Message --><-- Maybe data --><-- Maybe error data -->
//! ```
//!
//! # Protocol errors
//!
//! In the event that the peer completely violates the protocol, such as by
//! sending the wrong response type for a message, a peer may send back a
//! message containing a [`ProtocolError`](message::ProtocolError). This is a
//!  separate message body, and includes details about the failure. It is
//!  intended for things like invalid response kinds, unsupported operations,
//!  or serialization failures. It is also used to indicate mismatches of the
//!  protocol versions.
//!
//! [1]: https://docs.rs/hubpack/latest/hubpack/

pub mod mac;
pub mod message;
pub mod mgmt;
mod module_id;
use hubpack::SerializedSize;
#[cfg(any(test, feature = "std"))]
pub use module_id::filter_module_data;
#[cfg(any(test, feature = "std"))]
pub use module_id::keep_module_data;
#[cfg(any(test, feature = "std"))]
pub use module_id::merge_module_data;
#[cfg(any(test, feature = "std"))]
pub use module_id::remove_module_data;
pub use module_id::InvalidPort;
pub use module_id::ModuleId;

/// The maximum size of the payload of a message, i.e., any trailing data after
/// the inner message contents;
pub const MAX_PAYLOAD_SIZE: usize = 1024;
pub const MAX_PACKET_SIZE: usize =
    MAX_PAYLOAD_SIZE + crate::message::Header::MAX_SIZE + crate::message::Message::MAX_SIZE;

/// The UDP port on which both sides should listen.
///
/// Note that the protocol is by-definition bidirectional. Both the host and SP
/// may initiate messages to their peer. For the host, this includes things like
/// write requests; for the SP, it may initiate messages to notify the host of
/// interrupts or alarms.
pub const PORT: u16 = 11112;

/// The IPv6 multicast address on which both peers should listen.
///
/// See RFD 250 for background on this specific address. Briefly, this is a
/// link-local multicast address that is unlikely to conflict with others, such
/// as the All-Nodes address.
//
// NOTE: This isn't a `std::net::Ipv6Addr` to support `no_std` environments.
pub const ADDR: [u16; 8] = [0xff02, 0, 0, 0, 0, 0, 0x1de, 2];

// Helper function to catch changes to encoding, where we add a new variant but
// do not change the test accordingly.
#[cfg(test)]
pub(crate) fn check_invalid_variants<T>(first_invalid_variant: u8)
where
    T: hubpack::SerializedSize + serde::de::DeserializeOwned + serde::Serialize + core::fmt::Debug,
{
    let mut buf = vec![0u8; T::MAX_SIZE];
    for i in first_invalid_variant..=u8::MAX {
        buf[0] = i;
        let res = hubpack::deserialize::<T>(&buf).expect_err(&format!(
            "Should not be able to deserialize variant with ID {i}"
        ));
        assert_eq!(
            res,
            hubpack::Error::Custom,
            "Should not be able to deserialize variant with ID {i}"
        );
    }
}
