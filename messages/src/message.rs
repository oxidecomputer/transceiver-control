// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Message formats and definitions.
//!

use crate::mac::BadMacAddrRange;
use crate::mac::MacAddrs;
use crate::mgmt::ManagementInterface;
use crate::mgmt::MemoryRead;
use crate::mgmt::MemoryWrite;
use crate::ModuleId;
use core::fmt;
use hubpack::SerializedSize;
use serde::de::Error as SerdeError;
use serde::de::Unexpected;
use serde::de::Visitor;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

/// Definitions of message versions.
///
/// Both the inner and outer messages define minimum-supported and current
/// versions. The `MIN` version is the minimum guaranteed to be compatible with
/// the `CURRENT`. Here _compatible_ means that all messages from `MIN` can be
/// correctly deserialized by software running at least `MIN`. That means that
/// all message data in `MIN` correspond to the same values in `CURRENT` --
/// colloquially, `CURRENT` is a superset of `MIN`.
///
/// Because this crate uses `hubpack` for serialization, this means that no
/// variants of the message enums have been removed or reordered between `MIN`
/// and `CURRENT`. So `CURRENT` may contain _new_ items (or renamed ones), but
/// existing ones cannot be moved around relative to one another or removed.
///
/// This version of the protocol is _committed_. Any changes to the types here
/// **MUST** be compatible with `MIN`. Changes may add new enum variants; rename
/// variants; or rename struct fields; but they **MUST NOT** change the types of
/// those fields or reorder them. Peers **SHOULD**, on a best-effort basis,
/// decode and hande any messages that whose version is at least `MIN`. If the
/// message comes from a version prior to `CURRENT`, they must be able to decode
/// it, assuming we've not broken compatibility. If the message comes from a
/// version _after_ `CURRENT`, they _may_ be able to decode it. Specifically, if
/// they cannot, presumably because it came from a later version, they
/// **SHOULD** still send back a `ProtocolError` message, such as
/// `VersionMismatch` or `NotSupported`. Those are gauranteed to be compatible
/// with and decodable by the peer.
pub mod version {
    pub mod inner {
        pub const V1: u8 = 1;
        pub const CURRENT: u8 = V1;
        pub const MIN: u8 = V1;
    }
    pub mod outer {
        pub const V1: u8 = 1;
        pub const MIN: u8 = V1;
        pub const CURRENT: u8 = V1;
    }
}

/// An error related to the actual messaging protocol.
///
/// This is an error reported in the outer message.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize)]
#[cfg_attr(any(test, feature = "std"), derive(thiserror::Error))]
pub enum ProtocolError {
    /// An unexpected message type was encountered.
    #[cfg_attr(any(test, feature = "std"), error("Wrong message type"))]
    WrongMessage,

    /// The requested operation is not supported or unknown.
    #[cfg_attr(any(test, feature = "std"), error("Unsupported or unknown operation"))]
    NotSupported,

    /// A request would result in a response that is too large to fit in a
    /// single UDP message.
    #[cfg_attr(
        any(test, feature = "std"),
        error("Request too large for single protocol message")
    )]
    RequestTooLarge,

    /// The trailing data is an unexpected size.
    #[cfg_attr(
        any(test, feature = "std"),
        error(
            "Message trailing data has incorrect size: \
            expected={expected} actual={actual}"
        )
    )]
    WrongDataSize { expected: u32, actual: u32 },

    /// The version in the header is unexpected.
    #[cfg_attr(
        any(test, feature = "std"),
        error("Version mismatch: expected={expected}, actual={actual}")
    )]
    VersionMismatch { expected: u8, actual: u8 },

    /// A failure to serialize or deserialize data.
    #[cfg_attr(any(test, feature = "std"), error("Serialization failed"))]
    Serialization,
}

/// An inner message error related to hardware accesses.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize, SerializedSize)]
#[cfg_attr(any(test, feature = "std"), derive(thiserror::Error))]
pub enum HwError {
    /// The FPGA reported an I2C error
    #[cfg_attr(any(test, feature = "std"), error("FPGA reported an I2C error"))]
    I2cError,

    /// An invalid module index was provided.
    ///
    /// Module indices are provided in a `u64` bitmask. However, current Sidecar
    /// designs include only 32 switch ports. This is used to return errors in
    /// the event that the host sets any of the upper 32 bits of that `u64`.
    #[cfg_attr(any(test, feature = "std"), error("Invalid module index"))]
    InvalidModuleIndex,

    /// An error interacting with a board FPGA to operate on the transceivers.
    #[cfg_attr(any(test, feature = "std"), error("Error interacting with FPGA"))]
    FpgaError,
}

/// Deserialize the [`HwError`]s from a packet buffer that are expected, given
/// the set of _failed_ modules described in `failed_modules`.
///
/// When issue certain requests to the SP, such as `HostRequest::Read`, the SP
/// responds with two `ModuleId`s: one for the successful modules and one for
/// the failed modules. The trailing data in a UDP packet, after the message
/// itself, contains all the data for the succesfully-read modules, followed by
/// one `HwError` for each failed module. This method can be used to decode
/// those errors.
///
/// Note that `buf` is expected to start at the first `HwError`. One can use
/// `SpResponse::expected_data_len()` and
/// `SpResponse::expected_error_data_len()` to determine the length of these
/// buffers.
#[cfg(any(feature = "std", test))]
pub fn deserialize_hw_errors(
    failed_modules: ModuleId,
    buf: &[u8],
) -> Result<Vec<HwError>, ProtocolError> {
    match failed_modules.selected_transceiver_count() {
        0 => Ok(vec![]),
        n => {
            const ITEM_SIZE: usize = HwError::MAX_SIZE;
            let n_bytes = n * ITEM_SIZE;
            if buf.len() < n_bytes {
                return Err(ProtocolError::WrongDataSize {
                    expected: u32::try_from(n_bytes).unwrap(),
                    actual: u32::try_from(buf.len()).unwrap(),
                });
            }
            let mut out = Vec::with_capacity(n);
            let chunks = buf.chunks_exact(ITEM_SIZE);
            for chunk in chunks {
                out.push(
                    hubpack::deserialize(chunk)
                        .map_err(|_| ProtocolError::Serialization)?
                        .0,
                );
            }
            Ok(out)
        }
    }
}

/// A common header to all messages between host and SP.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize)]
pub struct Header {
    // The outer message protocol version.
    version: u8,
    /// An arbitrary message ID, shared between a request and its response.
    pub message_id: u64,
    /// The expected contents of the remainder of the UDP packet.
    ///
    /// This helps understand how to handle failures to parse the remaining
    /// contents of the packet.
    pub message_kind: MessageKind,
}

impl Header {
    /// Create a new `Header` from an ID and message kind, at the current
    /// version.
    pub const fn new(message_id: u64, message_kind: MessageKind) -> Self {
        Self {
            version: version::outer::CURRENT,
            message_id,
            message_kind,
        }
    }

    /// Return the outer protocol version in `self`.
    pub const fn version(&self) -> u8 {
        self.version
    }
}

/// Description of the remaining contents of a message from the peer.
///
/// This is useful for determining how to proceed in the event of a failure to
/// deserialize the remaining bytes. For example, suppose the host has an
/// outstanding request to the SP, and receives an `SpResponse` message with the
/// ID of that request. If the message fails to deserialize, we'd probably like
/// to fail the request as a whole, rather than retrying it.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize)]
pub enum MessageKind {
    /// The message is expected to contain a [`MessageBody::Error`].
    Error,
    /// The message is expected to contain a [`MessageBody::HostRequest`].
    HostRequest,
    /// The message is expected to contain a [`MessageBody::SpResponse`].
    SpResponse,
    /// The message is expected to contain a [`MessageBody::SpRequest`].
    SpRequest,
    /// The message is expected to contain a [`MessageBody::HostResponse`].
    HostResponse,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize)]
pub struct Message {
    version: u8,
    pub body: MessageBody,
}

impl Message {
    /// Construct a new message, at the current version, from a body.
    pub fn new(body: MessageBody) -> Self {
        Self {
            version: version::inner::CURRENT,
            body,
        }
    }

    /// Return the inner protocol version number.
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Return the kind of message this includes.
    pub const fn kind(&self) -> MessageKind {
        match self.body {
            MessageBody::Error(_) => MessageKind::Error,
            MessageBody::HostRequest(_) => MessageKind::HostRequest,
            MessageBody::SpResponse(_) => MessageKind::SpResponse,
            MessageBody::SpRequest(_) => MessageKind::SpRequest,
            MessageBody::HostResponse(_) => MessageKind::HostResponse,
        }
    }
}

/// The body of a message between host and SP.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize)]
pub enum MessageBody {
    /// An error message from the peer, indicating a failure of the protocol,
    /// such as an unexpected message, failed deserialization, or version
    /// mismatch.
    Error(ProtocolError),

    /// A request sent from host to SP.
    HostRequest(HostRequest),

    /// A response sent from SP to host.
    ///
    /// The intended reply type for a [`HostRequest`].
    SpResponse(SpResponse),

    /// A request sent from SP to host.
    SpRequest(SpRequest),

    /// A response sent from host to SP.
    ///
    /// The intended reply type for an [`SpRequest`].
    HostResponse(HostResponse),
}

impl From<ProtocolError> for Message {
    fn from(e: ProtocolError) -> Self {
        Self::new(MessageBody::Error(e))
    }
}

impl From<HostRequest> for Message {
    fn from(r: HostRequest) -> Self {
        Self::new(MessageBody::HostRequest(r))
    }
}

impl From<SpResponse> for Message {
    fn from(r: SpResponse) -> Self {
        Self::new(MessageBody::SpResponse(r))
    }
}

impl From<SpRequest> for Message {
    fn from(r: SpRequest) -> Self {
        Self::new(MessageBody::SpRequest(r))
    }
}

impl From<HostResponse> for Message {
    fn from(r: HostResponse) -> Self {
        Self::new(MessageBody::HostResponse(r))
    }
}

/// A request from the host to the SP.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize)]
pub enum HostRequest {
    /// Request to read a region of the transceivers' memory maps.
    Read { modules: ModuleId, read: MemoryRead },

    /// Request to write to a region of the transceiver's memory map.
    ///
    /// The data to be written is contained in the remainder of the UDP packet.
    /// This data should be a single byte array of the size specified by the
    /// contained `MemoryWrite`, and will broadcast to all transceiver modules
    /// addressed by the message.
    Write {
        modules: ModuleId,
        write: MemoryWrite,
    },

    /// Request to return the status of the transceiver modules.
    Status(ModuleId),

    /// Request that the ResetL line be asserted.
    AssertReset(ModuleId),

    /// Request that the ResetL line be de-asserted.
    DeassertReset(ModuleId),

    /// Request that the LpMode line be asserted.
    AssertLpMode(ModuleId),

    /// Request that the LpMode line be de-asserted.
    DeassertLpMode(ModuleId),

    /// Request that power be enabled to a module should it be inserted.
    EnablePower(ModuleId),

    /// Request that power be disabled to a module should it be inserted.
    DisablePower(ModuleId),

    /// Assert type of management interface that a set of modules uses.
    ///
    /// This is used to allow the SP to read and interpret parts of the
    /// transceivers' memory maps such as the temperature or power draw, for the
    /// purposes of health and safety monitoring.
    ManagementInterface {
        modules: ModuleId,
        interface: ManagementInterface,
    },

    /// Ask the SP to return the available MAC addresses for host system use.
    MacAddrs,

    /// Request that a latched power fault be cleared.
    ///
    /// When a power fault has occurred, the transceiver's power supply will not
    /// re-enable as long as the fault is latched. Clearing the fault allows the
    /// power supply to be enabled again.
    ClearPowerFault(ModuleId),
}

impl HostRequest {
    /// Return the number of bytes expected to follow `self`.
    ///
    /// If `None` is returned, the message expects no data at all.
    pub fn expected_data_len(&self) -> Option<usize> {
        match self {
            HostRequest::Write { modules, write } => {
                Some(modules.selected_transceiver_count() * usize::from(write.len()))
            }
            _ => None,
        }
    }
}

/// A response to a host request, sent from SP to host.
///
/// Most operations are fallible. As such, they report the set of modules on
/// which the operation succeed, and the set on which it failed. Such messages
/// may have trailing data, which indicates the successful data first, followed
/// by data indicating the failure.
///
/// For example, suppose the host sends a request to read data from two modules.
/// The first succeeds, and the second fails. The trailing data then contains a
/// byte array with the successfully-read data, followed by a byte array
/// encoding the `HwError` variant corresponding to the message. Note that for
/// many failures, each error may be a different variant.
///
/// The [`SpResponse::expected_data_len()`] and
/// [`SpResponse::expected_error_data_len()`] can be used to determine the
/// number of _bytes_ of expected success data or error data.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize)]
pub enum SpResponse {
    /// The result of a read operation.
    ///
    /// The actual data read from the transceivers' memory is contained in the
    /// remaining bytes of the UDP packet. Note that this may actually contain a
    /// sequence of byte arrays, one for each of the addressed modules.
    Read {
        /// The modules that were successfully read from.
        modules: ModuleId,
        /// The modules on which the read failed.
        failed_modules: ModuleId,
        /// The read operation performed.
        read: MemoryRead,
    },

    /// The result of a write operation.
    Write {
        /// The modules that were successfully written to.
        modules: ModuleId,
        /// The modules on which the write failed.
        failed_modules: ModuleId,
        /// The write operation performed.
        write: MemoryWrite,
    },

    /// The status of a set of transceiver modules.
    ///
    /// Each module may have a different set of status flags set. The
    /// [`Message`] type contains the mask identifying all the modules, and the
    /// remaining bytes of the UDP packet are a list of [`Status`] objects for
    /// each module specified.
    ///
    /// The ordering of the status objects is from lowest index to highest --
    /// that is, taking the output of the returned `ModuleId::to_indices()`
    /// method.
    Status {
        /// The modules whose status was successfully read.
        modules: ModuleId,
        /// The modules on which fetching the status failed.
        failed_modules: ModuleId,
    },

    /// A generic acknowledgement of a specific message, where no further data
    /// is required from the SP.
    Ack {
        /// The modules which successfully performed the requested operation.
        modules: ModuleId,
        /// The modules which failed to perform the requested operation.
        failed_modules: ModuleId,
    },

    /// The requested MAC address information for the host.
    MacAddrs(MacAddrResponse),
}

impl SpResponse {
    /// Return the number of _data_ bytes expected to follow `self`.
    ///
    /// If `None`, the message expects no data at all.
    pub fn expected_data_len(&self) -> Option<usize> {
        match self {
            SpResponse::Read { modules, read, .. } => {
                Some(modules.selected_transceiver_count() * usize::from(read.len()))
            }
            SpResponse::Status { modules, .. } => {
                // NOTE: We don't `hubpack::deserialize` the `Status` objects,
                // those are directly constructed using `Status::from_bits()`.
                // So using `size_of` is appropriate here.
                Some(modules.selected_transceiver_count() * core::mem::size_of::<Status>())
            }
            _ => None,
        }
    }

    /// Return the number of _error_ bytes expected to follow `self`.
    ///
    /// If `None`, the message expects no error data at all.
    pub fn expected_error_data_len(&self) -> Option<usize> {
        match self {
            SpResponse::Read { failed_modules, .. }
            | SpResponse::Write { failed_modules, .. }
            | SpResponse::Status { failed_modules, .. }
            | SpResponse::Ack { failed_modules, .. } => {
                Some(failed_modules.selected_transceiver_count() * HwError::MAX_SIZE)
            }
            _ => None,
        }
    }
}

/// A response to a request for MAC addresses.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize)]
pub enum MacAddrResponse {
    /// The validated MAC address range for the host.
    Ok(MacAddrs),
    /// The MAC address range is invalid.
    Error(BadMacAddrRange),
}

/// A request from the SP to the host.
//
// TODO-implement
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize)]
pub enum SpRequest {}

/// A response to a SP request, sent from host to SP.
//
// TODO-implement
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize)]
pub enum HostResponse {}

bitflags::bitflags! {
    /// The status of a single transceiver module.
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct Status: u8 {
        /// The module is present in the receptacle.
        ///
        /// This translates to the `ModPrsL` pin in SFF-8679 rev 1.8 section
        /// 5.3.4.
        const PRESENT               = 0b0000_0001;

        /// The module's power is enabled.
        ///
        /// Note that this is not part of the QSFP specification, but provided
        /// by the Sidecar board design itself.
        const ENABLED               = 0b0000_0010;

        /// The module is held in reset.
        ///
        /// This translates to the `ResetL` pin in SFF-8679 rev 1.8 section
        /// 5.3.2.
        const RESET                 = 0b0000_0100;

        /// The module is held in low-power mode.
        ///
        /// This translates to the `ResetL` pin in SFF-8679 rev 1.8 section
        /// 5.3.3.
        const LOW_POWER_MODE        = 0b0000_1000;

        /// At least one interrupt is signaled on the module. The details of the
        /// interrupt cause can be queried by reading various bytes of the QSFP
        /// memory map, such as bytes 3-21 in the lower memory page. See
        /// SFF-8636 rev 2.10a section 6.2.3 for details.
        ///
        /// This translates to the `IntL` pin in SFF-8679 rev 1.8 section
        /// 5.3.5.
        const INTERRUPT             = 0b0001_0000;

        /// This module's power supply has come up successfully.
        ///
        /// Note that this is not part of the QSFP specification, but provided
        /// by the Sidecar board design itself.
        const POWER_GOOD            = 0b0010_0000;

        /// This module's power supply has not come up after being enabled.
        ///
        /// Note that this is not part of the QSFP specification, but provided
        /// by the Sidecar board design itself.
        const FAULT_POWER_TIMEOUT   = 0b0100_0000;

        /// This module unexpectedly lost power.
        ///
        /// Note that this is not part of the QSFP specification, but provided
        /// by the Sidecar board design itself.
        const FAULT_POWER_LOST      = 0b1000_0000;
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl core::str::FromStr for Status {
    type Err = bitflags::parser::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().map(Self)
    }
}

impl Serialize for Status {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(self.bits())
    }
}

struct StatusVisitor;

impl<'de> Visitor<'de> for StatusVisitor {
    type Value = Status;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a single u8")
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
        E: SerdeError,
    {
        u8::try_from(v)
            .map(Status::from_bits_truncate)
            .map_err(|_| SerdeError::invalid_value(Unexpected::Unsigned(v), &self))
    }

    fn visit_u32<E>(self, v: u32) -> Result<Self::Value, E>
    where
        E: SerdeError,
    {
        u8::try_from(v)
            .map(Status::from_bits_truncate)
            .map_err(|_| SerdeError::invalid_value(Unexpected::Unsigned(u64::from(v)), &self))
    }

    fn visit_u16<E>(self, v: u16) -> Result<Self::Value, E>
    where
        E: SerdeError,
    {
        u8::try_from(v)
            .map(Status::from_bits_truncate)
            .map_err(|_| SerdeError::invalid_value(Unexpected::Unsigned(u64::from(v)), &self))
    }

    fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
    where
        E: SerdeError,
    {
        Status::from_bits(v).ok_or(SerdeError::invalid_value(
            Unexpected::Unsigned(u64::from(v)),
            &self,
        ))
    }
}

impl<'de> Deserialize<'de> for Status {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_u8(StatusVisitor)
    }
}

impl SerializedSize for Status {
    const MAX_SIZE: usize = core::mem::size_of::<Status>();
}

#[cfg(test)]
mod test {
    use crate::check_invalid_variants;
    use crate::mac::BadMacAddrRange;
    use crate::mac::BadMacAddrReason;
    use crate::mac::MacAddrs;
    use crate::message::deserialize_hw_errors;
    use crate::message::Header;
    use crate::message::HostRequest;
    use crate::message::HwError;
    use crate::message::MacAddrResponse;
    use crate::message::Message;
    use crate::message::MessageBody;
    use crate::message::MessageKind;
    use crate::message::ProtocolError;
    use crate::message::SpResponse;
    use crate::message::Status;
    use crate::mgmt::sff8636;
    use crate::mgmt::MemoryRead;
    use crate::mgmt::MemoryWrite;
    use crate::ModuleId;
    use core::mem::size_of;
    use hubpack::SerializedSize;

    // Tests that the current version has not broken serialization.
    //
    // This uses the fact that `hubpack` assigns IDs to each variant of an enum
    // based on the order they appear.  These are used by
    // `hubpack::{serialize,deserialize}` to determine the enum variant encoded
    // in a binary message, which are based on the _ordering_ of the enum
    // variants. I.e, we're really testing if that ordering has changed in a
    // meaningful way.
    //
    // If it _has_, we have two options:
    //
    // - Bump `MIN` -> `CURRENT`
    // - Rework the changes to avoid that change.
    //
    // Each test below checks one of the enums in the protocol.

    #[test]
    fn test_protocol_error_encoding_unchanged() {
        let mut buf = [0u8; ProtocolError::MAX_SIZE];
        const TEST_DATA: [ProtocolError; 6] = [
            ProtocolError::WrongMessage,
            ProtocolError::NotSupported,
            ProtocolError::RequestTooLarge,
            ProtocolError::WrongDataSize {
                expected: 0,
                actual: 0,
            },
            ProtocolError::VersionMismatch {
                expected: 0,
                actual: 0,
            },
            ProtocolError::Serialization,
        ];
        for (variant_id, variant) in TEST_DATA.iter().enumerate() {
            buf[0] = u8::try_from(variant_id).unwrap();
            let decoded = hubpack::deserialize(&buf).unwrap().0;
            assert_eq!(
                variant, &decoded,
                "Serialization encoding changed! Either `version::outer::CURRENT` \
                or `version::outer::MIN` will need to be updated, \
                or the changes to `ProtocolError` need to be reworked to \
                avoid reordering or removing variants."
            );
        }
        check_invalid_variants::<ProtocolError>(u8::try_from(TEST_DATA.len()).unwrap());
    }

    #[test]
    fn test_hardware_error_encoding_unchanged() {
        let mut buf = [0u8; HwError::MAX_SIZE];
        const TEST_DATA: [HwError; 3] = [
            HwError::I2cError,
            HwError::InvalidModuleIndex,
            HwError::FpgaError,
        ];

        for (variant_id, variant) in TEST_DATA.iter().enumerate() {
            buf[0] = u8::try_from(variant_id).unwrap();
            let decoded = hubpack::deserialize(&buf).unwrap().0;
            assert_eq!(
                variant, &decoded,
                "Serialization encoding changed! Either `version::inner::CURRENT` \
                or `version::inner::MIN` will need to be updated, \
                or the changes to `HwError` need to be reworked to \
                avoid reordering or removing variants."
            );
        }
        check_invalid_variants::<HwError>(u8::try_from(TEST_DATA.len()).unwrap());
    }

    #[test]
    fn test_header_encoding_unchanged() {
        const HEADER: Header = Header {
            version: 0,
            message_id: 0,
            message_kind: MessageKind::Error,
        };
        let decoded = hubpack::deserialize(&[0; Header::MAX_SIZE]).unwrap().0;
        assert_eq!(HEADER, decoded, "Serialization encoding changed!");
    }

    #[test]
    fn test_message_body_encoding_unchanged() {
        let mut buf = [0u8; MessageBody::MAX_SIZE];

        // This is not const because `Memory{Read,Write}` don't have const
        // constructors.
        let modules = ModuleId::empty();
        let read = MemoryRead::new(sff8636::Page::Lower, 0, 1).unwrap();
        let test_data: [MessageBody; 3] = [
            MessageBody::Error(ProtocolError::WrongMessage),
            MessageBody::HostRequest(HostRequest::Read { modules, read }),
            MessageBody::SpResponse(SpResponse::Read {
                modules,
                failed_modules: modules,
                read,
            }),
            // Others cannot be tested, since the enums they contain cannot be
            // constructed.
        ];

        // Touch up the deserialization test buffer for the `MemoryRead`
        // message. This is for the request, the response has an additional
        // offset.
        //
        // This position is computed from:
        //
        // - 1 octet for the HostRequest variant ID
        // - 4 octets for size_of::<MaskType>()
        // - 1 octet for the MemoryRead's Page variant ID
        // - 1 octet for the inner sff8636::Page variant ID
        // - 1 octet for the offset
        const LEN_POS: usize = 5 + core::mem::size_of::<ModuleId>();
        for (variant_id, variant) in test_data.iter().enumerate() {
            buf.fill(0);
            buf[0] = u8::try_from(variant_id).unwrap();

            match variant {
                MessageBody::HostRequest(_) => {
                    buf[LEN_POS] = read.len();
                }
                MessageBody::SpResponse(_) => {
                    // Same offset as above, but we need to add one more
                    // `ModuleId`, as the response includes the failed modules.
                    buf[LEN_POS + core::mem::size_of::<ModuleId>()] = read.len();
                }
                _ => {}
            }
            let decoded = hubpack::deserialize(&buf).unwrap().0;
            assert_eq!(variant, &decoded, "Serialization encoding changed!");
        }
        check_invalid_variants::<MessageBody>(u8::try_from(test_data.len()).unwrap());
    }

    #[test]
    fn test_message_encoding_unchanged() {
        let buf = [0u8; Message::MAX_SIZE];
        const MESSAGE: Message = Message {
            version: 0,
            body: MessageBody::Error(ProtocolError::WrongMessage),
        };
        let decoded = hubpack::deserialize(&buf).unwrap().0;
        assert_eq!(MESSAGE, decoded, "Serialization encoding changed!");
    }

    #[test]
    fn test_mac_addr_response_encoding_unchanged() {
        let mut buf = [0u8; MacAddrResponse::MAX_SIZE];
        let test_data: [MacAddrResponse; 2] = [
            MacAddrResponse::Ok(MacAddrs::new([0; 6], 1, 1).unwrap()),
            MacAddrResponse::Error(BadMacAddrRange {
                reason: BadMacAddrReason::SpansMultipleOuis,
                base_mac: [0; 6],
                count: 0,
                stride: 0,
            }),
        ];
        for (variant_id, variant) in test_data.iter().enumerate() {
            buf.fill(0);
            buf[0] = u8::try_from(variant_id).unwrap();
            // Write in the count / stride if needed;
            if matches!(variant, MacAddrResponse::Ok(_)) {
                let bytes = 1u16.to_le_bytes();
                buf[7..9].copy_from_slice(&bytes);
                buf[9] = 1;
            }
            let decoded = hubpack::deserialize(&buf).unwrap().0;
            assert_eq!(
                variant, &decoded,
                "Serialization encoding changed! Either `version::inner::CURRENT` \
                or `version::inner::MIN` will need to be updated, \
                or the changes to `MacAddrResponse` need to be reworked to \
                avoid reordering or removing variants."
            );
        }
        check_invalid_variants::<MacAddrResponse>(u8::try_from(test_data.len()).unwrap());
    }

    #[test]
    fn test_sp_response_encoding_unchanged() {
        let mut buf = [0u8; SpResponse::MAX_SIZE];

        // This is not const because `Memory{Read,Write}` don't have const
        // constructors.
        let modules = ModuleId::empty();
        let failed_modules = ModuleId::empty();
        let test_data: [SpResponse; 5] = [
            SpResponse::Read {
                modules,
                failed_modules,
                read: MemoryRead::new(sff8636::Page::Lower, 0, 1).unwrap(),
            },
            SpResponse::Write {
                modules,
                failed_modules,
                write: MemoryWrite::new(sff8636::Page::Lower, 0, 1).unwrap(),
            },
            SpResponse::Status {
                modules,
                failed_modules,
            },
            SpResponse::Ack {
                modules,
                failed_modules,
            },
            SpResponse::MacAddrs(MacAddrResponse::Ok(MacAddrs::new([0; 6], 1, 1).unwrap())),
        ];

        for (variant_id, variant) in test_data.iter().enumerate() {
            buf.fill(0);
            buf[0] = u8::try_from(variant_id).unwrap();

            // Touch up the `Memory{Read,Write}` and `MacAddrs` deserialization
            // buffers, since those can't be constructed from all zeros.
            //
            // The length position is offset by:
            //
            // - 1 for the SpResponse variant ID
            // - 8 for the modules
            // - 8 for the failed modules
            // - 1 for the Page variant ID
            // - 1 for the sff8636::Page variant ID
            // - 1 for the offset.
            const LEN_POS: usize = 1 + 2 * core::mem::size_of::<ModuleId>() + 1 + 1 + 1;

            // Count is offset by:
            //
            // - 1 for the SpResponse variant ID
            // - 1 for the MacAddrResponse variant ID
            // - 6 for the MAC octets.
            const COUNT_POS: usize = 8;
            const STRIDE_POS: usize = COUNT_POS + size_of::<u16>();
            match variant {
                SpResponse::Read { read, .. } => {
                    buf[LEN_POS] = read.len();
                }
                SpResponse::Write { write, .. } => {
                    buf[LEN_POS] = write.len();
                }
                SpResponse::MacAddrs(MacAddrResponse::Ok(macs)) => {
                    buf[COUNT_POS..COUNT_POS + size_of::<u16>()]
                        .copy_from_slice(&macs.count().to_le_bytes());
                    buf[STRIDE_POS] = macs.stride();
                }
                _ => {}
            }

            let decoded = hubpack::deserialize(&buf).unwrap().0;
            assert_eq!(
                variant, &decoded,
                "Serialization encoding changed! Either `version::inner::CURRENT` \
                or `version::inner::MIN` will need to be updated, \
                or the changes to `SpResponse` need to be \
                reworked to avoid reordering or removing variants."
            );
        }
    }

    #[test]
    fn test_host_request_data_len() {
        let write = MemoryWrite::new(sff8636::Page::Lower, 0, 2).unwrap();

        let request = HostRequest::Write {
            modules: ModuleId::empty(),
            write,
        };
        assert_eq!(request.expected_data_len(), Some(0));

        let request = HostRequest::Write {
            modules: ModuleId(1),
            write,
        };
        assert_eq!(request.expected_data_len(), Some(2));

        let request = HostRequest::Write {
            modules: ModuleId(0b11),
            write,
        };
        assert_eq!(request.expected_data_len(), Some(4));

        let request = HostRequest::Status(ModuleId(1));
        assert_eq!(request.expected_data_len(), None);
    }

    #[test]
    fn test_sp_response_data_len() {
        let read = MemoryRead::new(sff8636::Page::Lower, 0, 2).unwrap();

        let request = SpResponse::Read {
            modules: ModuleId::empty(),
            failed_modules: ModuleId::empty(),
            read,
        };
        assert_eq!(request.expected_data_len(), Some(0));

        let request = SpResponse::Read {
            modules: ModuleId(1),
            failed_modules: ModuleId::empty(),
            read,
        };
        assert_eq!(request.expected_data_len(), Some(2));

        let request = SpResponse::Read {
            modules: ModuleId(0b11),
            failed_modules: ModuleId::empty(),
            read,
        };
        assert_eq!(request.expected_data_len(), Some(4));

        let request = SpResponse::Status {
            modules: ModuleId(1),
            failed_modules: ModuleId::empty(),
        };
        assert_eq!(
            request.expected_data_len(),
            Some(core::mem::size_of::<Status>())
        );

        let request = SpResponse::Ack {
            modules: ModuleId(1),
            failed_modules: ModuleId::empty(),
        };
        assert_eq!(request.expected_data_len(), None);
    }

    #[test]
    fn test_sp_response_error_data_len() {
        let modules = ModuleId(0b11);
        let failed_modules = ModuleId(0b11);
        let write = MemoryWrite::new(sff8636::Page::Lower, 0, 2).unwrap();
        let read = MemoryRead::new(sff8636::Page::Lower, 0, 2).unwrap();
        let expected = [
            SpResponse::Read {
                modules,
                failed_modules,
                read,
            },
            SpResponse::Write {
                modules,
                failed_modules,
                write,
            },
            SpResponse::Status {
                modules,
                failed_modules,
            },
            SpResponse::Ack {
                modules,
                failed_modules,
            },
        ];
        for each in expected.iter() {
            assert_eq!(
                each.expected_error_data_len(),
                Some(2 * core::mem::size_of::<HwError>())
            );
        }
        let req = SpResponse::MacAddrs(MacAddrResponse::Ok(MacAddrs::new([0; 6], 1, 1).unwrap()));
        assert!(req.expected_error_data_len().is_none());
    }

    #[test]
    fn test_deserialize_hw_errors() {
        let modules = ModuleId(0);
        assert_eq!(deserialize_hw_errors(modules, &[0; 8]).unwrap(), vec![]);

        let modules = ModuleId(1);
        assert_eq!(
            deserialize_hw_errors(modules, &[]).unwrap_err(),
            ProtocolError::WrongDataSize {
                expected: 1,
                actual: 0
            }
        );

        let modules = ModuleId(1);
        assert_eq!(
            deserialize_hw_errors(modules, &[0]).unwrap(),
            vec![HwError::I2cError],
        );
    }

    // Manual tests for serialization of `Status`, since we can't derive `serde`
    // traits on `bitflags >= 2.0`.
    #[test]
    fn test_serialize_status() {
        let st = Status::PRESENT | Status::ENABLED;
        let x = serde_json::to_string(&st).unwrap();
        assert_eq!(x, "3");
        assert_eq!(st, serde_json::from_str(&x).unwrap());

        let mut bytes = vec![0];
        let n_bytes = hubpack::serialize(&mut bytes, &st).unwrap();
        assert_eq!(n_bytes, size_of::<Status>());
        assert_eq!(n_bytes, size_of::<u8>());
        assert_eq!(bytes, &[st.bits()]);
        assert_eq!(st, hubpack::deserialize(&bytes).unwrap().0);
    }
}
