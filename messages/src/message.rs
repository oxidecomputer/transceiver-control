// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Message formats and definitions.

use super::mgmt::ManagementInterface;
use super::mgmt::MemoryRead;
use super::mgmt::MemoryWrite;
use super::Error;
use super::MacAddrs;
use super::ModuleId;
use hubpack::SerializedSize;
use serde::Deserialize;
use serde::Serialize;

pub mod version {
    pub const V1: u8 = 1;
    pub const V2: u8 = 2;
    pub const V3: u8 = 3;
    pub const V4: u8 = 4;
    pub const V5: u8 = 5;
    pub const V6: u8 = 6;

    /// The current version of the messaging protocol.
    pub const CURRENT: u8 = V6;

    /// The minimum supported version that is compatible with the current.
    ///
    /// "Compatible" means that all messages from this version may be serialized
    /// and deserialized correctly. That means that all message data in `MIN`
    /// correspond to the same values in `CURRENT` -- colloquially, `CURRENT` is
    /// a superset of `MIN`.
    ///
    /// Because this crate uses `hubpack` for serialization, this also means
    /// that no variants of the message enums have been removed or reordered. So
    /// `CURRENT` may contain _new_ items, but existing ones cannot be moved or
    /// removed.
    ///
    /// This version of the protocol is _committed_. Any changes to the types
    /// here, or [`Error`], _must_ be compatible with this version. They can
    /// add new enum variants, but _must not_ change or reorder any of the
    /// existing variants. Peers should, on a best-effort basis, decode and
    /// handle any messages that are at least this version. If the message comes
    /// from a version prior to their `CURRENT`, they _must_ be able to decode
    /// it, assuming we've not broken compatibility. If the message comes from a
    /// version _after_ `CURRENT`, they _may_ be able to decode it. If they
    /// cannot, presumably because the message was added in a later version,
    /// then they _must_ still send back a protocol error of some kind, such as
    /// `Error::VersionMismatch`. Those are guaranteed to be compatible and
    /// decodable by the peer.
    pub const MIN: u8 = V5;
}

/// A common header to all messages between host and SP.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize)]
pub struct Header {
    /// The protocol version.
    pub version: u8,
    /// An arbitrary message ID, shared between a request and its response.
    pub message_id: u64,
}

/// A message from either the host or SP.
///
/// All messages share a common [`Header`] and reference a set of transceiver
/// modules on a Sidecar. For messages which contain variable length data, such
/// as a [`HostRequest::Write`] or [`SpResponse::Read`], the data is contained
/// in the UDP packet, following the `Message` itself.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize)]
pub struct Message {
    pub header: Header,
    pub modules: ModuleId,
    pub body: MessageBody,
}

impl Message {
    /// Return the length of the expected data that should follow `self`.
    ///
    /// If the message expects no data at all, `None` is returned. If the
    /// message generally expects data, but the particular contents of this one
    /// imply the data should be empty (e.g., zero transceivers were addressed),
    /// then `Some(0)` is returned. Otherwise, `Some(x)` is returned for a
    /// nonzero `x`.
    pub fn expected_data_len(&self) -> Option<usize> {
        let bytes_per_xcvr = match self.body {
            MessageBody::HostRequest(HostRequest::Write(inner)) => usize::from(inner.len()),
            MessageBody::SpResponse(SpResponse::Read(inner)) => usize::from(inner.len()),
            MessageBody::SpResponse(SpResponse::Status) => core::mem::size_of::<Status>(),
            _ => return None,
        };
        Some(self.modules.selected_transceiver_count() * bytes_per_xcvr)
    }
}

/// The body of a message between host and SP.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize)]
pub enum MessageBody {
    /// A request from host to SP.
    ///
    /// Must be replied to with a `SpResponse`.
    HostRequest(HostRequest),

    /// A response from SP to host.
    ///
    /// The intended reply type for a `HostRequest`.
    SpResponse(SpResponse),

    /// A request from SP to host.
    ///
    /// Must be replied to with a `HostResponse`.
    SpRequest(SpRequest),

    /// A response from host to SP.
    ///
    /// The intended reply type for a `SpRequest`.
    HostResponse(HostResponse),
}

/// A request from the host to the SP.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize)]
pub enum HostRequest {
    /// Request to read a region of the transceiver's memory map.
    Read(MemoryRead),

    /// Request to write to a region of the transceiver's memory map.
    ///
    /// The data to be written is contained in the remainder of the UDP packet.
    /// This data should be a single byte array of the size specified by the
    /// contained `MemoryWrite`, and will broadcast to all transceiver modules
    /// addressed by the message.
    Write(MemoryWrite),

    /// Request to return the status of the transceiver's modules.
    Status,

    /// Request that the ResetL line be asserted.
    AssertReset,

    /// Request that the ResetL line be de-asserted.
    DeassertReset,

    /// Request that the LpMode line be asserted.
    AssertLpMode,

    /// Request that the LpMode line be de-asserted.
    DeassertLpMode,

    /// Request that power be enabled to a module should it be inserted.
    EnablePower,

    /// Request that power be disabled to a module should it be inserted.
    DisablePower,

    /// Assert type of management interface that a set of modules uses.
    ///
    /// This is used to allow the SP to read and interpret parts of the
    /// transceivers' memory maps such as the temperature or power draw, for the
    /// purposes of health and safety monitoring.
    ManagementInterface(ManagementInterface),

    /// Ask the SP to return the available MAC addresses for host system use.
    MacAddrs,
}

/// A response to a host request, sent from SP to host.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize)]
pub enum SpResponse {
    /// The request failed.
    Error(Error),

    /// The result of a read operation.
    ///
    /// The actual data read from the transceivers' memory is contained in the
    /// remaining bytes of the UDP packet. Note that this may actually contain a
    /// sequence of byte arrays, one for each of the addressed modules.
    Read(MemoryRead),

    /// The result of a write operation.
    Write(MemoryWrite),

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
    Status,

    /// A generic acknowledgement of a specific message, where no further data
    /// is required from the SP.
    Ack,

    /// The requested MAC address information for the host.
    MacAddrs(MacAddrs),
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
pub enum HostResponse {
    /// The request failed.
    Error(Error),
}

bitflags::bitflags! {
    /// The status of a single transceiver module.
    #[derive(Deserialize, Serialize, SerializedSize)]
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

#[cfg(test)]
mod encoding_tests {
    use super::Error;
    use super::HostRequest;
    use super::HostResponse;
    use super::MessageBody;
    use super::SpResponse;
    use crate::mgmt::sff8636;
    use crate::mgmt::ManagementInterface;
    use crate::mgmt::MemoryRead;
    use crate::mgmt::MemoryWrite;
    use crate::HwError;
    use crate::MacAddrs;
    use crate::PortMask;
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

    // Test that the error variant encoding has not changed.
    #[test]
    fn test_error_encoding_unchanged() {
        let mut buf = [0u8; Error::MAX_SIZE];
        const TEST_DATA: [Error; 16] = [
            Error::InvalidPort(0),
            Error::InvalidFpga(0),
            Error::InvalidPage(0),
            Error::InvalidBank(0),
            Error::PageIsUnbanked(0),
            Error::PageIsBanked(0),
            Error::InvalidMemoryAccess { offset: 0, len: 0 },
            Error::ReadFailed(HwError::StatusPortWriteFailed),
            Error::WriteFailed(HwError::StatusPortWriteFailed),
            Error::StatusFailed(HwError::StatusPortWriteFailed),
            Error::RequestTooLarge,
            Error::ProtocolError,
            Error::MissingData,
            Error::WrongDataSize,
            Error::VersionMismatch {
                expected: 0,
                actual: 0,
            },
            Error::InvalidOperationSize {
                size: 0,
                interface: ManagementInterface::Sff8636,
            },
        ];

        for (variant_id, variant) in TEST_DATA.iter().enumerate() {
            buf[0] = u8::try_from(variant_id).unwrap();
            let (decoded, _rest) = hubpack::deserialize::<Error>(buf.as_slice()).unwrap();
            assert_eq!(
                variant, &decoded,
                "Serialization encoding changed! Either `version::CURRENT` \
                or `version::MIN` will need to be updated, \
                or the changes to `crate::Error` need to be reworked to \
                avoid reordering or removing variants."
            );
        }
    }

    #[test]
    fn test_hardware_error_encoding_unchanged() {
        let mut buf = [0u8; HwError::MAX_SIZE];
        const TEST_DATA: [HwError; 25] = [
            HwError::StatusPortWriteFailed,
            HwError::StatusPortReadFailed,
            HwError::ControlPortWriteFailed,
            HwError::ControlPortReadFailed,
            HwError::PowerEnableReadFailed,
            HwError::PowerEnableWriteFailed,
            HwError::ResetLReadFailed,
            HwError::ResetLWriteFailed,
            HwError::LpModeReadFailed,
            HwError::LpModeWriteFailed,
            HwError::ModPrsLReadFailed,
            HwError::IntLReadFailed,
            HwError::PgReadFailed,
            HwError::PgTimeoutReadFailed,
            HwError::PgLostReadFailed,
            HwError::PageSelectWriteBufFailed,
            HwError::PageSelectWriteFailed,
            HwError::BankSelectWriteBufFailed,
            HwError::BankSelectWriteFailed,
            HwError::WaitFailed,
            HwError::I2cError(PortMask::empty()),
            HwError::ReadSetupFailed,
            HwError::ReadBufFailed,
            HwError::WriteBufFailed,
            HwError::WriteSetupFailed,
        ];

        for (variant_id, variant) in TEST_DATA.iter().enumerate() {
            buf[0] = u8::try_from(variant_id).unwrap();
            let (decoded, _rest) = hubpack::deserialize::<HwError>(buf.as_slice()).unwrap();
            assert_eq!(
                variant, &decoded,
                "Serialization encoding changed! Either `version::CURRENT` \
                or `version::MIN` will need to be updated, \
                or the changes to `crate::HwError` need to be reworked to \
                avoid reordering or removing variants."
            );
        }
    }

    #[test]
    fn test_host_request_encoding_unchanged() {
        let mut buf = [0u8; HostRequest::MAX_SIZE];

        // This is not const because `Memory{Read,Write}` don't have const
        // constructors.
        let test_data: [HostRequest; 11] = [
            HostRequest::Read(MemoryRead::new(sff8636::Page::Lower, 0, 1).unwrap()),
            HostRequest::Write(MemoryWrite::new(sff8636::Page::Lower, 0, 1).unwrap()),
            HostRequest::Status,
            HostRequest::AssertReset,
            HostRequest::DeassertReset,
            HostRequest::AssertLpMode,
            HostRequest::DeassertLpMode,
            HostRequest::EnablePower,
            HostRequest::DisablePower,
            HostRequest::ManagementInterface(ManagementInterface::Sff8636),
            HostRequest::MacAddrs,
        ];

        for (variant_id, variant) in test_data.iter().enumerate() {
            buf.fill(0);
            buf[0] = u8::try_from(variant_id).unwrap();

            // Touch up the deserialization test buffer for the
            // `Memory{Read,Write}` messages.
            //
            // This position is computed from:
            //
            // - 1 octet for the HostRequest variant ID
            // - 1 octet for the MemoryRead's Page variant ID
            // - 1 octet for the inner sff8636::Page variant ID
            // - 1 octet for the offset
            const LEN_POS: usize = 4;
            match variant {
                HostRequest::Read(read) => {
                    buf[LEN_POS] = read.len();
                }
                HostRequest::Write(write) => {
                    buf[LEN_POS] = write.len();
                }
                _ => {}
            }

            let (decoded, _rest) = hubpack::deserialize::<HostRequest>(buf.as_slice()).unwrap();
            assert_eq!(
                variant, &decoded,
                "Serialization encoding changed! Either `version::CURRENT` \
                or `version::MIN` will need to be updated, \
                or the changes to `crate::HostRequest` need to be \
                reworked to avoid reordering or removing variants."
            );
        }
    }

    #[test]
    fn test_sp_response_encoding_unchanged() {
        let mut buf = [0u8; SpResponse::MAX_SIZE];

        // This is not const because `Memory{Read,Write}` don't have const
        // constructors.
        let test_data: [SpResponse; 6] = [
            SpResponse::Error(Error::InvalidPort(0)),
            SpResponse::Read(MemoryRead::new(sff8636::Page::Lower, 0, 1).unwrap()),
            SpResponse::Write(MemoryWrite::new(sff8636::Page::Lower, 0, 1).unwrap()),
            SpResponse::Status,
            SpResponse::Ack,
            SpResponse::MacAddrs(MacAddrs::new([0; 6], 1, 1).unwrap()),
        ];

        for (variant_id, variant) in test_data.iter().enumerate() {
            buf.fill(0);
            buf[0] = u8::try_from(variant_id).unwrap();

            // Touch up the `Memory{Read,Write}` and `MacAddrs` deserialization
            // buffers, since those can't be constructed from all zeros.
            const LEN_POS: usize = 4;
            const COUNT_POS: usize = 7;
            const STRIDE_POS: usize = COUNT_POS + size_of::<u16>();
            match variant {
                SpResponse::Read(read) => {
                    buf[LEN_POS] = read.len();
                }
                SpResponse::Write(write) => {
                    buf[LEN_POS] = write.len();
                }
                SpResponse::MacAddrs(macs) => {
                    buf[COUNT_POS..COUNT_POS + size_of::<u16>()]
                        .copy_from_slice(&macs.count().to_le_bytes());
                    buf[STRIDE_POS] = macs.stride();
                }
                _ => {}
            }

            let (decoded, _rest) = hubpack::deserialize::<SpResponse>(buf.as_slice()).unwrap();
            assert_eq!(
                variant, &decoded,
                "Serialization encoding changed! Either `version::CURRENT` \
                or `version::MIN` will need to be updated, \
                or the changes to `crate::SpResponse` need to be \
                reworked to avoid reordering or removing variants."
            );
        }
    }

    #[test]
    fn test_message_body_encoding_unchanged() {
        let mut buf = [0u8; MessageBody::MAX_SIZE];

        const TEST_DATA: [(u8, MessageBody); 3] = [
            (0, MessageBody::HostRequest(HostRequest::Status)),
            (
                1,
                MessageBody::SpResponse(SpResponse::Error(Error::InvalidPort(0))),
            ),
            // SpRequest cannot be tested, since the enum has no variants.
            (
                3,
                MessageBody::HostResponse(HostResponse::Error(Error::InvalidPort(0))),
            ),
        ];

        for (variant_id, variant) in TEST_DATA.iter() {
            buf.fill(0);
            buf[0] = *variant_id;

            // NOTE: We're artificially making sure we test the
            // `HostRequest::Status` variants. That's just because it's easier
            // to test. 0 maps to `HostRequest::Read`. While we can successfully
            // _deserialize_ that, we can't create one to assert the equality
            // against, since all zeros isn't actually valid. That's because a
            // `len` of 0 isn't valid.
            //
            // The `MessageBody` enum consists only of a u8 for the variant
            // ID, followed by the inner data. So the ID for that inner
            // enum starts at index 1.
            if matches!(variant, MessageBody::HostRequest(_)) {
                const STATUS_VARIANT_START: usize = 1;
                const STATUS_VARIANT_ID: u8 = 2;
                buf[STATUS_VARIANT_START] = STATUS_VARIANT_ID;
            }

            let (decoded, _rest) = hubpack::deserialize::<MessageBody>(buf.as_slice()).unwrap();
            assert_eq!(
                variant, &decoded,
                "Serialization encoding changed! Either `version::CURRENT` \
                or `version::MIN` will need to be updated, \
                or the changes to `crate::MessageBody` need to be \
                reworked to avoid reordering or removing variants."
            );
        }
    }
}
