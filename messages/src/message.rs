// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Message formats and definitions.

use super::mgmt::ManagementInterface;
use super::mgmt::MemoryRead;
use super::mgmt::MemoryWrite;
use super::Error;
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

    pub const CURRENT: u8 = V5;
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
