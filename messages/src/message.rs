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
}

/// A common header to all messages between host and SP.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize, SerializedSize)]
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
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize, SerializedSize)]
pub struct Message {
    pub header: Header,
    pub modules: ModuleId,
    pub body: MessageBody,
}

/// The body of a message between host and SP.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize, SerializedSize)]
pub enum MessageBody {
    HostRequest(HostRequest),
    HostResponse(HostResponse),
    SpRequest(SpRequest),
    SpResponse(SpResponse),
}

/// A request from the host to the SP.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize, SerializedSize)]
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

    /// Request that the modules be reset.
    Reset,

    /// Explicity request that the modules go into a specific power mode.
    ///
    /// Note that this includes the low- and high-power modes defined by the
    /// electrical specifications such as SFF-8679 (the `LPMode` pin), but also
    /// allows us to explicitly power down a transceiver. That is useful for
    /// ensuring that there's no wasted power, for example, when a customer
    /// purposefully disables a transceiver via the control plane.
    ///
    /// Note that the _host side_ is responsible for ensuring that a transition
    /// to high-power mode is valid. The host guarantees that it has applied
    /// the configuration required by the module, prior to requesting such a
    /// transition.
    SetPowerMode(PowerMode),

    /// Assert type of management interface that a set of modules uses.
    ///
    /// This is used to allow the SP to read and interpret parts of the
    /// transceivers' memory maps such as the temperature or power draw, for the
    /// purposes of health and safety monitoring.
    ManagementInterface(ManagementInterface),
}

/// A response to a host request, sent from SP to host.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize, SerializedSize)]
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
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize, SerializedSize)]
pub enum SpRequest {}

/// A response to a SP request, sent from host to SP.
//
// TODO-implement
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize, SerializedSize)]
pub enum HostResponse {}

bitflags::bitflags! {
    /// The status of a single transceiver module.
    #[derive(Deserialize, Serialize, SerializedSize)]
    pub struct Status: u8 {
        /// The module is present in the receptacle.
        ///
        /// This translates to the `ModPrsL` pin in SFF-8679 rev 1.8 section
        /// 5.3.4.
        const PRESENT           = 0b0000_0001;

        /// The module's power is enabled.
        ///
        /// Note that this is not part of the QSFP specification, but provided
        /// by the Sidecar board design itself.
        const ENABLED           = 0b0000_0010;

        /// The module is held in reset.
        ///
        /// This translates to the `ResetL` pin in SFF-8679 rev 1.8 section
        /// 5.3.2.
        const RESET             = 0b0000_0100;

        /// The module is held in low-power mode.
        ///
        /// This translates to the `ResetL` pin in SFF-8679 rev 1.8 section
        /// 5.3.3.
        const LOW_POWER_MODE    = 0b0000_1000;

        /// At least one interrupt is signaled on the module. The details of the
        /// interrupt cause can be queried by reading various bytes of the QSFP
        /// memory map, such as bytes 3-21 in the lower memory page. See
        /// SFF-8636 rev 2.10a section 6.2.3 for details.
        ///
        /// This translates to the `IntL` pin in SFF-8679 rev 1.8 section
        /// 5.3.5.
        const INTERRUPT         = 0b0001_0000;
    }
}

/// An allowed power mode for the module.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize, SerializedSize)]
pub enum PowerMode {
    /// A module is entirely powered off, using the EFuse.
    Off,

    /// Power is enabled to the module, but the `LPMode` pin is set to high.
    ///
    /// Note: This requires that we never set the `Power_override` bit (SFF-8636
    /// rev 2.10a, section 6.2.6, byte 93 bit 2), as that defeats the purpose of
    /// hardware control.
    Low,

    /// The module is in high-power mode.
    ///
    /// Note that additional configuration may be required to correctly
    /// configure the module, such as described in SFF-8636 rev 2.10a table
    /// 6-10, and that the _host side_ is responsible for ensuring that the
    /// relevant configuration is applied.
    High,
}
