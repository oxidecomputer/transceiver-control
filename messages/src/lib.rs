// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

#![cfg_attr(all(not(test), not(feature = "std")), no_std)]

//! Messaging formats for managing the Sidecar transceiver ports over the
//! network.

pub mod message;
pub mod mgmt;

use hubpack::SerializedSize;
use mgmt::ManagementInterface;
use serde::Deserialize;
use serde::Serialize;

/// The maximum size of the payload of a message, i.e., any trailing data after
/// the [`message::Message`] contents.
pub const MAX_PAYLOAD_SIZE: usize = 1024;

/// The UDP port on which both sides should listen.
///
/// Note that the protocol is by-definition bidirectional. Both the host and SP
/// may initiate messages to their peer. For the host, this includes things like
/// write requests; for the SP, it may initiate messages to notify the host of
/// interrupts or alarms.
pub const PORT: u16 = 11112;

/// The IPv6 multicast address on which both peers should listen.
///
/// See RFD 250 for backgroun on this specific address. Briefly, this is a
/// link-local multicast address that is unlikely to conflict with others, such
/// as the All-Nodes address.
//
// NOTE: This isn't a `std::net::Ipv6Addr` to support `no_std` environments.
pub const ADDR: [u16; 8] = [0xff02, 0, 0, 0, 0, 0, 0x1de, 2];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize)]
#[cfg_attr(any(test, feature = "std"), derive(thiserror::Error))]
pub enum Error {
    /// An attempt to reference an invalid transceiver port on a Sidecar or FPGA.
    #[cfg_attr(any(test, feature = "std"), error("Invalid transceiver port: {0}"))]
    InvalidPort(u8),

    /// An attempt to reference an invalid FPGA on a Sidecar.
    #[cfg_attr(any(test, feature = "std"), error("Invalid FPGA: {0}"))]
    InvalidFpga(u8),

    /// Accessed an invalid upper memory page.
    #[cfg_attr(
        any(test, feature = "std"),
        error("Invalid upper memory page: 0x{0:02x}")
    )]
    InvalidPage(u8),

    /// Accessed an invalid upper memory bank.
    #[cfg_attr(
        any(test, feature = "std"),
        error("Invalid upper memory bank: 0x{0:02x}")
    )]
    InvalidBank(u8),

    /// A page does not accept a bank number.
    #[cfg_attr(
        any(test, feature = "std"),
        error("Page does not accept a bank number: 0x{0:02x}")
    )]
    PageIsUnbanked(u8),

    /// A page requires a bank number.
    #[cfg_attr(
        any(test, feature = "std"),
        error("Page requires a bank number: 0x{0:02x}")
    )]
    PageIsBanked(u8),

    /// An access to memory outside of the 256-byte memory map.
    #[cfg_attr(
        any(test, feature = "std"),
        error(
            "Invalid memory access: \
            offset=0x{offset:02x}, len=0x{len:02x}"
        )
    )]
    InvalidMemoryAccess { offset: u8, len: u8 },

    /// A read failed for some reason.
    #[cfg_attr(any(test, feature = "std"), error("Failure during read: {0}"))]
    ReadFailed(HwError),

    /// A write failed for some reason.
    #[cfg_attr(any(test, feature = "std"), error("Failure during write: {0}"))]
    WriteFailed(HwError),

    /// A reset failed for some reason.
    #[cfg_attr(any(test, feature = "std"), error("Failure during reset: {0}"))]
    ResetFailed(HwError),

    /// Reading transceiver status failed for some reason.
    #[cfg_attr(any(test, feature = "std"), error("Failure reading status: {0}"))]
    StatusFailed(HwError),

    /// Failed to set power mode
    #[cfg_attr(any(test, feature = "std"), error("Failure to set power mode: {0}"))]
    PowerModeFailed(HwError),

    /// A request would result in a response that is too large to fit in a
    /// single UDP message.
    #[cfg_attr(
        any(test, feature = "std"),
        error("Request too large for single protocol message")
    )]
    RequestTooLarge,

    /// Someone sent an unexpected message (e.g. the host sending an SpRequest).
    #[cfg_attr(any(test, feature = "std"), error("Protocol error"))]
    ProtocolError,

    /// A message expected trailing data, but none was contained in the UDP
    /// packet.
    #[cfg_attr(
        any(test, feature = "std"),
        error("Message expects trailing data, but none found")
    )]
    MissingData,

    /// The trailing data is an unexpected size.
    #[cfg_attr(
        any(test, feature = "std"),
        error("Message trailing data has incorrect size")
    )]
    WrongDataSize,

    /// The version in the header is unexpected.
    #[cfg_attr(
        any(test, feature = "std"),
        error("Version mismatch: expected={expected}, actual={actual}")
    )]
    VersionMismatch { expected: u8, actual: u8 },

    /// A write or read is an invalid size for the provided management
    /// interface.
    #[cfg_attr(
        any(test, feature = "std"),
        error(
            "Write or read of {size} bytes too \
            large for management interface {interface:?}"
        )
    )]
    InvalidOperationSize {
        size: u8,
        interface: ManagementInterface,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize, SerializedSize)]
#[cfg_attr(any(test, feature = "std"), derive(thiserror::Error))]
pub enum HwError {
    /// Could not set the reset pin
    #[cfg_attr(any(test, feature = "std"), error("Could not set reset pin"))]
    SetResetFailed,

    /// Could not clear the reset pin
    #[cfg_attr(any(test, feature = "std"), error("Could not clear reset pin"))]
    ClearResetFailed,

    /// Failed to clear the power enable mask
    #[cfg_attr(any(test, feature = "std"), error("Failed to clear power enable mask"))]
    ClearPowerEnableFailed,

    /// Failed to set the power enable mask
    #[cfg_attr(any(test, feature = "std"), error("Failed to set power enable mask"))]
    SetPowerEnableFailed,

    /// Failed to clear the low power mode mask
    #[cfg_attr(
        any(test, feature = "std"),
        error("Failed to clear low power mode mask")
    )]
    ClearLpModeFailed,

    /// Failed to set the low power mode mask
    #[cfg_attr(any(test, feature = "std"), error("Failed to set low power mode mask"))]
    SetLpModeFailed,

    /// Failed to read the `EN` register
    #[cfg_attr(any(test, feature = "std"), error("Failed to read `EN` register"))]
    EnableReadFailed,

    /// Failed to read the `RESET` register
    #[cfg_attr(any(test, feature = "std"), error("Failed to read `RESET` register"))]
    ResetReadFailed,

    /// Failed to read the `LPMODE` register
    #[cfg_attr(any(test, feature = "std"), error("Failed to read `LPMODE` register"))]
    LpReadFailed,

    /// Failed to read the `PRESENT` register
    #[cfg_attr(any(test, feature = "std"), error("Failed to read `PRESENT` register"))]
    PresentReadFailed,

    /// Failed to read the `IRQ` register
    #[cfg_attr(any(test, feature = "std"), error("Failed to read `IRQ` register"))]
    IrqReadFailed,

    /// Could not set up the write buffer for a page select
    #[cfg_attr(
        any(test, feature = "std"),
        error("Could not set up write buffer for page select")
    )]
    PageSelectWriteBufFailed,

    /// The page select write operation failed
    #[cfg_attr(
        any(test, feature = "std"),
        error("Page select write operation failed")
    )]
    PageSelectWriteFailed,

    /// Could not set up the write buffer for a bank select
    #[cfg_attr(
        any(test, feature = "std"),
        error("Could not set up write buffer for bank select")
    )]
    BankSelectWriteBufFailed,

    /// The bank select write operation failed
    #[cfg_attr(
        any(test, feature = "std"),
        error("Bank select write operation failed")
    )]
    BankSelectWriteFailed,

    /// Waiting for the operation to complete failed
    #[cfg_attr(
        any(test, feature = "std"),
        error("Waiting for the operation to complete failed")
    )]
    WaitFailed,

    /// The FPGA reported an I2C error
    #[cfg_attr(
        any(test, feature = "std"),
        error("FPGA reported an I2C error, module may not be present")
    )]
    I2cError,

    /// The read setup operation failed
    #[cfg_attr(any(test, feature = "std"), error("Read setup operation failed"))]
    ReadSetupFailed,

    /// Reading back the read buffer failed
    #[cfg_attr(
        any(test, feature = "std"),
        error("Reading back the FPGA read buffer failed")
    )]
    ReadBufFailed,

    /// Loading the write buffer failed
    #[cfg_attr(
        any(test, feature = "std"),
        error("Loading the FPGA write buffer failed")
    )]
    WriteBufFailed,

    /// The write setup call failed
    #[cfg_attr(any(test, feature = "std"), error("Write setup call failed"))]
    WriteSetupFailed,
}

// We're currently only expecting to be able to address up to 16 transceivers
// per Sidecar FPGA. The `PortMask` below exposes this publicly, so we may wish
// to hide it if / when we want to support other front I/O board designs with
// different arrangements of FPGAs and / or transceivers.
type MaskType = u16;

/// A bitmask used to identify the set of transceiver ports to which a message
/// applies.
///
/// Note that this bitmask is always per-FPGA.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize, SerializedSize)]
pub struct PortMask(pub MaskType);

impl PortMask {
    pub const MAX_INDEX: u8 = (core::mem::size_of::<MaskType>() * 8) as _;

    /// Return true if the provided index is set, or false otherwise. If the
    /// index is out of range, and error is returned.
    pub fn is_set(&self, index: u8) -> Result<bool, Error> {
        if index >= Self::MAX_INDEX {
            Err(Error::InvalidPort(index))
        } else {
            Ok((self.0 & (1 << index)) != 0)
        }
    }

    /// Set the bit at the provided index. If it is out of range, an error is
    /// returned.
    pub fn set(&mut self, index: u8) -> Result<(), Error> {
        if index >= Self::MAX_INDEX {
            Err(Error::InvalidPort(index))
        } else {
            self.0 |= 1 << index;
            Ok(())
        }
    }

    /// Clear the bit at the provided index. If it is out of range, an error is
    /// returned.
    pub fn clear(&mut self, index: u8) -> Result<(), Error> {
        if index >= Self::MAX_INDEX {
            Err(Error::InvalidPort(index))
        } else {
            self.0 &= !(1 << index);
            Ok(())
        }
    }

    /// Construct a port bitmask from a slice of indices.
    ///
    /// If any index is out of bounds, an error is returned.
    pub fn from_indices(indices: &[u8]) -> Result<Self, Error> {
        let mut out = 0;
        for index in indices.iter().copied() {
            if index >= Self::MAX_INDEX {
                return Err(Error::InvalidPort(index));
            }
            out |= 1 << index;
        }
        Ok(Self(out))
    }

    /// Return the indices of the ports identified by the bitmask.
    pub fn to_indices(&self) -> impl Iterator<Item = u8> + '_ {
        (0..Self::MAX_INDEX).filter(|i| self.is_set(*i).unwrap())
    }

    /// A convenience function to return a port bitmask identifying a single
    /// port by index.
    pub const fn single(index: u8) -> Result<Self, Error> {
        if index >= Self::MAX_INDEX {
            Err(Error::InvalidPort(index))
        } else {
            Ok(Self(1 << index))
        }
    }

    /// Return the number of transceivers addressed by `self.
    pub const fn selected_transceiver_count(&self) -> usize {
        self.0.count_ones() as _
    }

    /// Convience function to address all transceivers.
    pub const fn all() -> Self {
        Self(!0)
    }
}

/// Identifier for a set of transceiver modules accessed through a single FPGA.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Serialize, SerializedSize)]
pub struct ModuleId {
    pub fpga_id: u8,
    pub ports: PortMask,
}

impl ModuleId {
    /// Return the number of transceivers addressed by `self`.
    pub const fn selected_transceiver_count(&self) -> usize {
        self.ports.selected_transceiver_count()
    }

    /// Convenience method to build a `ModuleId` that selects all transceivers
    /// on the given FPGA.
    pub const fn all_transceivers(&self, fpga_id: u8) -> Self {
        Self {
            fpga_id,
            ports: PortMask::all(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Error;
    use super::PortMask;

    #[test]
    fn test_port_mask_from_indices() {
        let ix = vec![0, 1, 2];
        let mask = PortMask::from_indices(&ix).unwrap();
        assert_eq!(mask.0, 0b111);
        assert_eq!(mask.to_indices().collect::<Vec<_>>(), ix);
    }

    #[test]
    fn test_port_mask_from_indices_out_of_range() {
        let port = PortMask::MAX_INDEX;
        assert_eq!(
            PortMask::from_indices(&[port]),
            Err(Error::InvalidPort(port))
        );
    }

    #[test]
    fn test_port_mask_test_set_clear() {
        let mut mask = PortMask(0b101);
        assert!(mask.is_set(0).unwrap());
        assert!(!mask.is_set(1).unwrap());
        assert!(mask.is_set(2).unwrap());

        mask.set(0).unwrap();
        assert!(mask.is_set(0).unwrap());

        mask.set(1).unwrap();
        assert!(mask.is_set(1).unwrap());

        mask.clear(1).unwrap();
        assert!(!mask.is_set(1).unwrap());

        assert!(mask.set(200).is_err());
        assert!(mask.clear(200).is_err());
        assert!(mask.is_set(200).is_err());
    }

    #[test]
    fn test_port_mask_all() {
        assert_eq!(PortMask::all().0, 0xFFFF);
    }

    #[test]
    fn test_selected_transceiver_count() {
        assert_eq!(PortMask(0b101).selected_transceiver_count(), 2);
    }
}
