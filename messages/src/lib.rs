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

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize, SerializedSize)]
#[cfg_attr(any(test, feature = "std"), derive(thiserror::Error))]
pub enum Error {
    /// An attempt to reference an invalid transceiver port on a Sidecar or FPGA.
    InvalidPort(u8),

    /// An attempt to reference an invalid FPGA on a Sidecar.
    InvalidFpga(u8),

    /// Accessed an invalid upper memory page.
    InvalidPage(u8),

    /// Accessed an invalid upper memory bank.
    InvalidBank(u8),

    /// A page does not accept a bank number.
    PageIsUnbanked(u8),

    /// A page requires a bank number.
    PageIsBanked(u8),

    /// An access to memory outside of the 256-byte memory map.
    InvalidMemoryAccess { offset: u8, len: u8 },

    /// A read failed for some reason.
    ReadFailed,

    /// A write failed for some reason.
    WriteFailed,

    /// A request would result in a response that is too large to fit in a
    /// single UDP message.
    RequestTooLarge,

    /// Someone sent an unexpected message (e.g. the host sending an SpRequest).
    ProtocolError,

    /// A message expected trailing data, but none was contained in the UDP
    /// packet.
    MissingData,

    /// The version in the header is unexpected.
    VersionMismatch { expected: u8, actual: u8 },
}

#[cfg(any(test, feature = "std"))]
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
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
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Serialize, SerializedSize)]
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
