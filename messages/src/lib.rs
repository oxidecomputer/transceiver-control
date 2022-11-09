// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![cfg_attr(all(not(test), not(feature = "std")), no_std)]

//! Messaging formats for managing the Sidecar QSFP ports over the network.

pub mod message;

#[cfg(all(not(test), not(feature = "std")))]
use heapless::Vec;

#[cfg(any(test, feature = "std"))]
use std::vec::Vec;

use hubpack::SerializedSize;
use serde::Deserialize;
use serde::Serialize;

/// The maximum size of the body of a message.
pub const MAX_MESSAGE_SIZE: usize = 1024;

/// The UDP port on which both sides should listen.
///
/// Note that the protocol is by-definition bidirectional. Both the host and SP
/// may initiate messages to their peer. For the host, this includes things like
/// write requests; for the SP, it may initiate messages to notify the host of
/// interrupts or alarms.
pub const PORT: u16 = 22222;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize, SerializedSize)]
pub enum Error {
    /// An attempt to reference an invalid QSFP port on a Sidecar or FPGA.
    InvalidPort(u8),
    /// An attempt to reference an invalid FPGA on a Sidecar.
    InvalidFpga(u8),
    /// An attempt was made to read or write an invalid or unsupported QSFP
    /// memory map page.
    InvalidQsfpPage(u8),
    /// An attempt to read or write an invalid portion of QSFP memory map.
    InvalidMemoryAccess { page: u8, offset: u8, len: u8 },
    /// A read failed for some reason.
    ReadFailed,
    /// A write failed for some reason.
    WriteFailed,
    /// A request would result in a response that is too large to fit in a
    /// single UDP message.
    RequestTooLarge,
}

/// A bitmask used to identify ports, on a single FPGA.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize, SerializedSize)]
pub struct PortMask(u32);

impl core::fmt::UpperHex for PortMask {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:X}", self.0)
    }
}

impl PortMask {
    pub const NUM_PORTS: u8 = 32;

    /// Return true if the provided index is set, or false otherwise. If the
    /// index is out of range, and error is returned.
    pub fn is_set(&self, index: u8) -> Result<bool, Error> {
        if index >= Self::NUM_PORTS {
            Err(Error::InvalidPort(index))
        } else {
            Ok((self.0 & (1 << index)) != 0)
        }
    }

    /// Set the bit at the provided index. If it is out of range, an error is
    /// returned.
    pub fn set(&mut self, index: u8) -> Result<(), Error> {
        if index >= Self::NUM_PORTS {
            Err(Error::InvalidPort(index))
        } else {
            self.0 |= 1 << index;
            Ok(())
        }
    }

    /// Clear the bit at the provided index. If it is out of range, an error is
    /// returned.
    pub fn clear(&mut self, index: u8) -> Result<(), Error> {
        if index >= Self::NUM_PORTS {
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
            if index >= Self::NUM_PORTS {
                return Err(Error::InvalidPort(index));
            }
            out |= 1 << index;
        }
        Ok(Self(out))
    }

    /// Return the indices of the ports identified by the bitmask.
    pub fn to_indices(&self) -> impl Iterator<Item = u8> + '_ {
        (0..Self::NUM_PORTS).filter(|i| self.is_set(*i).unwrap())
    }

    /// A convenience function to return a port bitmask identifying a single
    /// port by index.
    pub const fn single(index: u8) -> Result<Self, Error> {
        if index >= Self::NUM_PORTS {
            Err(Error::InvalidPort(index))
        } else {
            Ok(Self(1 << index))
        }
    }
}

impl From<u32> for PortMask {
    fn from(x: u32) -> Self {
        Self(x)
    }
}

impl From<PortMask> for u32 {
    fn from(m: PortMask) -> Self {
        m.0
    }
}

/// Identifier for an FPGA on a Sidecar.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize)]
pub struct Fpga(u8);

impl Fpga {
    pub const LEFT: Self = Self(0);
    pub const RIGHT: Self = Self(1);
}

impl TryFrom<u8> for Fpga {
    type Error = Error;
    fn try_from(x: u8) -> Result<Self, Self::Error> {
        let maybe_self = Self(x);
        match maybe_self {
            Self::LEFT | Self::RIGHT => Ok(maybe_self),
            _ => Err(Error::InvalidFpga(x)),
        }
    }
}

/// A unique identifier for a set of transceiver modules on a Sidecar.
///
/// Modules are identified by a combination of the FPGA and a bitmask of ports
/// on that FPGA.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize, SerializedSize)]
pub struct ModuleId {
    pub fpga: Fpga,
    pub ports: PortMask,
}

impl core::fmt::UpperHex for ModuleId {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "0x{:X}:0x{:X}", self.fpga.0, self.ports)
    }
}

// Map a logical port to the FPGA and per-FPGA port index.
fn port_to_ids(port: u8) -> Result<(Fpga, u8), Error> {
    // There are 16 ports per FPGA, with a stride of 8. That is:
    //
    // Logical port     FPGA    On-FPGA port
    // ------------     ----    ------------
    // 0-8              0       0-8
    // 8-16             1       0-8
    // 16-24            0       9-16
    // 24-32            1       9-16.
    //
    // The below basically implements poor-man's 2D array indexing from a single
    // flattened index, assuming row-major ordering.
    const STRIDE: u8 = 8;
    const PORTS_PER_FPGA: u8 = 16;
    const NUM_FPGAS: u8 = 2;
    let fpga_id = (port / STRIDE) % NUM_FPGAS;
    let port_index = ((port / PORTS_PER_FPGA) * STRIDE) + (port % STRIDE);
    Fpga::try_from(fpga_id).map(|fpga| (fpga, port_index))
}

pub fn ids_from_logical_ports(ports: &[u8]) -> Result<[ModuleId; 2], Error> {
    let mut port_indices: Vec<(Fpga, Vec<u8>)> = Vec::with_capacity(2);
    for port in ports {
        let (this_fpga, index) = port_to_ids(*port)?;
        match port_indices.iter_mut().find(|(fpga, _)| fpga == &this_fpga) {
            Some((_, ref mut indices)) => indices.push(index),
            None => port_indices.push((this_fpga, vec![index])),
        }
    }
    port_indices
        .into_iter()
        .map(|(fpga, indices)| {
            PortMask::from_indices(&indices).map(|ports| ModuleId { fpga, ports })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::ids_from_logical_ports;
    use super::Error;
    use super::Fpga;
    use super::PortMask;

    #[test]
    fn test_port_mask_from_indices() {
        let ix = vec![0, 1, 2];
        let mask = PortMask::from_indices(&ix).unwrap();
        assert_eq!(u32::from(mask), 0b111);
        assert_eq!(mask.to_indices().collect::<Vec<_>>(), ix);
    }

    #[test]
    fn test_port_mask_from_indices_out_of_range() {
        let port = PortMask::NUM_PORTS;
        assert_eq!(
            PortMask::from_indices(&[port]),
            Err(Error::InvalidPort(port))
        );
    }

    #[test]
    fn test_port_mask_test_set_clear() {
        let mut mask = PortMask::from(0b101u32);
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
    fn test_fpga() {
        assert_eq!(Fpga::try_from(0u8).unwrap(), Fpga::LEFT);
        assert_eq!(Fpga::try_from(1u8).unwrap(), Fpga::RIGHT);
        assert_eq!(Fpga::try_from(10u8), Err(Error::InvalidFpga(10)));
    }

    #[test]
    fn test_ids_from_logical_ports() {
        let logical = (0..PortMask::NUM_PORTS).collect::<Vec<_>>();
        let ids = ids_from_logical_ports(&logical).unwrap();
        assert_eq!(ids.len(), 2);

        let id = &ids[0];
        assert_eq!(id.fpga, Fpga::LEFT);
        for i in 0..16 {
            assert!(id.ports.is_set(i).unwrap());
        }

        let id = &ids[1];
        assert_eq!(id.fpga, Fpga::RIGHT);
        for i in 0..16 {
            assert!(id.ports.is_set(i).unwrap());
        }
    }
}
