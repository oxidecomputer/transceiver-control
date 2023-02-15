// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

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

    /// Reading transceiver status failed for some reason.
    #[cfg_attr(any(test, feature = "std"), error("Failure reading status: {0}"))]
    StatusFailed(HwError),

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
    /// Failed to write to the `STATUS_PORT` register
    #[cfg_attr(
        any(test, feature = "std"),
        error("Failed to write `STATUS_PORT` register")
    )]
    StatusPortWriteFailed,

    /// Failed to read the `STATUS_PORT` register
    #[cfg_attr(
        any(test, feature = "std"),
        error("Failed to read `STATUS_PORT` register")
    )]
    StatusPortReadFailed,

    /// Failed to write to the `CONTROL_PORT` register
    #[cfg_attr(
        any(test, feature = "std"),
        error("Failed to write `CONTROL_PORT` register")
    )]
    ControlPortWriteFailed,

    /// Failed to read the `CONTROL_PORT` register
    #[cfg_attr(
        any(test, feature = "std"),
        error("Failed to read `CONTROL_PORT` register")
    )]
    ControlPortReadFailed,

    /// Failed to read the `POWER_EN` register
    #[cfg_attr(
        any(test, feature = "std"),
        error("Failed to read `POWER_EN` register")
    )]
    PowerEnableReadFailed,

    /// Failed to write the `POWER_EN` register
    #[cfg_attr(
        any(test, feature = "std"),
        error("Failed to write `POWER_EN` register")
    )]
    PowerEnableWriteFailed,

    /// Failed to read the `RESETL` register
    #[cfg_attr(any(test, feature = "std"), error("Failed to read `RESETL` register"))]
    ResetLReadFailed,

    /// Failed to write the `RESETL` register
    #[cfg_attr(any(test, feature = "std"), error("Failed to write `RESETL` register"))]
    ResetLWriteFailed,

    /// Failed to read the `LPMODE` register
    #[cfg_attr(any(test, feature = "std"), error("Failed to read `LPMODE` register"))]
    LpModeReadFailed,

    /// Failed to write the `LPMODE` register
    #[cfg_attr(any(test, feature = "std"), error("Failed to write `LPMODE` register"))]
    LpModeWriteFailed,

    /// Failed to read the `MODPRSL` register
    #[cfg_attr(any(test, feature = "std"), error("Failed to read `MODPRSL` register"))]
    ModPrsLReadFailed,

    /// Failed to read the `INTL` register
    #[cfg_attr(any(test, feature = "std"), error("Failed to read `INTL` register"))]
    IntLReadFailed,

    /// Failed to read the `PG` register
    #[cfg_attr(any(test, feature = "std"), error("Failed to read `PG` register"))]
    PgReadFailed,

    /// Failed to read the `PG_TIMEOUT` register
    #[cfg_attr(
        any(test, feature = "std"),
        error("Failed to read `PG_TIMEOUT` register")
    )]
    PgTimeoutReadFailed,

    /// Failed to read the `PgLost` register
    #[cfg_attr(any(test, feature = "std"), error("Failed to read `PgLost` register"))]
    PgLostReadFailed,

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

    /// The FPGA reported an I2C error.  u32 is a logical mask for which
    /// ports saw a failure.
    #[cfg_attr(
        any(test, feature = "std"),
        error("FPGA reported an I2C error on the following ports: {:?}", .0.to_indices().collect::<Vec<_>>())
    )]
    I2cError(PortMask),

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

    /// Construct a port bitmask from an iterator over indices.
    ///
    /// If any index is out of bounds, an error is returned.
    pub fn from_index_iter<I: Iterator<Item = u8>>(it: I) -> Result<Self, Error> {
        let mut out = 0;
        for index in it {
            if index >= Self::MAX_INDEX {
                return Err(Error::InvalidPort(index));
            }
            out |= 1 << index;
        }
        Ok(Self(out))
    }

    /// Construct a port bitmask from a slice of indices.
    ///
    /// If any index is out of bounds, an error is returned.
    pub fn from_indices(indices: &[u8]) -> Result<Self, Error> {
        Self::from_index_iter(indices.iter().copied())
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

    /// Convience function to address zero transceivers.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Return the set of modules that are in `self` and not `other`.
    pub const fn remove(&self, other: &PortMask) -> PortMask {
        Self(self.0 & !other.0)
    }

    /// Return `true` if the provided index is contained in set of addressed
    /// modules.
    pub const fn contains(&self, ix: u8) -> bool {
        (self.0 & (1 << ix)) != 0
    }
}

/// Identifier for a set of transceiver modules accessed through a single FPGA.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize, SerializedSize)]
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
    pub const fn all_transceivers(fpga_id: u8) -> Self {
        Self {
            fpga_id,
            ports: PortMask::all(),
        }
    }

    /// Convenience method to build a `ModuleId` that selects no transceivers on
    /// the given FPGA.
    pub const fn empty(fpga_id: u8) -> Self {
        Self {
            fpga_id,
            ports: PortMask::empty(),
        }
    }

    /// Return `true` if the provided index is contained in set of addressed
    /// modules.
    pub const fn contains(&self, ix: u8) -> bool {
        self.ports.contains(ix)
    }
}

/// The MAC address allocation for the target system.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize)]
pub struct MacAddrs {
    // The first valid MAC address for the system.
    base_mac: [u8; 6],
    // The number of available addresses following `base_mac`.
    count: u16,
    // The stride pattern used to compute the next available MAC address.
    //
    // This is used in situations in which subsystems may make assumptions
    // about spacing between addresses. At the time of writing, this applies to
    // the Chelsio T6 NICs.
    stride: u8,
}

impl MacAddrs {
    /// Create a new MAC address range.
    ///
    /// This will do some basic sanity checks on the provided data to make sure
    /// that the full range is valid. Specifically, we check that the base MAC
    /// is not a multicast address, that all addresses in the range share the
    /// same OUI, and that count/stride are nonzero.
    pub const fn new(base_mac: [u8; 6], count: u16, stride: u8) -> Option<Self> {
        if Self::is_valid(base_mac, count, stride) {
            Some(Self {
                base_mac,
                count,
                stride,
            })
        } else {
            None
        }
    }

    const fn is_valid(base_mac: [u8; 6], count: u16, stride: u8) -> bool {
        if count == 0 || stride == 0 {
            return false;
        }

        // Check the multicast bit.
        if (base_mac[0] & 0b1) != 0 {
            return false;
        }

        // Check that the last address, at `n * stride` does not change the OUI.
        let base_n = u32::from_be_bytes([base_mac[2], base_mac[3], base_mac[4], base_mac[5]]);
        let n = count as u32;
        let stride = stride as u32;
        let offset = n * stride; // Cannot overflow based on types.
        match base_n.checked_add(offset) {
            Some(last) => last.to_be_bytes()[0] == base_mac[2],
            None => false,
        }
    }

    /// Return an iterator over the MAC addresses in `self`.
    pub const fn iter(&self) -> MacAddrIter {
        MacAddrIter {
            mac_addrs: *self,
            current: 0,
        }
    }

    /// Return the `n`th address in the range of MACs provided by `self`.
    pub const fn nth(&self, n: u16) -> Option<[u8; 6]> {
        if n >= self.count {
            return None;
        }
        let base_n = u32::from_be_bytes([
            self.base_mac[2],
            self.base_mac[3],
            self.base_mac[4],
            self.base_mac[5],
        ]);

        // Compute the total offset as a `u32`. Based on the types of `n` and
        // `self.stride` this cannot overflow.
        let n = n as u32;
        let stride = self.stride as u32;
        let offset = n * stride;

        // This also cannot overflow, by construction, since we do
        // `base_n.checked_add` in `Self::is_valid`.
        let new_n = base_n + offset;
        let new_bytes = new_n.to_be_bytes();

        Some([
            self.base_mac[0],
            self.base_mac[1],
            self.base_mac[2],
            new_bytes[1],
            new_bytes[2],
            new_bytes[3],
        ])
    }
}

/// An iterator over the MAC addresses in `MacAddrs`. Constructed with
/// [`MacAddrs::iter()`].
pub struct MacAddrIter {
    mac_addrs: MacAddrs,
    current: u16,
}

impl core::iter::Iterator for MacAddrIter {
    type Item = [u8; 6];

    fn next(&mut self) -> Option<Self::Item> {
        match self.mac_addrs.nth(self.current) {
            None => None,
            Some(n) => {
                self.current += 1;
                Some(n)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Error;
    use super::MacAddrs;
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

    #[test]
    fn test_port_mask_remove() {
        let mask = PortMask(0b111);
        let other = PortMask(0b001);
        assert_eq!(mask.remove(&other), PortMask(0b110));
    }

    #[test]
    fn test_port_mask_contains() {
        let mask = PortMask(0b01);
        assert!(mask.contains(0));
        assert!(!mask.contains(1));
    }

    #[test]
    fn test_mac_addrs() {
        let macs = MacAddrs {
            base_mac: [0xa8, 0x40, 0x25, 0x00, 0x00, 0x00],
            count: 8,
            stride: 2,
        };
        let all_macs = macs.iter().collect::<Vec<_>>();
        assert_eq!(all_macs.len(), 8);
        for (mac0, mac1) in macs.iter().take(3).zip(macs.iter().skip(1)) {
            let off0 = u16::from_be_bytes([mac0[4], mac0[5]]);
            let off1 = u16::from_be_bytes([mac1[4], mac1[5]]);
            assert_eq!(off1 - off0, u16::from(macs.stride));
        }
    }

    // Check that we fail to build a MAC address range if we don't pass the
    // basic sanity checks.
    #[test]
    fn test_mac_addrs_is_valid() {
        assert!(
            !MacAddrs::is_valid([0xa8, 0x40, 0x25, 0xff, 0xff, 0xff], 0, 1),
            "Should not be able to make MAC range with count of zero",
        );
        assert!(
            !MacAddrs::is_valid([0xa8, 0x40, 0x25, 0xff, 0xff, 0xff], 2, 0),
            "Should not be able to make MAC range with stride of zero",
        );
        assert!(
            !MacAddrs::is_valid([0xa8, 0x40, 0x25, 0xff, 0xff, 0xff], 2, 1),
            "Should not be able to make MAC range with addresses that change OUI",
        );
        assert!(
            !MacAddrs::is_valid([0xa8 | 0b1, 0x40, 0x25, 0xff, 0xff, 0xff], 2, 1),
            "Should not be able to make MAC range with multicast MACs",
        );
        assert!(
            !MacAddrs::is_valid([0xa8, 0x40, 0xff, 0x01, 0x00, 0xff], u16::MAX, u8::MAX),
            "Should not be able to make MAC range that would overflow",
        );
        assert!(
            MacAddrs::is_valid([0xa8, 0x40, 0xff, 0x01, 0x00, 0xfe], u16::MAX, u8::MAX),
            "Should be able to make MAC range that would not overflow",
        );
    }
}
