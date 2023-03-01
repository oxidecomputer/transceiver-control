// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Operate on MAC addresses from the SP.

use hubpack::SerializedSize;
use serde::Deserialize;
use serde::Serialize;

/// An error indicating that a MAC address range is invalid.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize, SerializedSize)]
#[cfg_attr(any(test, feature = "std"), derive(thiserror::Error))]
pub struct BadMacAddrRange {
    pub reason: BadMacAddrReason,
    pub base_mac: [u8; 6],
    pub count: u16,
    pub stride: u8,
}

impl core::fmt::Display for BadMacAddrRange {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            f,
            "The MAC address range is invalid, \
            reason: {:?}, base: {:?}, \
            count: {}, stride: {}",
            self.reason, self.base_mac, self.count, self.stride,
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize, SerializedSize)]
#[cfg_attr(any(test, feature = "std"), derive(thiserror::Error))]
pub enum BadMacAddrReason {
    /// The range spans multiple OUIs
    #[cfg_attr(
        any(test, feature = "std"),
        error("The MAC address range spans multiple OUIs")
    )]
    SpansMultipleOuis,

    /// The count or stride is zero.
    #[cfg_attr(
        any(test, feature = "std"),
        error("The MAC address count and/or stride is zero")
    )]
    ZeroStrideOrCount,

    /// The base MAC address is multicast.
    #[cfg_attr(any(test, feature = "std"), error("The base MAC address is multicast"))]
    MulticastBaseAddr,
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
    pub const fn new(base_mac: [u8; 6], count: u16, stride: u8) -> Result<Self, BadMacAddrRange> {
        if count == 0 || stride == 0 {
            return Err(BadMacAddrRange {
                reason: BadMacAddrReason::ZeroStrideOrCount,
                base_mac,
                count,
                stride,
            });
        }

        // Check the multicast bit.
        if (base_mac[0] & 0b1) != 0 {
            return Err(BadMacAddrRange {
                reason: BadMacAddrReason::MulticastBaseAddr,
                base_mac,
                count,
                stride,
            });
        }

        // Check that the last address, at `n * stride` does not change the OUI.
        let base_n = u32::from_be_bytes([base_mac[2], base_mac[3], base_mac[4], base_mac[5]]);
        let n = count as u32;
        let offset = n * stride as u32; // Cannot overflow based on types.
        match base_n.checked_add(offset) {
            Some(last) if last.to_be_bytes()[0] == base_mac[2] => Ok(Self {
                base_mac,
                count,
                stride,
            }),
            _ => Err(BadMacAddrRange {
                reason: BadMacAddrReason::SpansMultipleOuis,
                base_mac,
                count,
                stride,
            }),
        }
    }

    /// Return the base MAC address of the range.
    pub const fn base_mac(&self) -> &[u8; 6] {
        &self.base_mac
    }

    /// Return the count of addresses in the range.
    pub const fn count(&self) -> u16 {
        self.count
    }

    /// Return the stride of the addresses in the range.
    pub const fn stride(&self) -> u8 {
        self.stride
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
    use super::BadMacAddrRange;
    use super::BadMacAddrReason;
    use super::MacAddrs;
    use crate::check_invalid_variants;
    use hubpack::SerializedSize;

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
            matches!(
                MacAddrs::new([0xa8, 0x40, 0x25, 0xff, 0xff, 0xff], 0, 1),
                Err(BadMacAddrRange {
                    reason: BadMacAddrReason::ZeroStrideOrCount,
                    ..
                }),
            ),
            "Should not be able to make MAC range with count of zero",
        );
        assert!(
            matches!(
                MacAddrs::new([0xa8, 0x40, 0x25, 0xff, 0xff, 0xff], 2, 0),
                Err(BadMacAddrRange {
                    reason: BadMacAddrReason::ZeroStrideOrCount,
                    ..
                }),
            ),
            "Should not be able to make MAC range with stride of zero",
        );
        assert!(
            matches!(
                MacAddrs::new([0xa8, 0x40, 0x25, 0xff, 0xff, 0xff], 2, 1),
                Err(BadMacAddrRange {
                    reason: BadMacAddrReason::SpansMultipleOuis,
                    ..
                }),
            ),
            "Should not be able to make MAC range with addresses that change OUI",
        );
        assert!(
            matches!(
                MacAddrs::new([0xa8 | 0b1, 0x40, 0x25, 0xff, 0xff, 0xff], 2, 1),
                Err(BadMacAddrRange {
                    reason: BadMacAddrReason::MulticastBaseAddr,
                    ..
                })
            ),
            "Should not be able to make MAC range with multicast MACs",
        );
        assert!(
            matches!(
                MacAddrs::new([0xa8, 0x40, 0xff, 0x01, 0x00, 0xff], u16::MAX, u8::MAX),
                Err(BadMacAddrRange {
                    reason: BadMacAddrReason::SpansMultipleOuis,
                    ..
                }),
            ),
            "Should not be able to make MAC range that would overflow",
        );
        MacAddrs::new([0xa8, 0x40, 0xff, 0x01, 0x00, 0xfe], u16::MAX, u8::MAX)
            .expect("Should be able to make MAC range that would not overflow");
    }

    #[test]
    fn test_bad_mac_addr_reason_encoding_unchanged() {
        const TEST_DATA: [BadMacAddrReason; 3] = [
            BadMacAddrReason::SpansMultipleOuis,
            BadMacAddrReason::ZeroStrideOrCount,
            BadMacAddrReason::MulticastBaseAddr,
        ];
        let mut buf = [0u8; BadMacAddrReason::MAX_SIZE];
        for (variant_id, variant) in TEST_DATA.iter().enumerate() {
            buf[0] = u8::try_from(variant_id).unwrap();
            let decoded = hubpack::deserialize::<BadMacAddrReason>(&buf).unwrap().0;
            assert_eq!(variant, &decoded);
        }
        check_invalid_variants::<BadMacAddrReason>(u8::try_from(TEST_DATA.len()).unwrap());
    }

    #[test]
    fn test_bad_mac_addr_range_encoding_unchanged() {
        const TEST_DATA: BadMacAddrRange = BadMacAddrRange {
            reason: BadMacAddrReason::SpansMultipleOuis,
            base_mac: [0; 6],
            count: 0,
            stride: 0,
        };
        let decoded = hubpack::deserialize::<BadMacAddrRange>(&[0; BadMacAddrRange::MAX_SIZE])
            .unwrap()
            .0;
        assert_eq!(TEST_DATA, decoded);
    }
}
