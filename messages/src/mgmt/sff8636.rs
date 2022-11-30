// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Types for working with transceivers conforming to the SFF-8636 management
//! interface specification.

use crate::mgmt::ManagementInterface;
use crate::mgmt::MemoryPage;
use crate::Error;
use hubpack::SerializedSize;
use serde::Deserialize;
use serde::Serialize;

/// A single memory page for a transcevier conforming to the SFF-8636 management
/// specification.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, SerializedSize,
)]
pub enum Page {
    Lower,
    Upper(UpperPage),
}

impl Page {
    pub const fn page(&self) -> Option<u8> {
        match self {
            Page::Lower => None,
            Page::Upper(inner) => Some(inner.page()),
        }
    }
}

/// An upper memory page for an SFF-8636 transceiver module.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    Deserialize,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
    SerializedSize,
)]
pub struct UpperPage(u8);

impl UpperPage {
    pub const fn new(page_number: u8) -> Result<Self, Error> {
        if matches!(
        page_number,
        // Static module identity and capabilities.
        0x00 |
        // Deprecated page supporting SFF-8079.
        0x01 |
        // User read/write space.
        0x02 |
        // Static monitor thresholds, advertising and channel controls.
        0x03 |
        // Additional monitored parameters for PAM4 / DWDM modules.
        0x20..=0x21 |
        // Vendor-specific functions.
        0x04..=0x1F |
        // Vendor-specific functions.
        0x80..=0xFF
        ) {
            Ok(Self(page_number))
        } else {
            Err(Error::InvalidPage(page_number))
        }
    }

    pub const fn page(&self) -> u8 {
        self.0
    }
}

impl MemoryPage for Page {
    const INTERFACE: ManagementInterface = ManagementInterface::Sff8636;

    fn max_offset(&self) -> u8 {
        match self {
            Page::Lower => u8::MAX / 2,
            Page::Upper(_) => u8::MAX,
        }
    }

    fn min_offset(&self) -> u8 {
        match self {
            Page::Lower => 0,
            Page::Upper(_) => 128,
        }
    }

    const MAX_READ_SIZE: u8 = 128;

    const MAX_WRITE_SIZE: u8 = 4;
}

#[cfg(test)]
mod tests {
    use super::Error;
    use super::UpperPage;

    #[test]
    fn test_upper_page() {
        assert!(UpperPage::new(0x00).is_ok());
        assert!(UpperPage::new(0xFF).is_ok());
        assert!(matches!(UpperPage::new(0x22), Err(Error::InvalidPage(_))));
    }
}
