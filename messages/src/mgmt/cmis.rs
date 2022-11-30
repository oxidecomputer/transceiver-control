// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Types for working with transceivers conforming to the Common Management
//! Interface Specification (CMIS) version 5.0.

use crate::mgmt::ManagementInterface;
use crate::mgmt::MemoryPage;
use crate::Error;
use hubpack::SerializedSize;
use serde::Deserialize;
use serde::Serialize;

/// A single page of the memory map of a transceiver module conforming to CMIS.
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

    pub const fn bank(&self) -> Option<u8> {
        match self {
            Page::Lower => None,
            Page::Upper(inner) => inner.bank(),
        }
    }
}

/// A single upper page of a transceiver conforming to CMIS.
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
pub struct UpperPage {
    bank: Option<u8>,
    page: u8,
}

impl UpperPage {
    /// Create a new page that does not accept a bank number.
    ///
    /// If the requested page number is invalid, an error is returned. If the
    /// requested page number _does_ accept a bank, an error is returned.
    pub const fn new_unbanked(page: u8) -> Result<Self, Error> {
        if page_accepts_bank_number(page) {
            return Err(Error::PageIsBanked(page));
        }
        Ok(Self { bank: None, page })
    }

    /// Create a new page that _does_ require a bank number.
    ///
    /// An error is returned if:
    ///
    /// - The requested page number is invalid.
    /// - The requested page number does _not_ accept a bank.
    /// - The requested bank number is invalid.
    pub const fn new_banked(page: u8, bank: u8) -> Result<Self, Error> {
        if !is_valid_page(page) {
            return Err(Error::InvalidPage(page));
        }
        if bank > MAX_BANK {
            return Err(Error::InvalidBank(bank));
        }
        if !page_accepts_bank_number(page) {
            return Err(Error::PageIsUnbanked(page));
        }
        Ok(Self {
            bank: Some(bank),
            page,
        })
    }

    pub const fn page(&self) -> u8 {
        self.page
    }

    pub const fn bank(&self) -> Option<u8> {
        self.bank
    }
}

// See CMIS 5.0 rev 4.0 Figure 8-1 for details.
const fn is_valid_page(page: u8) -> bool {
    matches!(
        page,
        // Identity, advertising, thresholds, laser control.
        0x00..=0x04 |
        // Banked pages.
        0x10..=0x3F | 0x9F | 0xA0..=0xAF |
        // Custom pages.
        0xB0..=0xFF
    )
}

// See CMIS 5.0 rev 4.0 Figure 8-1 for details.
const fn page_accepts_bank_number(page: u8) -> bool {
    matches!(page, 0x10..=0x3F | 0x9F | 0xA0..=0xAF)
}

/// The maximum valid bank number supported by CMIS.
pub const MAX_BANK: u8 = 0x03;

impl MemoryPage for Page {
    const INTERFACE: ManagementInterface = ManagementInterface::Cmis;

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

    const MAX_READ_SIZE: u8 = 8;

    const MAX_WRITE_SIZE: u8 = 8;
}

#[cfg(test)]
mod tests {
    use super::Error;
    use super::UpperPage;

    #[test]
    fn test_page() {
        assert!(UpperPage::new_unbanked(0x00).is_ok());
        assert!(UpperPage::new_unbanked(0xFF).is_ok());
        assert!(matches!(
            UpperPage::new_banked(0x00, 0x01),
            Err(Error::PageIsUnbanked(_))
        ));
        assert!(matches!(
            UpperPage::new_banked(0x10, 0x10),
            Err(Error::InvalidBank(_))
        ));
        assert!(UpperPage::new_banked(0x10, 0x01).is_ok());
    }
}
