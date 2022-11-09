// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Types for working with transceivers conforming to the Common Management
//! Interface Specification (CMIS) version 5.0.

use crate::Error;
use hubpack::SerializedSize;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Serialize, SerializedSize)]
pub struct Page {
    bank: Option<u8>,
    page: u8,
}

impl Page {
    /// Create a new page that does not accept a bank number.
    ///
    /// If the requested page number is invalid, an error is returned. If the
    /// requested page number _does_ accept a bank, an error is returned.
    pub fn new_unbanked(page: u8) -> Result<Self, Error> {
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
    pub fn new_banked(page: u8, bank: u8) -> Result<Self, Error> {
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

    pub fn page(&self) -> u8 {
        self.page
    }

    pub fn bank(&self) -> Option<u8> {
        self.bank
    }
}

// See CMIS 5.0 rev 4.0 Figure 8-1 for details.
fn is_valid_page(page: u8) -> bool {
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
fn page_accepts_bank_number(page: u8) -> bool {
    matches!(page, 0x10..=0x3F | 0x9F | 0xA0..=0xAF)
}

/// The maximum valid bank number supported by CMIS.
pub const MAX_BANK: u8 = 0x03;

#[cfg(test)]
mod tests {
    use super::Error;
    use super::Page;

    #[test]
    fn test_page() {
        assert!(Page::new_unbanked(0x00).is_ok());
        assert!(Page::new_unbanked(0xFF).is_ok());
        assert!(matches!(
            Page::new_banked(0x00, 0x01),
            Err(Error::PageIsUnbanked(_))
        ));
        assert!(matches!(
            Page::new_banked(0x10, 0x10),
            Err(Error::InvalidBank(_))
        ));
        assert!(Page::new_banked(0x10, 0x01).is_ok());
    }
}
