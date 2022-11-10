// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Types for working with transceivers conforming to the SFF-8636 management
//! interface specification.

use crate::Error;
use hubpack::SerializedSize;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Serialize, SerializedSize)]
pub struct Page(u8);

impl Page {
    pub fn new(page_number: u8) -> Result<Self, Error> {
        if matches!(
        page_number,
        // Static module identity and capabilities.
        0x00 |
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

    pub fn page(&self) -> u8 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Error;
    use super::Page;

    #[test]
    fn test_page() {
        assert!(Page::new(0x00).is_ok());
        assert!(Page::new(0xFF).is_ok());
        assert!(matches!(Page::new(0x22), Err(Error::InvalidPage(_))));
    }
}
