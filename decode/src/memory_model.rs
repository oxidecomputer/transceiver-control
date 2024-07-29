// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Decoding of transceiver module memory models.

use crate::Error;
use crate::Identifier;
use crate::ParseFromModule;
use std::fmt;
use transceiver_messages::mgmt::cmis;
use transceiver_messages::mgmt::sff8636;
use transceiver_messages::mgmt::MemoryRead;
use transceiver_messages::mgmt::Page;

/// Description of the memory model of a transceiver memory map.
///
/// Modules all include a 256-byte memory map, divided into lower and
/// upper pages. The upper page is indexed by a page number. If the module
/// supports only a single upper page (index 0), then the module is referred to
/// as "flat memory". Otherwise, different upper pages may be swapped in at the
/// request of the fixed-side device, allowing for much more data than fits in
/// the fixed 256-byte map.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemoryModel {
    /// The memory map is flat (only the lower page and upper page 0).
    Flat,
    /// The memory map supports the listed pages.
    Paged(Vec<Page>),
}

impl fmt::Display for MemoryModel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MemoryModel::Flat => write!(f, "Flat"),
            MemoryModel::Paged(pages) => write!(
                f,
                "Paged [{}]",
                pages
                    .iter()
                    .map(|page| {
                        // Safety: This is an upper page, since we only build
                        // this type by parsing from the below implementation of
                        // `ParseFromModule`.
                        let page_index = page.page().unwrap();

                        // Possibly generate a `/{bank_index}` suffix.
                        let bank_suffix = if let Some(bank) = page.bank() {
                            format!("/{bank}")
                        } else {
                            String::new()
                        };

                        format!("0x{page_index:02x}{bank_suffix}")
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        }
    }
}

impl ParseFromModule for MemoryModel {
    fn reads(id: Identifier) -> Result<Vec<MemoryRead>, Error> {
        match id {
            Identifier::QsfpPlusSff8636 | Identifier::Qsfp28 => {
                // See SFF-8636 rev 2.10a Table 6-2 and Table 6-21.
                //
                // The first byte is the status word, bit 2 of which indicates
                // if flat or paged memory. The second has several bits which
                // indicate the supported pages.
                let page = sff8636::Page::Lower;
                let status = MemoryRead::new(page, 2, 1).unwrap();
                let page = sff8636::Page::Upper(sff8636::UpperPage::new(0).unwrap());
                let advertised_pages = MemoryRead::new(page, 195, 1).unwrap();
                Ok(vec![status, advertised_pages])
            }
            Identifier::QsfpPlusCmis | Identifier::QsfpDD => {
                // See CMIS rev 5.0 Table 8-4 and Table 8-40.
                //
                // Byte 2 bit 7 indicates whether memory is flat or paged. If
                // paged, the module is required to support pages 0x00-0x02 and
                // 0x10-0x11. Additional supported pages are listed in the bits
                // of byte 142.
                let page = cmis::Page::Lower;
                let characteristics = MemoryRead::new(page, 2, 1).unwrap();

                let page = cmis::Page::Upper(cmis::UpperPage::new_unbanked(1).unwrap());
                let advertised_pages = MemoryRead::new(page, 142, 1).unwrap();

                // TODO-completeness: Read page 0x01 byte 155, where bit 6
                // indicates support for pages 0x04 and 0x12, laser tunables.

                // TODO-completeness: Read page 0x01 byte 145, where bit 3
                // indicates support for page 0x15, timing characteristics.

                // TODO-completeness: Byte 142 bit 6 indicates support for VDM,
                // in pages, 0x20-0x2F. However, only a subset of these pages
                // may actually be supported. That's described in page 0x2f,
                // byte 128 bit 1, see CMIS Table 8-128. Implement this read as
                // well.

                Ok(vec![characteristics, advertised_pages])
            }
            _ => Err(Error::UnsupportedIdentifier(id)),
        }
    }

    fn parse<'a>(id: Identifier, mut reads: impl Iterator<Item = &'a [u8]>) -> Result<Self, Error> {
        match id {
            Identifier::QsfpPlusSff8636 | Identifier::Qsfp28 => {
                let status = reads
                    .next()
                    .and_then(|bytes| bytes.first())
                    .ok_or(Error::ParseFailed)?;
                if status & (1 << 2) == 0 {
                    let advertised_pages = reads
                        .next()
                        .and_then(|bytes| bytes.first())
                        .ok_or(Error::ParseFailed)?;

                    // These pages are required. The others are described by
                    // bits in the `advertised_pages` byte.
                    let mut pages = vec![
                        Page::from(sff8636::UpperPage::new(0x00).unwrap()),
                        Page::from(sff8636::UpperPage::new(0x03).unwrap()),
                    ];
                    if (advertised_pages & (1 << 7)) != 0 {
                        pages.push(Page::from(sff8636::UpperPage::new(0x02).unwrap()));
                    }
                    if (advertised_pages & (1 << 6)) != 0 {
                        pages.push(Page::from(sff8636::UpperPage::new(0x01).unwrap()));
                    }
                    if (advertised_pages & (1 << 0)) != 0 {
                        pages.push(Page::from(sff8636::UpperPage::new(0x20).unwrap()));
                        pages.push(Page::from(sff8636::UpperPage::new(0x21).unwrap()));
                    }
                    pages.sort();
                    Ok(MemoryModel::Paged(pages))
                } else {
                    Ok(MemoryModel::Flat)
                }
            }
            Identifier::QsfpPlusCmis | Identifier::QsfpDD => {
                let status = reads
                    .next()
                    .and_then(|bytes| bytes.first())
                    .ok_or(Error::ParseFailed)?;
                if status & (1 << 7) == 0 {
                    let advertised_pages = reads
                        .next()
                        .and_then(|bytes| bytes.first())
                        .ok_or(Error::ParseFailed)?;

                    // These pages are required, and are not banked.
                    let mut pages: Vec<_> = [0x00, 0x01, 0x02]
                        .into_iter()
                        .map(|page| Page::from(cmis::UpperPage::new_unbanked(page).unwrap()))
                        .collect();

                    // These pages are also required, but the banks that they
                    // supprt are described in the advertised_pages byte. We
                    // construct a single page for each, with the maximum bank
                    // supported.
                    let max_bank = match advertised_pages & 0b11 {
                        0b00 => 0,
                        0b01 => 1,
                        0b10 => 3,
                        _ => unreachable!("Reserved value in the CMIS spec"),
                    };
                    for page in [0x10, 0x11] {
                        pages.push(Page::from(
                            cmis::UpperPage::new_banked(page, max_bank).unwrap(),
                        ));
                    }

                    if (advertised_pages & (1 << 2)) != 0 {
                        pages.push(Page::from(cmis::UpperPage::new_unbanked(0x03).unwrap()));
                    }

                    if (advertised_pages & (1 << 5)) != 0 {
                        for page in [0x13, 0x14] {
                            pages.push(Page::from(
                                cmis::UpperPage::new_banked(page, max_bank).unwrap(),
                            ));
                        }
                    }

                    // TODO-completeness: Handle other reads listed above.

                    pages.sort();
                    Ok(MemoryModel::Paged(pages))
                } else {
                    Ok(MemoryModel::Flat)
                }
            }
            _ => Err(Error::UnsupportedIdentifier(id)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Identifier;
    use super::MemoryModel;
    use super::ParseFromModule;

    #[test]
    fn test_parse_memory_model_from_module_sff8636() {
        let id = Identifier::Qsfp28;

        // Paged, supporting pages 0x02, 0x01, and _not_ 0x20-0x21.
        let status = vec![0b000];
        let pages = vec![(1 << 7) | (1 << 6)];
        const EXPECTED_PAGES: &[u8] = &[0x00, 0x01, 0x02, 0x03];

        let parsed =
            MemoryModel::parse(id, vec![status.as_slice(), pages.as_slice()].into_iter()).unwrap();
        match parsed {
            MemoryModel::Paged(pages) => {
                assert!(pages
                    .iter()
                    .zip(EXPECTED_PAGES.iter())
                    .all(|(page, expected_page)| page.page() == Some(*expected_page)));
            }
            _ => panic!("Expected a paged memory model"),
        }

        // Flat
        let status = vec![0b100];
        let parsed = MemoryModel::parse(id, std::iter::once(status.as_slice())).unwrap();
        assert_eq!(parsed, MemoryModel::Flat);
    }

    #[test]
    fn test_parse_memory_model_from_module_cmis() {
        let id = Identifier::QsfpPlusCmis;

        // Paged
        let status = vec![0];
        let advertised_pages = vec![0b00];
        let parsed = MemoryModel::parse(
            id,
            [status.as_slice(), advertised_pages.as_slice()].into_iter(),
        )
        .unwrap();
        const EXPECTED_PAGES: &[u8] = &[0x00, 0x01, 0x02, 0x10, 0x11];
        match parsed {
            MemoryModel::Paged(pages) => {
                assert!(pages
                    .iter()
                    .zip(EXPECTED_PAGES.iter())
                    .all(|(page, expected_page)| page.page() == Some(*expected_page)));
            }
            _ => panic!("Expected a paged memory model"),
        }

        // Flat
        let status = vec![1 << 7];
        let parsed = MemoryModel::parse(id, std::iter::once(status.as_slice())).unwrap();
        assert_eq!(parsed, MemoryModel::Flat);
    }
}
