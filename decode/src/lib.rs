// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Decode various transceiver module memory maps and data.

use chrono::NaiveDate;
use std::fmt;
use std::ops::Range;
use thiserror::Error;
use transceiver_messages::mgmt::cmis;
use transceiver_messages::mgmt::sff8636;
use transceiver_messages::mgmt::ManagementInterface;
use transceiver_messages::mgmt::MemoryRead;
use transceiver_messages::Error as MessageError;

/// An error related to decoding a transceiver memory map.
#[derive(Clone, Copy, Debug, Error)]
pub enum Error {
    #[error("Unsupported SFF-8024 Identifier: '{0}'")]
    UnsupportedIdentifier(Identifier),

    #[error("Management or messaging error")]
    Management(#[from] MessageError),

    #[error("Memory map parsing failed")]
    ParseFailed,
}

/// The SFF-8024 identifier for a transceiver module.
///
/// This identifier is used as the main description of the kind of module, and
/// indicates the spec that the it should conform to. It is required to
/// interpret the remainder of the memory map.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
#[repr(u8)]
pub enum Identifier {
    Unknown,
    Gbic,
    Soldered,
    Sfp,
    Xbi,
    Xenpak,
    Xfp,
    Xff,
    XffE,
    Xpak,
    X2,
    DwdmSfp,
    Qsfp,
    QsfpPlusSff8636,
    Cxp,
    ShieldedMultiLane4,
    ShieldedMultiLane8,
    Qsfp28,
    Cxp2,
    Cdfp,
    ShieldedMultiLane4Fanout,
    ShieldedMultiLane8Fanout,
    Cdfp3,
    MicroQsfp,
    QsfpDD,
    Qsfp8,
    SfpDD,
    Dsfp,
    X4MultiLink,
    X8MiniLink,
    QsfpPlusCmis,
    Unsupported(u8),
    Reserved(u8),
    VendorSpecific(u8),
}

impl Identifier {
    pub const fn management_interface(&self) -> Result<ManagementInterface, Error> {
        use Identifier::*;
        match self {
            QsfpPlusSff8636 | Qsfp28 => Ok(ManagementInterface::Sff8636),
            QsfpPlusCmis | QsfpDD => Ok(ManagementInterface::Cmis),
            _ => Err(Error::UnsupportedIdentifier(*self)),
        }
    }
}

impl From<u8> for Identifier {
    fn from(x: u8) -> Self {
        use Identifier::*;
        match x {
            0x00 => Unknown,
            0x01 => Gbic,
            0x02 => Soldered,
            0x03 => Sfp,
            0x04 => Xbi,
            0x05 => Xenpak,
            0x06 => Xfp,
            0x07 => Xff,
            0x08 => XffE,
            0x09 => Xpak,
            0x0a => X2,
            0x0b => DwdmSfp,
            0x0c => Qsfp,
            0x0d => QsfpPlusSff8636,
            0x0e => Cxp,
            0x0f => ShieldedMultiLane4,
            0x10 => ShieldedMultiLane8,
            0x11 => Qsfp28,
            0x12 => Cxp2,
            0x13 => Cdfp,
            0x14 => ShieldedMultiLane4Fanout,
            0x15 => ShieldedMultiLane8Fanout,
            0x16 => Cdfp3,
            0x17 => MicroQsfp,
            0x18 => QsfpDD,
            0x19 => Qsfp8,
            0x1a => SfpDD,
            0x1b => Dsfp,
            0x1c => X4MultiLink,
            0x1d => X8MiniLink,
            0x1e => QsfpPlusCmis,
            0x21..=0x7f => Reserved(x),
            0x80.. => VendorSpecific(x),
            _ => Unsupported(x),
        }
    }
}

impl From<Identifier> for u8 {
    fn from(id: Identifier) -> Self {
        use Identifier::*;
        match id {
            Unknown => 0x00,
            Gbic => 0x01,
            Soldered => 0x02,
            Sfp => 0x03,
            Xbi => 0x04,
            Xenpak => 0x05,
            Xfp => 0x06,
            Xff => 0x07,
            XffE => 0x08,
            Xpak => 0x09,
            X2 => 0x0a,
            DwdmSfp => 0x0b,
            Qsfp => 0x0c,
            QsfpPlusSff8636 => 0x0d,
            Cxp => 0x0e,
            ShieldedMultiLane4 => 0x0f,
            ShieldedMultiLane8 => 0x10,
            Qsfp28 => 0x11,
            Cxp2 => 0x12,
            Cdfp => 0x13,
            ShieldedMultiLane4Fanout => 0x14,
            ShieldedMultiLane8Fanout => 0x15,
            Cdfp3 => 0x16,
            MicroQsfp => 0x17,
            QsfpDD => 0x18,
            Qsfp8 => 0x19,
            SfpDD => 0x1a,
            Dsfp => 0x1b,
            X4MultiLink => 0x1c,
            X8MiniLink => 0x1d,
            QsfpPlusCmis => 0x1e,
            Reserved(x) | VendorSpecific(x) | Unsupported(x) => x,
        }
    }
}

impl core::fmt::Display for Identifier {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use Identifier::*;
        write!(
            f,
            "{}",
            match self {
                Unknown => "Unknown or unspecified",
                Gbic => "GBIC",
                Soldered => "Module/connector soldered to motherboard",
                Sfp => "SFP/SFP+/SFP28",
                Xbi => "XBI",
                Xenpak => "XENPAK",
                Xfp => "XFP",
                Xff => "XFF",
                XffE => "XFP-E",
                Xpak => "XPAK",
                X2 => "X2",
                DwdmSfp => "DWDM-SFP/SFP+",
                Qsfp => "QSFP",
                QsfpPlusSff8636 => "QSFP+ or later with SFF-8636 management interface",
                Cxp => "CXP or later",
                ShieldedMultiLane4 => "Shielded mini multi-lane 4X",
                ShieldedMultiLane8 => "Shielded mini multi-lane 8X",
                Qsfp28 => "QSFP28 or later with SFF-8636 management interface",
                Cxp2 => "CXP2",
                Cdfp => "CDFP (Style 1 or 2)",
                ShieldedMultiLane4Fanout => "Shielded mini multi-lane 4X fanout",
                ShieldedMultiLane8Fanout => "Shielded mini multi-lane 8X fanout",
                Cdfp3 => "CDFP (Style 3)",
                MicroQsfp => "MicroQSFP",
                QsfpDD => "QSFP-DD Double Density 8X Pluggable Transceiver",
                Qsfp8 => "QSFP 8X Pluggable Transceiver",
                SfpDD => "SFP-DD 2X Double Density Pluggable Transceiver",
                Dsfp => "DSFP Dual Small Form Factor Pluggable Transceiver",
                X4MultiLink => "x4 MiniLink/OcuLink",
                X8MiniLink => "x8 MiniLink",
                QsfpPlusCmis => "QSFP+ or later with Common Management Interface Specification",
                Reserved(_) => "Reserved",
                VendorSpecific(_) => "Vendor Specific",
                Unsupported(_) => "Unsupported",
            }
        )
    }
}

/// The identifying information for a transceiver module.
#[derive(Clone, Debug)]
pub struct Identity {
    /// The SFF-8024 identifier.
    pub identifier: Identifier,
    /// The vendor information.
    pub vendor: Vendor,
}

/// Vendor-specific information about a transceiver module.
#[derive(Clone)]
pub struct Vendor {
    pub name: String,
    pub oui: [u8; 3],
    pub part: String,
    pub revision: String,
    pub serial: String,
    pub date: DateCode,
}

impl Vendor {
    /// Return a formatted version of the Organizational Unique Identifier.
    pub fn format_oui(&self) -> String {
        format!(
            "{0:02x}-{1:02x}-{2:02x}",
            self.oui[0], self.oui[1], self.oui[2]
        )
    }
}

impl fmt::Display for Vendor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", &self.name, &self.part)
    }
}

impl fmt::Debug for Vendor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Vendor")
            .field("name", &self.name)
            .field("oui", &self.format_oui())
            .field("part", &self.part)
            .field("revision", &self.revision)
            .field("serial", &self.serial)
            .field("date", &self.date)
            .finish()
    }
}

/// A trait used to read and parse data from a transceiver memory map.
///
/// There are many kinds of transceivers, and although they often include the
/// same data, the location of that data in the memory map can be different.
/// This trait provides a way to issue a set of reads from a module's map, and
/// parse the result into a type.
pub trait ParseFromModule: Sized {
    /// The set of memory reads required to parse the data.
    fn reads(id: Identifier) -> Result<Vec<MemoryRead>, Error>;

    /// Parse the result of the above reads into `Self`.
    fn parse<'a>(id: Identifier, reads: impl Iterator<Item = &'a [u8]>) -> Result<Self, Error>;
}

impl ParseFromModule for Vendor {
    fn reads(id: Identifier) -> Result<Vec<MemoryRead>, Error> {
        match id {
            Identifier::QsfpPlusSff8636 | Identifier::Qsfp28 => {
                // See SFF-8636 rev 2.10a Table 6-14.
                //
                // The bytes for the various vendor-specific data is encoded
                // between offsets 148 and 220, with a few other bits
                // interspersed. However, the spec supports reading up to 128
                // bytes at a time, so we'll read the whole page and parse out
                // only those portions we care about below.
                let page = sff8636::Page::Upper(sff8636::UpperPage::new(0)?);
                const START: u8 = 148;
                const END: u8 = 220;
                Ok(vec![MemoryRead::new(page, START, END - START)?])
            }
            Identifier::QsfpPlusCmis | Identifier::QsfpDD => {
                // See CMIS rev 5.0 Table 8-24.
                //
                // In contrast to SFF-8636, these bytes are all contiguous.
                // However, the spec mandates that reads are of at most 8 bytes
                // at a time, so we need to split the data into many reads.
                let page = cmis::Page::Upper(cmis::UpperPage::new_unbanked(0)?);
                const START: u8 = 129;
                const END: u8 = 190;

                // We'll explicitly read into 8-byte chunks, and deal with these
                // boundaries below in the parsing method.
                const LEN: u8 = 8;
                (START..END)
                    .step_by(LEN.into())
                    .map(|offset| MemoryRead::new(page, offset, LEN).map_err(Error::from))
                    .collect()
            }
            _ => Err(Error::UnsupportedIdentifier(id)),
        }
    }

    fn parse<'a>(id: Identifier, mut reads: impl Iterator<Item = &'a [u8]>) -> Result<Self, Error> {
        match id {
            Identifier::QsfpPlusSff8636 | Identifier::Qsfp28 => {
                // We start our single contiguous read at `READ_START`. The
                // byte addresses listed in SFF-8636 Table 6-14 are all
                // absolute, relative to the start of the memory map. This
                // provides a clear way to shift those (offset, len) values to
                // the start of the read.
                const READ_START: usize = 148;
                const fn shift_range(start: usize, len: usize) -> Range<usize> {
                    (start - READ_START)..(start - READ_START + len)
                }
                const NAME: Range<usize> = shift_range(148, 16);
                const OUI: Range<usize> = shift_range(165, 3);
                const PART: Range<usize> = shift_range(168, 16);
                const REVISION: Range<usize> = shift_range(184, 2);
                const SERIAL: Range<usize> = shift_range(196, 16);
                const DATE: Range<usize> = shift_range(212, 8);

                // Make sure we have at least one read.
                let data = match reads.next() {
                    None => return Err(Error::ParseFailed),
                    Some(d) => d,
                };

                let name = ascii_to_string(&data[NAME]);
                let oui = data[OUI].try_into().unwrap();
                let part = ascii_to_string(&data[PART]);
                let revision = ascii_to_string(&data[REVISION]);
                let serial = ascii_to_string(&data[SERIAL]);
                let date = DateCode::from(&data[DATE]);

                Ok(Self {
                    name,
                    oui,
                    part,
                    revision,
                    serial,
                    date,
                })
            }
            Identifier::QsfpPlusCmis | Identifier::QsfpDD => {
                // The byte offsets in the `reads` data, offset by first byte.
                const NAME: Range<usize> = 0..16; // 16 bytes
                const OUI: Range<usize> = 16..19; // 3 bytes
                const PART: Range<usize> = 19..35; // 16 bytes
                const REVISION: Range<usize> = 35..37; // 2 bytes
                const SERIAL: Range<usize> = 37..53; // 16 bytes
                const DATE: Range<usize> = 53..61; // 8 bytes

                // We've read 8-byte chunks of data, which are logically
                // contiguous. For simplicity, we'll collect the entire buffer
                // into a vec, and then split off chunks. This is easier than
                // trying to create strings out of multiple chunks, mostly due
                // to how the checked methods for converting bytes to strings
                // work.
                let buf: Vec<_> = reads.flat_map(|b| b.iter().copied()).collect();
                let name = ascii_to_string(&buf[NAME]);
                let oui = buf[OUI].try_into().unwrap();
                let part = ascii_to_string(&buf[PART]);
                let revision = ascii_to_string(&buf[REVISION]);
                let serial = ascii_to_string(&buf[SERIAL]);
                let date = DateCode::from(&buf[DATE]);
                Ok(Self {
                    name,
                    oui,
                    part,
                    revision,
                    serial,
                    date,
                })
            }
            _ => Err(Error::UnsupportedIdentifier(id)),
        }
    }
}

fn ascii_to_string(buf: &[u8]) -> String {
    std::str::from_utf8(buf).unwrap().trim_end().to_string()
}

/// An SFF-8636 or CMIS date code.
#[derive(Clone, Debug, PartialEq)]
pub struct DateCode {
    pub date: NaiveDate,
    pub lot: Option<String>,
}

impl From<&[u8]> for DateCode {
    fn from(buf: &[u8]) -> Self {
        assert!(buf.len() >= 8);

        // The date code is specified in SFF-8636 section 6.2.36 or CMIS
        // 8.3.2.6. It is 8-octets, including:
        //
        // - Two digits for the year, relative to 2000.
        // - Two digits for the month number.
        // - Two digits for the day number.
        // - An optional 2-digit lot code.
        let year = std::str::from_utf8(&buf[..2])
            .unwrap()
            .parse::<i32>()
            .unwrap()
            + 2000;
        let month: u32 = std::str::from_utf8(&buf[2..4]).unwrap().parse().unwrap();
        let day: u32 = std::str::from_utf8(&buf[4..6]).unwrap().parse().unwrap();
        let lot = std::str::from_utf8(&buf[6..])
            .map(|x| {
                let x = x.trim_end();
                if x.is_empty() {
                    None
                } else {
                    Some(x.to_string())
                }
            })
            .unwrap_or(None);

        DateCode {
            date: NaiveDate::from_ymd_opt(year, month, day).unwrap(),
            lot,
        }
    }
}

impl fmt::Display for DateCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        const FMT: &str = "%d %b %Y";
        if let Some(lot) = &self.lot {
            write!(f, "{} (Lot {})", self.date.format(FMT), lot,)
        } else {
            write!(f, "{}", self.date.format(FMT))
        }
    }
}

/// Description of the memory model of a transceiver memory map.
///
/// Modules all include a 256-byte memory map, divided into lower and
/// upper pages. The upper page is indexed by a page number. If the module
/// supports only a single upper page (index 0), then the module is referred to
/// as "flat memory". Otherwise, different upper pages may be swapped in at the
/// request of the fixed-side device, allowing for much more data than fits in
/// the fixed 256-byte map.
#[derive(Clone, Debug, PartialEq)]
pub enum MemoryModel {
    /// The memory map is flat (only the lower page and upper page 0).
    Flat,
    /// The memory map supports the listed pages.
    Paged(Vec<u8>),
}

impl fmt::Display for MemoryModel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MemoryModel::Flat => write!(f, "Flat"),
            MemoryModel::Paged(pages) => write!(
                f,
                "Paged [{}]",
                pages
                    .into_iter()
                    .map(|page| format!("0x{page:02x}"))
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
                let status = MemoryRead::new(page, 2, 1)?;
                let page = sff8636::Page::Upper(sff8636::UpperPage::new(0)?);
                let advertised_pages = MemoryRead::new(page, 195, 1)?;
                Ok(vec![status, advertised_pages])
            }
            Identifier::QsfpPlusCmis | Identifier::QsfpDD => {
                // See CMIS rev 5.0 Table 8-4.
                //
                // We only need to read the single word / bit indicating whether
                // memory is paged or flat. If it's paged, it is required to
                // support a fixed set of pages.
                let page = cmis::Page::Lower;
                Ok(vec![MemoryRead::new(page, 2, 1)?])
            }
            _ => Err(Error::UnsupportedIdentifier(id)),
        }
    }

    fn parse<'a>(id: Identifier, mut reads: impl Iterator<Item = &'a [u8]>) -> Result<Self, Error> {
        match id {
            Identifier::QsfpPlusSff8636 | Identifier::Qsfp28 => {
                let status = reads
                    .next()
                    .map(|bytes| bytes.first())
                    .flatten()
                    .ok_or_else(|| Error::ParseFailed)?;
                if status & (1 << 2) == 0 {
                    let advertised_pages = reads
                        .next()
                        .map(|bytes| bytes.first())
                        .flatten()
                        .ok_or_else(|| Error::ParseFailed)?;

                    // These pages are required. The others are described by
                    // bits in the `advertised_pages` byte.
                    let mut pages = vec![0x00, 0x03];
                    if (advertised_pages & (1 << 7)) != 0 {
                        pages.push(0x02);
                    }
                    if (advertised_pages & (1 << 6)) != 0 {
                        pages.push(0x01);
                    }
                    if (advertised_pages & (1 << 0)) != 0 {
                        pages.push(0x20);
                        pages.push(0x21);
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
                    .map(|bytes| bytes.first())
                    .flatten()
                    .ok_or_else(|| Error::ParseFailed)?;
                if status & (1 << 7) == 0 {
                    Ok(MemoryModel::Paged(vec![0x00, 0x01, 0x02, 0x10, 0x11]))
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
    use super::DateCode;
    use super::Identifier;
    use super::MemoryModel;
    use super::NaiveDate;
    use super::ParseFromModule;
    use super::Vendor;

    #[test]
    fn test_parse_memory_model_from_module_sff8636() {
        let id = Identifier::Qsfp28;

        // Paged, supporting pages 0x02, 0x01, and _not_ 0x20-0x21.
        let status = vec![0b000];
        let pages = vec![(1 << 7) | (1 << 6)];
        const EXPECTED_PAGES: &[u8] = &[0x00, 0x01, 0x02, 0x03];

        let parsed =
            MemoryModel::parse(id, vec![status.as_slice(), pages.as_slice()].into_iter()).unwrap();
        assert_eq!(parsed, MemoryModel::Paged(EXPECTED_PAGES.to_vec()));

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
        let parsed = MemoryModel::parse(id, std::iter::once(status.as_slice())).unwrap();
        const EXPECTED_PAGES: &[u8] = &[0x00, 0x01, 0x02, 0x10, 0x11];
        assert_eq!(parsed, MemoryModel::Paged(EXPECTED_PAGES.to_vec()));

        // Paged
        let status = vec![1 << 7];
        let parsed = MemoryModel::parse(id, std::iter::once(status.as_slice())).unwrap();
        assert_eq!(parsed, MemoryModel::Flat);
    }

    // Assert that `substring` is a prefix of `full`.
    fn assert_prefix(full: &[u8], substring: &str) {
        assert!(std::str::from_utf8(full).unwrap().starts_with(substring))
    }

    #[test]
    fn test_parse_vendor_from_module_sff8636() {
        let id = Identifier::Qsfp28;
        let mut data = vec![0; 128];

        // Expected data.
        const VENDOR_NAME: &[u8] = b"some vendor     "; // 16 bytes, space padded.
        const OUI: [u8; 3] = [1, 2, 3];
        const PART: &[u8] = b"some part num   ";
        const REVISION: &[u8] = b"re";
        const SERIAL: &[u8] = b"some serial     ";
        const DATE: &[u8] = b"200101  ";

        // See SFF-8636 Table 6-14 for specifics.
        //
        // Briefly, copy the expected data into the correct byte locations, and
        // assert we get it back when parsing.
        let mut start = 0;
        data[start..start + VENDOR_NAME.len()].copy_from_slice(VENDOR_NAME);
        start += VENDOR_NAME.len() + 1; // 1 for Extended Module

        data[start..start + OUI.len()].copy_from_slice(&OUI);
        start += OUI.len();

        data[start..start + PART.len()].copy_from_slice(PART);
        start += PART.len();

        data[start..start + REVISION.len()].copy_from_slice(REVISION);
        start += REVISION.len() + 2 + 2 + 1 + 1 + 1 + 3;

        data[start..start + SERIAL.len()].copy_from_slice(SERIAL);
        start += SERIAL.len();

        data[start..start + DATE.len()].copy_from_slice(DATE);

        let parsed = Vendor::parse(id, std::iter::once(data.as_slice())).unwrap();

        assert_prefix(VENDOR_NAME, &parsed.name);
        assert_eq!(OUI, parsed.oui);
        assert_prefix(PART, &parsed.part);
        assert_prefix(REVISION, &parsed.revision);
        assert_prefix(SERIAL, &parsed.serial);
        assert_eq!(
            parsed.date,
            DateCode {
                date: NaiveDate::from_ymd_opt(2020, 01, 01).unwrap(),
                lot: None,
            }
        );
    }

    #[test]
    fn test_parse_vendor_from_module_cmis() {
        let id = Identifier::QsfpPlusCmis;

        // Expected data.
        const VENDOR_NAME: &[u8] = b"some vendor     "; // 16 bytes, space padded.
        const OUI: [u8; 3] = [1, 2, 3];
        const PART: &[u8] = b"some part num   ";
        const REVISION: &[u8] = b"re";
        const SERIAL: &[u8] = b"some serial     ";
        const DATE: &[u8] = b"20010100";

        // See CMIS Table 8-24.
        //
        // Data is contiguous, but our reads are limited to 8 bytes. Concatenate
        // the data, then take into 8-byte chunks to simulate this process.
        let mut all_data = Vec::new();
        all_data.extend_from_slice(VENDOR_NAME);
        all_data.extend_from_slice(&OUI);
        all_data.extend_from_slice(PART);
        all_data.extend_from_slice(REVISION);
        all_data.extend_from_slice(SERIAL);
        all_data.extend_from_slice(DATE);
        let reads = all_data.chunks(8);

        let parsed = Vendor::parse(id, reads).unwrap();
        assert_prefix(VENDOR_NAME, &parsed.name);
        assert_eq!(OUI, parsed.oui);
        assert_prefix(PART, &parsed.part);
        assert_prefix(REVISION, &parsed.revision);
        assert_prefix(SERIAL, &parsed.serial);
        assert_eq!(
            parsed.date,
            DateCode {
                date: NaiveDate::from_ymd_opt(2020, 01, 01).unwrap(),
                lot: Some(String::from("00")),
            }
        );
    }
}
