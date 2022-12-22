// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Decode various transceiver module memory maps and data.

use chrono::NaiveDate;
use std::borrow::Cow;
use std::fmt;
use std::ops::Range;
use thiserror::Error;
use transceiver_messages::mgmt::cmis;
use transceiver_messages::mgmt::sff8636;
pub use transceiver_messages::mgmt::ManagementInterface;
use transceiver_messages::mgmt::MemoryRead;
use transceiver_messages::mgmt::Page;
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

/// The vendor information for a transceiver module.
#[derive(Clone, Debug)]
pub struct VendorInfo {
    /// The SFF-8024 identifier.
    pub identifier: Identifier,
    /// The vendor information.
    pub vendor: Vendor,
}

/// Vendor-specific information about a transceiver module.
#[derive(Clone, Debug)]
pub struct Vendor {
    pub name: [u8; 16],
    pub oui: [u8; 3],
    pub part: [u8; 16],
    pub revision: [u8; 2],
    pub serial: [u8; 16],
    pub date: [u8; 8],
}

fn maybe_ascii(bytes: &[u8]) -> Option<&str> {
    std::str::from_utf8(bytes).map(str::trim_end).ok()
}

impl Vendor {
    /// Return a formatted version of the Organizational Unique Identifier.
    pub fn format_oui(&self) -> String {
        format!(
            "{0:02x}-{1:02x}-{2:02x}",
            self.oui[0], self.oui[1], self.oui[2]
        )
    }

    /// Return the Organizational Unique Identifier.
    pub fn oui(&self) -> &[u8; 3] {
        &self.oui
    }

    /// Return the vendor name as an ASCII string, if possible.
    ///
    /// If the data is malformed, `None` is returned.
    pub fn name(&self) -> Option<&str> {
        maybe_ascii(&self.name)
    }

    /// Lossily convert the name to a string.
    pub fn name_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.name)
    }

    /// Return the vendor part as an ASCII string, if possible.
    ///
    /// If the data is malformed, `None` is returned.
    pub fn part(&self) -> Option<&str> {
        maybe_ascii(&self.part)
    }

    /// Lossily convert the part number to a string.
    pub fn part_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.part)
    }

    /// Return the vendor revision as an ASCII string, if possible.
    ///
    /// If the data is malformed, `None` is returned.
    pub fn revision(&self) -> Option<&str> {
        maybe_ascii(&self.revision)
    }

    /// Lossily convert the revision to a string.
    pub fn revision_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.revision)
    }

    /// Return the vendor serial number as an ASCII string, if possible.
    ///
    /// If the data is malformed, `None` is returned.
    pub fn serial(&self) -> Option<&str> {
        maybe_ascii(&self.serial)
    }

    /// Lossily convert the serial number into a string.
    pub fn serial_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.serial)
    }

    /// Return the date code, if possible.
    ///
    /// If the data is malformed, `None` is returned.
    pub fn date(&self) -> Option<DateCode> {
        DateCode::try_from(self.date.as_slice()).ok()
    }

    /// Lossily convert the date code into a string.
    pub fn date_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.date)
    }

    /// Return the date code as a string, if possible.
    pub fn date_str(&self) -> Option<&str> {
        maybe_ascii(&self.date)
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

                let name = data[NAME].try_into().unwrap();
                let oui = data[OUI].try_into().unwrap();
                let part = data[PART].try_into().unwrap();
                let revision = data[REVISION].try_into().unwrap();
                let serial = data[SERIAL].try_into().unwrap();
                let date = data[DATE].try_into().unwrap();

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
                let name = buf[NAME].try_into().unwrap();
                let oui = buf[OUI].try_into().unwrap();
                let part = buf[PART].try_into().unwrap();
                let revision = buf[REVISION].try_into().unwrap();
                let serial = buf[SERIAL].try_into().unwrap();
                let date = buf[DATE].try_into().unwrap();
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

/// An SFF-8636 or CMIS date code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DateCode {
    pub date: NaiveDate,
    pub lot: Option<String>,
}

impl DateCode {
    /// Serialize self into the SFF-8636 date code format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0; 8];

        let date = self.date.format("%y%m%d").to_string();
        buf[..date.len()].copy_from_slice(date.as_bytes());
        if let Some(lot) = &self.lot {
            buf[6..].copy_from_slice(&lot.as_bytes()[..2]);
        }
        buf
    }
}

impl TryFrom<&[u8]> for DateCode {
    type Error = ();

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.len() < 8 {
            return Err(());
        }

        // The date code is specified in SFF-8636 section 6.2.36 or CMIS
        // 8.3.2.6. It is 8-octets, including:
        //
        // - Two digits for the year, relative to 2000.
        // - Two digits for the month number.
        // - Two digits for the day number.
        // - An optional 2-digit lot code.
        let year = std::str::from_utf8(&buf[..2])
            .map_err(|_| ())?
            .parse::<i32>()
            .map(|x| x + 2000)
            .map_err(|_| ())?;
        let month: u32 = std::str::from_utf8(&buf[2..4])
            .map_err(|_| ())?
            .parse()
            .map_err(|_| ())?;
        let day: u32 = std::str::from_utf8(&buf[4..6])
            .map_err(|_| ())?
            .parse()
            .map_err(|_| ())?;
        let lot = std::str::from_utf8(&buf[6..])
            .map(|s| {
                let s = s.trim();
                if s.is_empty() || s == "\0\0" {
                    None
                } else {
                    Some(s.to_string())
                }
            })
            .map_err(|_| ())?;

        if let Some(date) = NaiveDate::from_ymd_opt(year, month, day) {
            Ok(DateCode { date, lot })
        } else {
            Err(())
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

        assert_prefix(VENDOR_NAME, parsed.name().unwrap());
        assert_eq!(&OUI, parsed.oui());
        assert_prefix(PART, parsed.part().unwrap());
        assert_prefix(REVISION, parsed.revision().unwrap());
        assert_prefix(SERIAL, parsed.serial().unwrap());
        assert_eq!(
            parsed.date().unwrap(),
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
        assert_prefix(VENDOR_NAME, parsed.name().unwrap());
        assert_eq!(&OUI, parsed.oui());
        assert_prefix(PART, parsed.part().unwrap());
        assert_prefix(REVISION, parsed.revision().unwrap());
        assert_prefix(SERIAL, parsed.serial().unwrap());
        assert_eq!(
            parsed.date().unwrap(),
            DateCode {
                date: NaiveDate::from_ymd_opt(2020, 01, 01).unwrap(),
                lot: Some(String::from("00")),
            }
        );
    }

    #[test]
    fn test_date_code_to_bytes() {
        let expected = DateCode {
            date: NaiveDate::from_ymd_opt(2022, 02, 02).unwrap(),
            lot: Some(String::from("ab")),
        };
        let bytes = expected.to_bytes();
        let deser = DateCode::try_from(bytes.as_slice()).unwrap();
        assert_eq!(expected, deser);
    }
}
