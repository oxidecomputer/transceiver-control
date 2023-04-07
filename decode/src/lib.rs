// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Decode various transceiver module memory maps and data.

use std::fmt;
use std::ops::Range;
use thiserror::Error;
use transceiver_messages::mgmt::cmis;
use transceiver_messages::mgmt::sff8636;
use transceiver_messages::mgmt::Error as MgmtError;
pub use transceiver_messages::mgmt::ManagementInterface;
use transceiver_messages::mgmt::MemoryRead;
use transceiver_messages::mgmt::Page;

/// An error related to decoding a transceiver memory map.
#[derive(Clone, Copy, Debug, PartialEq, Error)]
pub enum Error {
    #[error("Unsupported SFF-8024 Identifier: '{0}'")]
    UnsupportedIdentifier(Identifier),

    #[error("Management error")]
    Management(#[from] MgmtError),

    #[error("Memory map parsing failed")]
    ParseFailed,

    #[error("Invalid OUI")]
    InvalidOui,
}

/// The SFF-8024 identifier for a transceiver module.
///
/// This identifier is used as the main description of the kind of module, and
/// indicates the spec that the it should conform to. It is required to
/// interpret the remainder of the memory map.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
#[repr(u8)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)
)]
#[cfg_attr(any(feature = "api-traits", test), serde(rename_all = "snake_case"))]
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

/// An Organization Unique Identifier.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema, PartialEq)
)]
#[cfg_attr(
    any(feature = "api-traits", test),
    serde(try_from = "String", into = "String")
)]
pub struct Oui(pub [u8; 3]);

#[cfg(any(feature = "api-traits", test))]
impl std::str::FromStr for Oui {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut out = [0u8; 3];

        // 3 octets, formatted as hex, with `-` separating them.
        if s.len() > (3 * 2 + 2) {
            return Err(Error::InvalidOui);
        }
        let mut i = 0;
        for part in s.splitn(out.len(), '-') {
            let Ok(octet) = u8::from_str_radix(part, 16) else {
                return Err(Error::InvalidOui);
            };
            out[i] = octet;
            i += 1;
        }
        if i != out.len() {
            return Err(Error::InvalidOui);
        }
        Ok(Oui(out))
    }
}

#[cfg(any(feature = "api-traits", test))]
impl std::convert::TryFrom<String> for Oui {
    type Error = <Self as std::str::FromStr>::Err;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_str().parse()
    }
}

#[cfg(any(feature = "api-traits", test))]
impl From<Oui> for String {
    fn from(o: Oui) -> String {
        format!("{o}")
    }
}

impl fmt::Display for Oui {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:02x}-{:02x}-{:02x}", self.0[0], self.0[1], self.0[2])
    }
}

/// The vendor information for a transceiver module.
#[derive(Clone, Debug)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema, PartialEq)
)]
pub struct VendorInfo {
    /// The SFF-8024 identifier.
    pub identifier: Identifier,
    /// The vendor information.
    pub vendor: Vendor,
}

/// Vendor-specific information about a transceiver module.
#[derive(Clone)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema, PartialEq)
)]
pub struct Vendor {
    pub name: String,
    pub oui: Oui,
    pub part: String,
    pub revision: String,
    pub serial: String,
    pub date: Option<String>,
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
            .field("oui", &format!("{}", self.oui))
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

impl ParseFromModule for VendorInfo {
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
                let oui = Oui(data[OUI].try_into().unwrap());
                let part = ascii_to_string(&data[PART]);
                let revision = ascii_to_string(&data[REVISION]);
                let serial = ascii_to_string(&data[SERIAL]);
                let date = std::str::from_utf8(&data[DATE]).ok().map(String::from);

                let vendor = Vendor {
                    name,
                    oui,
                    part,
                    revision,
                    serial,
                    date,
                };
                Ok(VendorInfo {
                    identifier: id,
                    vendor,
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
                let oui = Oui(buf[OUI].try_into().unwrap());
                let part = ascii_to_string(&buf[PART]);
                let revision = ascii_to_string(&buf[REVISION]);
                let serial = ascii_to_string(&buf[SERIAL]);
                let date = std::str::from_utf8(&buf[DATE]).ok().map(String::from);
                let vendor = Vendor {
                    name,
                    oui,
                    part,
                    revision,
                    serial,
                    date,
                };
                Ok(Self {
                    identifier: id,
                    vendor,
                })
            }
            _ => Err(Error::UnsupportedIdentifier(id)),
        }
    }
}

fn ascii_to_string(buf: &[u8]) -> String {
    match std::str::from_utf8(buf) {
        Ok(s) => s.trim_end().to_string(),
        Err(e) => {
            let (valid, _) = buf.split_at(e.valid_up_to());
            std::str::from_utf8(valid)
                .expect("utf8 checked right above")
                .trim_end()
                .to_string()
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

/// Description of software power control override status for a module.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PowerControl {
    /// The module uses the `LPMode` hardware signal to select low power mode.
    UseLpModePin,

    /// The module is configured for software control of low power mode.
    OverrideLpModePin {
        /// If true, the module is held in low power mode by software. If false,
        /// the module is allowed to enter high power mode.
        low_power: bool,
    },
}

impl ParseFromModule for PowerControl {
    fn reads(id: Identifier) -> Result<Vec<MemoryRead>, Error> {
        match id {
            Identifier::QsfpPlusSff8636 | Identifier::Qsfp28 => {
                // See SFF-8636 rev 2.10a Table 6-9.
                //
                // Byte 93, bit 0 contains the software override bit, and bit 1
                // if the module is forced to low power.
                let page = sff8636::Page::Lower;
                let power = MemoryRead::new(page, 93, 1).unwrap();
                Ok(vec![power])
            }
            Identifier::QsfpPlusCmis | Identifier::QsfpDD => {
                // See CMIS 5.0 table 8-10.
                //
                // Byte 26, bit 6 contains the software override bit, and bit 4
                // if the module is forced to low power. Note that the override
                // bit is really phrased as "allow the module to evaluate the
                // LPMode pin." That is, `0b1` means `LPMode` controls the
                // system, and `0b0` means software does.
                let page = cmis::Page::Lower;
                let power = MemoryRead::new(page, 26, 1).unwrap();
                Ok(vec![power])
            }
            _ => Err(Error::UnsupportedIdentifier(id)),
        }
    }

    fn parse<'a>(id: Identifier, mut reads: impl Iterator<Item = &'a [u8]>) -> Result<Self, Error> {
        match id {
            Identifier::QsfpPlusSff8636 | Identifier::Qsfp28 => {
                // Bit 0 -> override, bit 1 -> force low-power.
                reads
                    .next()
                    .and_then(|bytes| bytes.first())
                    .ok_or(Error::ParseFailed)
                    .map(|power| {
                        if power & 0b1 == 0 {
                            PowerControl::UseLpModePin
                        } else {
                            PowerControl::OverrideLpModePin {
                                low_power: (power & 0b10) != 0,
                            }
                        }
                    })
            }
            Identifier::QsfpPlusCmis | Identifier::QsfpDD => {
                // Bit 6 -> override (but see above), bit 4 -> force low-power.
                reads
                    .next()
                    .and_then(|bytes| bytes.first())
                    .ok_or(Error::ParseFailed)
                    .map(|power| {
                        if (power & 0b0100_0000) != 0 {
                            PowerControl::UseLpModePin
                        } else {
                            PowerControl::OverrideLpModePin {
                                low_power: (power & 0b0001_0000) != 0,
                            }
                        }
                    })
            }
            _ => Err(Error::UnsupportedIdentifier(id)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Identifier;
    use super::MemoryModel;
    use super::Oui;
    use super::ParseFromModule;
    use super::PowerControl;
    use super::Vendor;
    use super::VendorInfo;

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

        let parsed = VendorInfo::parse(id, std::iter::once(data.as_slice())).unwrap();

        assert_prefix(VENDOR_NAME, &parsed.vendor.name);
        assert_eq!(OUI, parsed.vendor.oui.0);
        assert_prefix(PART, &parsed.vendor.part);
        assert_prefix(REVISION, &parsed.vendor.revision);
        assert_prefix(SERIAL, &parsed.vendor.serial);
        assert_eq!(
            parsed.vendor.date.as_deref(),
            std::str::from_utf8(DATE).ok()
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

        let parsed = VendorInfo::parse(id, reads).unwrap();
        assert_prefix(VENDOR_NAME, &parsed.vendor.name);
        assert_eq!(OUI, parsed.vendor.oui.0);
        assert_prefix(PART, &parsed.vendor.part);
        assert_prefix(REVISION, &parsed.vendor.revision);
        assert_prefix(SERIAL, &parsed.vendor.serial);
        assert_eq!(
            parsed.vendor.date.as_deref(),
            std::str::from_utf8(DATE).ok()
        );
    }

    #[test]
    fn test_power_control_from_module_sff8636() {
        let id = Identifier::Qsfp28;

        let bytes = [0b10u8]; // NOT power override
        let control = PowerControl::parse(id, std::iter::once(bytes.as_slice())).unwrap();
        assert!(matches!(control, PowerControl::UseLpModePin));

        let bytes = [0b11u8]; // Power override, set to low power.
        let control = PowerControl::parse(id, std::iter::once(bytes.as_slice())).unwrap();
        assert!(matches!(
            control,
            PowerControl::OverrideLpModePin { low_power: true }
        ));

        let bytes = [0b01u8]; // Power override, _not_ set to low power.
        let control = PowerControl::parse(id, std::iter::once(bytes.as_slice())).unwrap();
        assert!(matches!(
            control,
            PowerControl::OverrideLpModePin { low_power: false }
        ));
    }

    #[test]
    fn test_power_control_from_module_cmis() {
        let id = Identifier::QsfpPlusCmis;

        let bytes = [0b0100_0000]; // NOT power override.
        let control = PowerControl::parse(id, std::iter::once(bytes.as_slice())).unwrap();
        assert!(matches!(control, PowerControl::UseLpModePin));

        let bytes = [0b0000_0000]; // YES power override, not low power
        let control = PowerControl::parse(id, std::iter::once(bytes.as_slice())).unwrap();
        assert!(matches!(
            control,
            PowerControl::OverrideLpModePin { low_power: false }
        ));

        let bytes = [0b0001_0000]; // Power override, set to low power.
        let control = PowerControl::parse(id, std::iter::once(bytes.as_slice())).unwrap();
        assert!(matches!(
            control,
            PowerControl::OverrideLpModePin { low_power: true }
        ));
    }

    #[test]
    fn test_oui_from_str() {
        let oui = Oui([0xa8, 0x40, 0x25]);
        let s = "a8-40-25";
        assert_eq!(format!("{oui}"), s);
        assert_eq!(oui, s.parse().unwrap());
    }

    #[test]
    fn test_vendor_info_serdes() {
        let v = VendorInfo {
            identifier: Identifier::QsfpPlusSff8636,
            vendor: Vendor {
                name: String::from("foo"),
                oui: Oui([0xa8, 0x40, 0x25]),
                part: String::from("bar"),
                revision: String::from("ab"),
                serial: String::from("some sn"),
                date: Some(String::from("220202ab")),
            },
        };
        let expected = "{\"identifier\":\"qsfp_plus_sff8636\",\"vendor\":\
            {\"name\":\"foo\",\"oui\":\"a8-40-25\",\"part\":\"bar\",\
            \"revision\":\"ab\",\"serial\":\"some sn\",\"date\":\"220202ab\"}}";
        assert_eq!(serde_json::to_string(&v).unwrap(), expected);
        assert_eq!(v, serde_json::from_str(expected).unwrap());
    }
}
