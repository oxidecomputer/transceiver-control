// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Decoding of transceiver identifying information.

use crate::Error;
use crate::ParseFromModule;
use std::fmt;
use std::ops::Range;
use transceiver_messages::mgmt::cmis;
use transceiver_messages::mgmt::sff8636;
pub use transceiver_messages::mgmt::ManagementInterface;
use transceiver_messages::mgmt::MemoryRead;

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
pub struct Oui(pub [u8; 3]);

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

impl std::convert::TryFrom<String> for Oui {
    type Error = <Self as std::str::FromStr>::Err;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_str().parse()
    }
}

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
                Ok(Self {
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

/// The host electrical interface ID.
///
/// See SFF-8024 Table 4-5.
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)
)]
#[cfg_attr(any(feature = "api-traits", test), serde(rename_all = "snake_case"))]
pub enum HostElectricalInterfaceId {
    Undefined,
    Id1000BaseCX,
    IdXaui,
    IdXfi,
    IdSfi,
    Id25Gaui,
    IdXlaui,
    IdXlppi,
    IdXlaui2,
    Id50Gaui2,
    Id50Gaui1,
    IdCaui4,
    IdCaui4WithoutFec,
    IdCaui4WithRsFec,
    Id100GGaui4,
    Id100GGaui2,
    Id100GGaui1S,
    Id100GGaui1L,
    Id200GGaui8,
    Id200GGaui4,
    Id200GGaui2S,
    Id200GGaui2L,
    Id400Gaui16,
    Id400Gaui8,
    Id400Gaui4S,
    Id400Gaui4L,
    Id800GS,
    Id800GL,
    Id10GBaseCx4,
    Id25GBaseCrCa25GL,
    Id25GBaseCrS,
    Id25GBaseCrN,
    Id40GBaseCr4,
    Id50GBaseCr2WithRsFec,
    Id50GBaseCr2WithFirecodeFec,
    Id50GBaseCr2,
    Id50GBaseCr,
    Id100GBaseCr10,
    Id100GBaseCr4,
    Id100GBaseCr2,
    Id100GBaseCr1,
    Id200GBaseCr4,
    Id200GBaseCr2,
    Id400GCr8,
    Id400GBaseCr4,
    Id800GEtcCr8,
    Reserved(u8),
    Other(u8),
    Custom(u8),
    EndOfList,
}

impl From<u8> for HostElectricalInterfaceId {
    fn from(x: u8) -> Self {
        match x {
            0x00 => HostElectricalInterfaceId::Undefined,
            0x01 => HostElectricalInterfaceId::Id1000BaseCX,
            0x02 => HostElectricalInterfaceId::IdXaui,
            0x03 => HostElectricalInterfaceId::IdXfi,
            0x04 => HostElectricalInterfaceId::IdSfi,
            0x05 => HostElectricalInterfaceId::Id25Gaui,
            0x06 => HostElectricalInterfaceId::IdXlaui,
            0x07 => HostElectricalInterfaceId::IdXlppi,
            0x08 => HostElectricalInterfaceId::IdXlaui2,
            0x09 => HostElectricalInterfaceId::Id50Gaui2,
            0x0a => HostElectricalInterfaceId::Id50Gaui1,
            0x0b => HostElectricalInterfaceId::IdCaui4,
            0x41 => HostElectricalInterfaceId::IdCaui4WithoutFec,
            0x42 => HostElectricalInterfaceId::IdCaui4WithRsFec,
            0x0c => HostElectricalInterfaceId::Id100GGaui4,
            0x0d => HostElectricalInterfaceId::Id100GGaui2,
            0x4b => HostElectricalInterfaceId::Id100GGaui1S,
            0x4c => HostElectricalInterfaceId::Id100GGaui1L,
            0x0e => HostElectricalInterfaceId::Id200GGaui8,
            0x0f => HostElectricalInterfaceId::Id200GGaui4,
            0x4d => HostElectricalInterfaceId::Id200GGaui2S,
            0x4e => HostElectricalInterfaceId::Id200GGaui2L,
            0x10 => HostElectricalInterfaceId::Id400Gaui16,
            0x11 => HostElectricalInterfaceId::Id400Gaui8,
            0x4f => HostElectricalInterfaceId::Id400Gaui4S,
            0x50 => HostElectricalInterfaceId::Id400Gaui4L,
            0x51 => HostElectricalInterfaceId::Id800GS,
            0x52 => HostElectricalInterfaceId::Id800GL,
            0x13 => HostElectricalInterfaceId::Id10GBaseCx4,
            0x14 => HostElectricalInterfaceId::Id25GBaseCrCa25GL,
            0x15 => HostElectricalInterfaceId::Id25GBaseCrS,
            0x16 => HostElectricalInterfaceId::Id25GBaseCrN,
            0x17 => HostElectricalInterfaceId::Id40GBaseCr4,
            0x43 => HostElectricalInterfaceId::Id50GBaseCr2WithRsFec,
            0x44 => HostElectricalInterfaceId::Id50GBaseCr2WithFirecodeFec,
            0x45 => HostElectricalInterfaceId::Id50GBaseCr2,
            0x18 => HostElectricalInterfaceId::Id50GBaseCr,
            0x19 => HostElectricalInterfaceId::Id100GBaseCr10,
            0x1a => HostElectricalInterfaceId::Id100GBaseCr4,
            0x1b => HostElectricalInterfaceId::Id100GBaseCr2,
            0x46 => HostElectricalInterfaceId::Id100GBaseCr1,
            0x1c => HostElectricalInterfaceId::Id200GBaseCr4,
            0x47 => HostElectricalInterfaceId::Id200GBaseCr2,
            0x1d => HostElectricalInterfaceId::Id400GCr8,
            0x48 => HostElectricalInterfaceId::Id400GBaseCr4,
            0x49 => HostElectricalInterfaceId::Id800GEtcCr8,
            0x12 | 0x30..=0x36 | 0x54..=0xbf => HostElectricalInterfaceId::Reserved(x),
            0xff => HostElectricalInterfaceId::EndOfList,
            0xc0..=0xfe => HostElectricalInterfaceId::Custom(x),
            _ => HostElectricalInterfaceId::Other(x),
        }
    }
}

impl fmt::Display for HostElectricalInterfaceId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            HostElectricalInterfaceId::Reserved(x) => format!("Reserved ({x})"),
            HostElectricalInterfaceId::Custom(x) => format!("Custom ({x})"),
            HostElectricalInterfaceId::Other(x) => format!("Other ({x})"),
            _ => match self {
                HostElectricalInterfaceId::Undefined => "Undefined",
                HostElectricalInterfaceId::Id1000BaseCX => "1000BASE-CX",
                HostElectricalInterfaceId::IdXaui => "XAUI",
                HostElectricalInterfaceId::IdXfi => "XFI",
                HostElectricalInterfaceId::IdSfi => "SFI",
                HostElectricalInterfaceId::Id25Gaui => "25GAUI C2M",
                HostElectricalInterfaceId::IdXlaui => "XLAUI C2M",
                HostElectricalInterfaceId::IdXlppi => "XLPPI",
                HostElectricalInterfaceId::IdXlaui2 => "LAUI-2 C2M",
                HostElectricalInterfaceId::Id50Gaui2 => "50GAUI-2 C2M",
                HostElectricalInterfaceId::Id50Gaui1 => "50GAUI-1 C2M",
                HostElectricalInterfaceId::IdCaui4 => "CAUI-4 C2M",
                HostElectricalInterfaceId::IdCaui4WithoutFec => "CAUI-4 C2M with out FEC",
                HostElectricalInterfaceId::IdCaui4WithRsFec => "CAUI-4 C2M with RS(528, 514) FEC",
                HostElectricalInterfaceId::Id100GGaui4 => "100GAUI-4 C2M",
                HostElectricalInterfaceId::Id100GGaui2 => "100GAUI-2 C2M",
                HostElectricalInterfaceId::Id100GGaui1S => "100GAUI-1-S C2M",
                HostElectricalInterfaceId::Id100GGaui1L => "100GAUI-1-L C2M",
                HostElectricalInterfaceId::Id200GGaui8 => "200GAUI-8 C2M",
                HostElectricalInterfaceId::Id200GGaui4 => "200GAUI-4 C2M",
                HostElectricalInterfaceId::Id200GGaui2S => "200GAUI-2-S C2M",
                HostElectricalInterfaceId::Id200GGaui2L => "200GAUI-2-L C2M",
                HostElectricalInterfaceId::Id400Gaui16 => "400GAUI-16 C2M",
                HostElectricalInterfaceId::Id400Gaui8 => "400GAUI-8 C2M",
                HostElectricalInterfaceId::Id400Gaui4S => "400GAUI-4-S C2M",
                HostElectricalInterfaceId::Id400Gaui4L => "400GAUI-4-L C2M",
                HostElectricalInterfaceId::Id800GS => "800G S C2M",
                HostElectricalInterfaceId::Id800GL => "800G L C2M",
                HostElectricalInterfaceId::Id10GBaseCx4 => "10GBASE-CX4",
                HostElectricalInterfaceId::Id25GBaseCrCa25GL => "25GBASE-CR CA-25G-L",
                HostElectricalInterfaceId::Id25GBaseCrS => "25GBASE-CR or 25GBASE-CR-S CA-25G-S",
                HostElectricalInterfaceId::Id25GBaseCrN => "25GBASE-CR or 25GBASE-CR-S CA-25G-N",
                HostElectricalInterfaceId::Id40GBaseCr4 => "40GBASE-CR4",
                HostElectricalInterfaceId::Id50GBaseCr2WithRsFec => {
                    "50GBASE-CR2 with RS(528, 514) FEC"
                }
                HostElectricalInterfaceId::Id50GBaseCr2WithFirecodeFec => {
                    "50GBASE-CR2 with Firecode FEC"
                }
                HostElectricalInterfaceId::Id50GBaseCr2 => "50GBASE-CR2 with no FEC",
                HostElectricalInterfaceId::Id50GBaseCr => "50GBASE-CR",
                HostElectricalInterfaceId::Id100GBaseCr10 => "100GBASE-CR10",
                HostElectricalInterfaceId::Id100GBaseCr4 => "100GBASE-CR4",
                HostElectricalInterfaceId::Id100GBaseCr2 => "100GBASE-CR2",
                HostElectricalInterfaceId::Id100GBaseCr1 => "100GBASE-CR1",
                HostElectricalInterfaceId::Id200GBaseCr4 => "200GBASE-CR4",
                HostElectricalInterfaceId::Id200GBaseCr2 => "200GBASE-CR2",
                HostElectricalInterfaceId::Id400GCr8 => "400G CR8",
                HostElectricalInterfaceId::Id400GBaseCr4 => "400GBASE-CR4",
                HostElectricalInterfaceId::Id800GEtcCr8 => "800G-ETC-CR8",
                HostElectricalInterfaceId::EndOfList => "End of list",
                _ => unreachable!(),
            }
            .to_string(),
        };
        write!(f, "{s}")
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)
)]
#[cfg_attr(any(feature = "api-traits", test), serde(rename_all = "snake_case"))]
pub enum MediaType {
    Undefined,
    MultiModeFiber,
    SingleModeFiber,
    PassiveCopper,
    ActiveCable,
    BaseT,
    Reserved(u8),
    Custom(u8),
}

impl fmt::Display for MediaType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            MediaType::Reserved(x) => format!("Reserved ({x})"),
            MediaType::Custom(x) => format!("Custom ({x})"),
            _ => match self {
                MediaType::Undefined => "Undefined",
                MediaType::MultiModeFiber => "Multi-mode fiber",
                MediaType::SingleModeFiber => "Single-mode fiber",
                MediaType::PassiveCopper => "Passive copper",
                MediaType::ActiveCable => "Active cable",
                MediaType::BaseT => "BASE-T",
                _ => unreachable!(),
            }
            .to_string(),
        };
        write!(f, "{s}")
    }
}

impl From<u8> for MediaType {
    fn from(x: u8) -> Self {
        match x {
            0x00 => Self::Undefined,
            0x01 => Self::MultiModeFiber,
            0x02 => Self::SingleModeFiber,
            0x03 => Self::PassiveCopper,
            0x04 => Self::ActiveCable,
            0x05 => Self::BaseT,
            0x40..=0x8f => Self::Custom(x),
            _ => Self::Reserved(x),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)
)]
#[cfg_attr(any(feature = "api-traits", test), serde(rename_all = "snake_case"))]
pub enum MediaInterfaceId {
    Mmf(MmfMediaInterfaceId),
    Smf(SmfMediaInterfaceId),
    PassiveCopper(PassiveCopperMediaInterfaceId),
    ActiveCable(ActiveCableMediaInterfaceId),
    BaseT(BaseTMediaInterfaceId),
}

impl MediaInterfaceId {
    pub fn from_u8(media_type: MediaType, x: u8) -> Option<Self> {
        match media_type {
            MediaType::Undefined | MediaType::Reserved(_) | MediaType::Custom(_) => None,
            MediaType::MultiModeFiber => Some(MediaInterfaceId::Mmf(MmfMediaInterfaceId::from(x))),
            MediaType::SingleModeFiber => Some(MediaInterfaceId::Smf(SmfMediaInterfaceId::from(x))),
            MediaType::PassiveCopper => Some(MediaInterfaceId::PassiveCopper(
                PassiveCopperMediaInterfaceId::from(x),
            )),
            MediaType::ActiveCable => Some(MediaInterfaceId::ActiveCable(
                ActiveCableMediaInterfaceId::from(x),
            )),
            MediaType::BaseT => Some(MediaInterfaceId::BaseT(BaseTMediaInterfaceId::from(x))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)
)]
#[cfg_attr(any(feature = "api-traits", test), serde(rename_all = "snake_case"))]
pub enum MmfMediaInterfaceId {
    Undefined,
    Id10GBaseSw,
    Id10GBaseSr,
    Id25GBaseSr,
    Id40GBaseSr3,
    Id40GESwdm4,
    Id40GEBiDi,
    Id50GBaseSr,
    Id100GBaseSr10,
    Id100GBaseSr4,
    Id100GBaseSwdm4,
    Id100GEBiDi,
    Id100GBaseSr2,
    Id100GBaseSr1,
    Id100GBaseVr1,
    Id200GBaseSr4,
    Id200GBaseSr2,
    Id200GBaseVr2,
    Id400GBaseSr16,
    Id400GBaseSr8,
    Id400GBaseSr4,
    Id400GBaseVr4,
    Id800GBaseSr8,
    Id800GBaseVr8,
    Id400GBaseSr42,
    Other(u8),
}

impl From<u8> for MmfMediaInterfaceId {
    fn from(x: u8) -> Self {
        match x {
            0x00 => MmfMediaInterfaceId::Undefined,
            0x01 => MmfMediaInterfaceId::Id10GBaseSw,
            0x02 => MmfMediaInterfaceId::Id10GBaseSr,
            0x03 => MmfMediaInterfaceId::Id25GBaseSr,
            0x04 => MmfMediaInterfaceId::Id40GBaseSr3,
            0x05 => MmfMediaInterfaceId::Id40GESwdm4,
            0x06 => MmfMediaInterfaceId::Id40GEBiDi,
            0x07 => MmfMediaInterfaceId::Id50GBaseSr,
            0x08 => MmfMediaInterfaceId::Id100GBaseSr10,
            0x09 => MmfMediaInterfaceId::Id100GBaseSr4,
            0x0a => MmfMediaInterfaceId::Id100GBaseSwdm4,
            0x0b => MmfMediaInterfaceId::Id100GEBiDi,
            0x0c => MmfMediaInterfaceId::Id100GBaseSr2,
            0x0d => MmfMediaInterfaceId::Id100GBaseSr1,
            0x1d => MmfMediaInterfaceId::Id100GBaseVr1,
            0x0e => MmfMediaInterfaceId::Id200GBaseSr4,
            0x1b => MmfMediaInterfaceId::Id200GBaseSr2,
            0x1e => MmfMediaInterfaceId::Id200GBaseVr2,
            0x0f => MmfMediaInterfaceId::Id400GBaseSr16,
            0x10 => MmfMediaInterfaceId::Id400GBaseSr8,
            0x11 => MmfMediaInterfaceId::Id400GBaseSr4,
            0x1f => MmfMediaInterfaceId::Id400GBaseVr4,
            0x12 => MmfMediaInterfaceId::Id800GBaseSr8,
            0x20 => MmfMediaInterfaceId::Id800GBaseVr8,
            0x1a => MmfMediaInterfaceId::Id400GBaseSr42,
            _ => MmfMediaInterfaceId::Other(x),
        }
    }
}

impl fmt::Display for MmfMediaInterfaceId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let MmfMediaInterfaceId::Other(x) = self {
            write!(f, "Other ({x:0x})")
        } else {
            let s = match self {
                MmfMediaInterfaceId::Undefined => "Undefined",
                MmfMediaInterfaceId::Id10GBaseSw => "10GBASE-SW",
                MmfMediaInterfaceId::Id10GBaseSr => "10GBASE-SR",
                MmfMediaInterfaceId::Id25GBaseSr => "25GBASE-SR",
                MmfMediaInterfaceId::Id40GBaseSr3 => "40GBASE-SR4",
                MmfMediaInterfaceId::Id40GESwdm4 => "40GE SWDM4",
                MmfMediaInterfaceId::Id40GEBiDi => "40GE BiDi",
                MmfMediaInterfaceId::Id50GBaseSr => "50GBASE-SR",
                MmfMediaInterfaceId::Id100GBaseSr10 => "100GBASE-SR10",
                MmfMediaInterfaceId::Id100GBaseSr4 => "100GBASE-SR4",
                MmfMediaInterfaceId::Id100GBaseSwdm4 => "100GE SWDM4",
                MmfMediaInterfaceId::Id100GEBiDi => "100GE BiDi",
                MmfMediaInterfaceId::Id100GBaseSr2 => "100GBASE-SR2",
                MmfMediaInterfaceId::Id100GBaseSr1 => "100GBASE-SR1",
                MmfMediaInterfaceId::Id100GBaseVr1 => "100GBASE-VR1",
                MmfMediaInterfaceId::Id200GBaseSr4 => "200GBASE-SR4",
                MmfMediaInterfaceId::Id200GBaseSr2 => "200GBASE-SR2",
                MmfMediaInterfaceId::Id200GBaseVr2 => "200GBASE-VR4",
                MmfMediaInterfaceId::Id400GBaseSr16 => "400GBASE-SR16",
                MmfMediaInterfaceId::Id400GBaseSr8 => "400GBASE-SR8",
                MmfMediaInterfaceId::Id400GBaseSr4 => "400GBASE-SR4",
                MmfMediaInterfaceId::Id400GBaseVr4 => "400GBASE-VR4",
                MmfMediaInterfaceId::Id800GBaseSr8 => "800GBASE-SR8",
                MmfMediaInterfaceId::Id800GBaseVr8 => "800GBASE-VR8",
                MmfMediaInterfaceId::Id400GBaseSr42 => "400GBASE-SR4.2",
                MmfMediaInterfaceId::Other(_) => unreachable!(),
            };
            write!(f, "{s}")
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)
)]
#[cfg_attr(any(feature = "api-traits", test), serde(rename_all = "snake_case"))]
pub enum SmfMediaInterfaceId {
    Undefined,
    Id10GBaseLw,
    Id10GBaseEw,
    Id10GZw,
    Id10GBaseLr,
    Id10GBaseEr,
    Id10GBaseBr,
    Id10GZr,
    Id25GBaseLr,
    Id25GBaseEr,
    Id25GBaseBr,
    Id40GBaseLr4,
    Id40GBaseFr,
    Id50GBaseFr,
    Id50GBaseLr,
    Id50GBaseEr,
    Id50GBaseBr,
    Id100GBaseLr4,
    Id100GBaseEr4,
    Id100GPsm4,
    Id100GCwdm4Ocp,
    Id100GCwdm4,
    Id100G4wdm10,
    Id100G4wdm20,
    Id100G4wdm40,
    Id100GBaseDr,
    Id100GFr,
    Id100GLr,
    Id100GLr120,
    Id100GEr130,
    Id100GEr140,
    Id100GBaseZr,
    Id200GBaseDr4,
    Id200GBaseFr4,
    Id200GBaseLr4,
    Id200GBaseEr4,
    Id400GBaseFr8,
    Id400GBaseLr8,
    Id400GBaseEr8,
    Id400GBaseDr4,
    Id400GBaseDr42,
    Id400GFr4,
    Id400GBaseLr46,
    Id400GLr410,
    Id400GBaseZr,
    Id800GBaseDr8,
    Id800GBaseDr82,
    Other(u8),
}

impl From<u8> for SmfMediaInterfaceId {
    fn from(x: u8) -> Self {
        match x {
            0x00 => SmfMediaInterfaceId::Undefined,
            0x01 => SmfMediaInterfaceId::Id10GBaseLw,
            0x02 => SmfMediaInterfaceId::Id10GBaseEw,
            0x03 => SmfMediaInterfaceId::Id10GZw,
            0x04 => SmfMediaInterfaceId::Id10GBaseLr,
            0x05 => SmfMediaInterfaceId::Id10GBaseEr,
            0x4e => SmfMediaInterfaceId::Id10GBaseBr,
            0x06 => SmfMediaInterfaceId::Id10GZr,
            0x07 => SmfMediaInterfaceId::Id25GBaseLr,
            0x08 => SmfMediaInterfaceId::Id25GBaseEr,
            0x4f => SmfMediaInterfaceId::Id25GBaseBr,
            0x09 => SmfMediaInterfaceId::Id40GBaseLr4,
            0x0a => SmfMediaInterfaceId::Id40GBaseFr,
            0x0b => SmfMediaInterfaceId::Id50GBaseFr,
            0x0c => SmfMediaInterfaceId::Id50GBaseLr,
            0x40 => SmfMediaInterfaceId::Id50GBaseEr,
            0x50 => SmfMediaInterfaceId::Id50GBaseBr,
            0x0d => SmfMediaInterfaceId::Id100GBaseLr4,
            0x0e => SmfMediaInterfaceId::Id100GBaseEr4,
            0x0f => SmfMediaInterfaceId::Id100GPsm4,
            0x34 => SmfMediaInterfaceId::Id100GCwdm4Ocp,
            0x10 => SmfMediaInterfaceId::Id100GCwdm4,
            0x11 => SmfMediaInterfaceId::Id100G4wdm10,
            0x12 => SmfMediaInterfaceId::Id100G4wdm20,
            0x13 => SmfMediaInterfaceId::Id100G4wdm40,
            0x14 => SmfMediaInterfaceId::Id100GBaseDr,
            0x15 => SmfMediaInterfaceId::Id100GFr,
            0x16 => SmfMediaInterfaceId::Id100GLr,
            0x4a => SmfMediaInterfaceId::Id100GLr120,
            0x4b => SmfMediaInterfaceId::Id100GEr130,
            0x4c => SmfMediaInterfaceId::Id100GEr140,
            0x44 => SmfMediaInterfaceId::Id100GBaseZr,
            0x17 => SmfMediaInterfaceId::Id200GBaseDr4,
            0x18 => SmfMediaInterfaceId::Id200GBaseFr4,
            0x19 => SmfMediaInterfaceId::Id200GBaseLr4,
            0x41 => SmfMediaInterfaceId::Id200GBaseEr4,
            0x1a => SmfMediaInterfaceId::Id400GBaseFr8,
            0x1b => SmfMediaInterfaceId::Id400GBaseLr8,
            0x42 => SmfMediaInterfaceId::Id400GBaseEr8,
            0x1c => SmfMediaInterfaceId::Id400GBaseDr4,
            0x55 => SmfMediaInterfaceId::Id400GBaseDr42,
            0x1d => SmfMediaInterfaceId::Id400GFr4,
            0x43 => SmfMediaInterfaceId::Id400GBaseLr46,
            0x1e => SmfMediaInterfaceId::Id400GLr410,
            0x4d => SmfMediaInterfaceId::Id400GBaseZr,
            0x56 => SmfMediaInterfaceId::Id800GBaseDr8,
            0x57 => SmfMediaInterfaceId::Id800GBaseDr82,
            _ => SmfMediaInterfaceId::Other(x),
        }
    }
}

impl fmt::Display for SmfMediaInterfaceId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let SmfMediaInterfaceId::Other(x) = self {
            write!(f, "Other ({x:02x})")
        } else {
            let s = match self {
                SmfMediaInterfaceId::Undefined => "Undefined",
                SmfMediaInterfaceId::Id10GBaseLw => "10GBASE-LW",
                SmfMediaInterfaceId::Id10GBaseEw => "10GBASE-EW",
                SmfMediaInterfaceId::Id10GZw => "10G-ZW",
                SmfMediaInterfaceId::Id10GBaseLr => "10GBASE-LR",
                SmfMediaInterfaceId::Id10GBaseEr => "10GBASE-ER",
                SmfMediaInterfaceId::Id10GBaseBr => "10GBASE-BR",
                SmfMediaInterfaceId::Id10GZr => "10G-ZR",
                SmfMediaInterfaceId::Id25GBaseLr => "25GBASE-LR",
                SmfMediaInterfaceId::Id25GBaseEr => "25GBASE-ER",
                SmfMediaInterfaceId::Id25GBaseBr => "25GBASE-BR",
                SmfMediaInterfaceId::Id40GBaseLr4 => "40GBASE-LR4",
                SmfMediaInterfaceId::Id40GBaseFr => "40GBASE-FR",
                SmfMediaInterfaceId::Id50GBaseFr => "50GBASE-FR",
                SmfMediaInterfaceId::Id50GBaseLr => "50GBASE-LR",
                SmfMediaInterfaceId::Id50GBaseEr => "50GBASE-ER",
                SmfMediaInterfaceId::Id50GBaseBr => "50GBASE-BR",
                SmfMediaInterfaceId::Id100GBaseLr4 => "100GBASE-LR4",
                SmfMediaInterfaceId::Id100GBaseEr4 => "100GBASE-ER4",
                SmfMediaInterfaceId::Id100GPsm4 => "100G PSM4",
                SmfMediaInterfaceId::Id100GCwdm4Ocp => "100G CWDM4-OCP",
                SmfMediaInterfaceId::Id100GCwdm4 => "100G CWDM4",
                SmfMediaInterfaceId::Id100G4wdm10 => "100G 4WDM-10",
                SmfMediaInterfaceId::Id100G4wdm20 => "100G 4WDM-20",
                SmfMediaInterfaceId::Id100G4wdm40 => "100G 4WDM-40",
                SmfMediaInterfaceId::Id100GBaseDr => "100GBASE-DR",
                SmfMediaInterfaceId::Id100GFr => "100G-FR / 100GBASE-FR1",
                SmfMediaInterfaceId::Id100GLr => "100G-LR / 100GBASE-LR1",
                SmfMediaInterfaceId::Id100GLr120 => "100G-LR1-20",
                SmfMediaInterfaceId::Id100GEr130 => "100G-ER1-30",
                SmfMediaInterfaceId::Id100GEr140 => "100G-ER1-40",
                SmfMediaInterfaceId::Id100GBaseZr => "100GBASE-ZR",
                SmfMediaInterfaceId::Id200GBaseDr4 => "200GBASE-DR4",
                SmfMediaInterfaceId::Id200GBaseFr4 => "200GBASE-FR4",
                SmfMediaInterfaceId::Id200GBaseLr4 => "200GBASE-LR4",
                SmfMediaInterfaceId::Id200GBaseEr4 => "200GBASE-ER4",
                SmfMediaInterfaceId::Id400GBaseFr8 => "400GBASE-FR8",
                SmfMediaInterfaceId::Id400GBaseLr8 => "400GBASE-LR8",
                SmfMediaInterfaceId::Id400GBaseEr8 => "400GBASE-ER8",
                SmfMediaInterfaceId::Id400GBaseDr4 => "400GBASE-DR4",
                SmfMediaInterfaceId::Id400GBaseDr42 => "400GBASE-DR4-2",
                SmfMediaInterfaceId::Id400GFr4 => "400G-FR4 / 400GBASE-FR4",
                SmfMediaInterfaceId::Id400GBaseLr46 => "400GBASE-LR4-6",
                SmfMediaInterfaceId::Id400GLr410 => "400G-LR4-10",
                SmfMediaInterfaceId::Id400GBaseZr => "400GBASE-ZR",
                SmfMediaInterfaceId::Id800GBaseDr8 => "800GBASE-DR8",
                SmfMediaInterfaceId::Id800GBaseDr82 => "800GBASE-DR8-2",
                SmfMediaInterfaceId::Other(_) => unreachable!(),
            };
            write!(f, "{s}")
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)
)]
#[cfg_attr(any(feature = "api-traits", test), serde(rename_all = "snake_case"))]
pub enum PassiveCopperMediaInterfaceId {
    Undefined,
    CopperCable,
    PassiveLoopback,
    Custom(u8),
    Reserved(u8),
}

impl From<u8> for PassiveCopperMediaInterfaceId {
    fn from(x: u8) -> Self {
        match x {
            0x00 => PassiveCopperMediaInterfaceId::Undefined,
            0x01 => PassiveCopperMediaInterfaceId::CopperCable,
            0xbf => PassiveCopperMediaInterfaceId::PassiveLoopback,
            0x02..=0xbe => PassiveCopperMediaInterfaceId::Reserved(x),
            0xc0..=0xff => PassiveCopperMediaInterfaceId::Custom(x),
        }
    }
}

impl fmt::Display for PassiveCopperMediaInterfaceId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Undefined => write!(f, "Undefined"),
            Self::CopperCable => write!(f, "Copper cable"),
            Self::PassiveLoopback => write!(f, "Passive loopback"),
            Self::Reserved(x) => write!(f, "Reserved ({x:02x})"),
            Self::Custom(x) => write!(f, "Custom ({x:02x})"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)
)]
#[cfg_attr(any(feature = "api-traits", test), serde(rename_all = "snake_case"))]
pub enum ActiveCableMediaInterfaceId {
    Undefined,
    ActiveWithBer1en12,
    ActiveWithBer5en5,
    ActiveWithBer2p6en4,
    ActiveWithBer10en6,
    ActiveLoopback,
    Custom(u8),
    Reserved(u8),
}

impl From<u8> for ActiveCableMediaInterfaceId {
    fn from(x: u8) -> Self {
        match x {
            0x00 => ActiveCableMediaInterfaceId::Undefined,
            0x01 => ActiveCableMediaInterfaceId::ActiveWithBer1en12,
            0x02 => ActiveCableMediaInterfaceId::ActiveWithBer5en5,
            0x03 => ActiveCableMediaInterfaceId::ActiveWithBer2p6en4,
            0x04 => ActiveCableMediaInterfaceId::ActiveWithBer10en6,
            0xbf => ActiveCableMediaInterfaceId::ActiveLoopback,
            0x05..=0xbe => ActiveCableMediaInterfaceId::Reserved(x),
            0xc0..=0xff => ActiveCableMediaInterfaceId::Custom(x),
        }
    }
}

impl fmt::Display for ActiveCableMediaInterfaceId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ActiveCableMediaInterfaceId::Custom(x) => write!(f, "Custom ({x:02x})"),
            ActiveCableMediaInterfaceId::Reserved(x) => write!(f, "Reserved ({x:02x})"),
            ActiveCableMediaInterfaceId::Undefined => write!(f, "Undefined"),
            ActiveCableMediaInterfaceId::ActiveLoopback => write!(f, "Active Loopback module"),
            _other => {
                let ber = match self {
                    ActiveCableMediaInterfaceId::ActiveWithBer1en12 => 10e-12,
                    ActiveCableMediaInterfaceId::ActiveWithBer5en5 => 5e-5,
                    ActiveCableMediaInterfaceId::ActiveWithBer2p6en4 => 2.6e-4,
                    ActiveCableMediaInterfaceId::ActiveWithBer10en6 => 10e-6,
                    _ => unreachable!(),
                };
                write!(f, "Active Cable assembly with BER < {ber:0.1e}")
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)
)]
#[cfg_attr(any(feature = "api-traits", test), serde(rename_all = "snake_case"))]
pub enum BaseTMediaInterfaceId {
    Undefined,
    Id1000BaseT,
    Id2p5GBaseT,
    Id5GBaseT,
    Id10GBaseT,
    Id25GBaseT,
    Id40GBaseT,
    Id50GBaseT,
    Custom(u8),
    Reserved(u8),
}

impl From<u8> for BaseTMediaInterfaceId {
    fn from(x: u8) -> Self {
        match x {
            0x00 => BaseTMediaInterfaceId::Undefined,
            0x01 => BaseTMediaInterfaceId::Id1000BaseT,
            0x02 => BaseTMediaInterfaceId::Id2p5GBaseT,
            0x03 => BaseTMediaInterfaceId::Id5GBaseT,
            0x04 => BaseTMediaInterfaceId::Id10GBaseT,
            0x05 => BaseTMediaInterfaceId::Id25GBaseT,
            0x06 => BaseTMediaInterfaceId::Id40GBaseT,
            0x07 => BaseTMediaInterfaceId::Id50GBaseT,
            0xc0..=0xff => BaseTMediaInterfaceId::Custom(x),
            0x08..=0xbf => BaseTMediaInterfaceId::Reserved(x),
        }
    }
}

impl fmt::Display for BaseTMediaInterfaceId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BaseTMediaInterfaceId::Undefined => write!(f, "Undefined"),
            BaseTMediaInterfaceId::Id1000BaseT => write!(f, "1000BASE-T"),
            BaseTMediaInterfaceId::Id2p5GBaseT => write!(f, "2.5GBASE-T"),
            BaseTMediaInterfaceId::Id5GBaseT => write!(f, "5GBASE-T"),
            BaseTMediaInterfaceId::Id10GBaseT => write!(f, "10GBASE-T"),
            BaseTMediaInterfaceId::Id25GBaseT => write!(f, "25GBASE-T"),
            BaseTMediaInterfaceId::Id40GBaseT => write!(f, "40GBASE-T"),
            BaseTMediaInterfaceId::Id50GBaseT => write!(f, "50GBASE-T"),
            BaseTMediaInterfaceId::Custom(x) => write!(f, "Custom ({x:02x})"),
            BaseTMediaInterfaceId::Reserved(x) => write!(f, "Reserved ({x:02x})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Identifier;
    use super::Oui;
    use super::ParseFromModule;
    use super::Vendor;
    use super::VendorInfo;

    // Assert that `substring` is a prefix of `full`.
    fn assert_prefix(full: &[u8], substring: &str) {
        assert!(std::str::from_utf8(full).unwrap().starts_with(substring))
    }

    #[test]
    fn test_parse_vendor_info_from_module_sff8636() {
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
    fn test_parse_vendor_info_from_module_cmis() {
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
            {\"name\":\"foo\",\"oui\":[168,64,37],\"part\":\"bar\",\
            \"revision\":\"ab\",\"serial\":\"some sn\",\"date\":\"220202ab\"}}";
        assert_eq!(serde_json::to_string(&v).unwrap(), expected);
        assert_eq!(v, serde_json::from_str(expected).unwrap());
    }
}
