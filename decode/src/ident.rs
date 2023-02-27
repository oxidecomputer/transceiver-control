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
                let oui = Oui(data[OUI].try_into().unwrap());
                let part = ascii_to_string(&data[PART]);
                let revision = ascii_to_string(&data[REVISION]);
                let serial = ascii_to_string(&data[SERIAL]);
                let date = std::str::from_utf8(&data[DATE]).ok().map(String::from);

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
                let oui = Oui(buf[OUI].try_into().unwrap());
                let part = ascii_to_string(&buf[PART]);
                let revision = ascii_to_string(&buf[REVISION]);
                let serial = ascii_to_string(&buf[SERIAL]);
                let date = std::str::from_utf8(&buf[DATE]).ok().map(String::from);
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
        assert_eq!(OUI, parsed.oui.0);
        assert_prefix(PART, &parsed.part);
        assert_prefix(REVISION, &parsed.revision);
        assert_prefix(SERIAL, &parsed.serial);
        assert_eq!(parsed.date.as_deref(), std::str::from_utf8(DATE).ok());
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
        assert_eq!(OUI, parsed.oui.0);
        assert_prefix(PART, &parsed.part);
        assert_prefix(REVISION, &parsed.revision);
        assert_prefix(SERIAL, &parsed.serial);
        assert_eq!(parsed.date.as_deref(), std::str::from_utf8(DATE).ok());
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
