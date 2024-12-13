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

crate::bitfield_enum! {
    name = Identifier,
    description = "The SFF-8024 Identifier for a transceiver module.\
    \
    This identifier is used as the main description of the kind of moduel, and
    indicates the spec that it should conform to. It is requried to interpret
    the remainder of the memory map.",
    variants = {
        0x00, Unknown, "Unknown or unspecified",
        0x01, Gbic, "GBIC",
        0x02, Soldered, "Module/connector soldered to motherboard",
        0x03, Sfp, "SFP/SFP+/SFP28",
        0x04, Xbi, "XBI",
        0x05, Xenpak, "XENPAK",
        0x06, Xfp, "XFP",
        0x07, Xff, "XFF",
        0x08, XffE, "XFP-E",
        0x09, Xpak, "XPAK",
        0x0a, X2, "X2",
        0x0b, DwdmSfp, "DWDM-SFP/SFP+",
        0x0c, Qsfp, "QSFP",
        0x0d, QsfpPlusSff8636, "QSFP+ or later with SFF-8636 management interface",
        0x0e, Cxp, "CXP or later",
        0x0f, ShieldedMultiLane4, "Shielded mini multi-lane 4X",
        0x10, ShieldedMultiLane8, "Shielded mini multi-lane 8X",
        0x11, Qsfp28, "QSFP28 or later with SFF-8636 management interface",
        0x12, Cxp2, "CXP2",
        0x13, Cdfp, "CDFP (Style 1 or 2)",
        0x14, ShieldedMultiLane4Fanout, "Shielded mini multi-lane 4X fanout",
        0x15, ShieldedMultiLane8Fanout, "Shielded mini multi-lane 8X fanout",
        0x16, Cdfp3, "CDFP (Style 3)",
        0x17, MicroQsfp, "MicroQSFP",
        0x18, QsfpDD, "QSFP-DD Double Density 8X Pluggable Transceiver",
        0x19, Osfp8, "OSFP 8X Pluggable Transceiver",
        0x1a, SfpDD, "SFP-DD 2X Double Density Pluggable Transceiver",
        0x1b, Dsfp, "DSFP Dual Small Form Factor Pluggable Transceiver",
        0x1c, X4MultiLink, "x4 MiniLink/OcuLink",
        0x1d, X8MiniLink, "x8 MiniLink",
        0x1e, QsfpPlusCmis, "QSFP+ or later with Common Management Interface Specification",
        0x21, OsfpXd, "OSFP-XD with with Common Management interface Specification"
    },
    other_variants = {
        Reserved : 0x21..=0x7f,
        VendorSpecific : 0x80..,
        Unsupported : _,
    }
}

impl Identifier {
    pub const fn management_interface(&self) -> Result<ManagementInterface, Error> {
        use Identifier::*;
        match self {
            QsfpPlusSff8636 | Qsfp28 => Ok(ManagementInterface::Sff8636),
            QsfpPlusCmis | QsfpDD | Osfp8 | OsfpXd => Ok(ManagementInterface::Cmis),
            _ => Err(Error::UnsupportedIdentifier(*self)),
        }
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
            Identifier::QsfpPlusCmis
            | Identifier::QsfpDD
            | Identifier::Osfp8
            | Identifier::OsfpXd => {
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
            Identifier::QsfpPlusCmis
            | Identifier::QsfpDD
            | Identifier::Osfp8
            | Identifier::OsfpXd => {
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

crate::bitfield_enum! {
    name = ExtendedSpecificationComplianceCode,
    description = "Extended electrical or optical interface codes",
    variants = {
        0x00, Unspecified, "Unspecified",
        0x01, Id100GAoc5en5, "100G AOC, retimed or 25GAUI C2M AOC (BER <= 5e-5)",
        0x02, Id100GBaseSr4, "100GBASE-SR4 or 25GBASE-SR",
        0x03, Id100GBaseLr4, "100GBASE-LR4 or 25GBASE-LR",
        0x04, Id100GBaseEr4, "100GBASE-ER4 or 25GBASE-ER",
        0x05, Id100GBaseSr10, "100GBASE-SR10",
        0x06, Id100GBCwdm4, "100G CWDM4",
        0x07, Id100GPsm4, "100G PSM4 Parallel SMF",
        0x08, Id100GAcc, "100G ACC, retimed or 25GAUI C2M ACC",
        0x09, Obsolete, "Obsolete",
        0x0b, Id100GBaseCr4, "100GBASE-CR4, 25GBASE-CR CA-25G-L or 50GBASE-CR2 with RS FEC",
        0x0c, Id25GBaseCrS, "25GBASE-CR CA-25G-S or 50GBASE-CR2 with BASE-R FEC",
        0x0d, Id25GBaseCrN, "25GBASE-CR CA-25G-N or 50GBASE-CR2 with no FEC",
        0x0e, Id10MbEth, "10 Mb/s Single Pair Ethernet",
        0x10, Id40GBaseEr4, "40GBASE-ER4",
        0x11, Id4x10GBaseSr, "4x10GBASE-SR",
        0x12, Id40GPsm4, "40G PSM4 Parallel SMF",
        0x13, IdG959p1i12d1, "G959.1 profile P1I1-2D1",
        0x14, IdG959p1s12d2, "G959.1 profile P1S1-2D2",
        0x15, IdG9592p1l1d1, "G959.1 profile P1L1-2D2",
        0x16, Id10GBaseT, "10GBASE-T with SFI elecrical interface",
        0x17, Id100GClr4, "100G CLR4",
        0x18, Id100GAoc10en12, "100G AOC, retimed or 25GAUI C2M AOC (BER <= 10e-12)",
        0x19, Id100GAcc10en12, "100G ACC, retimed or 25GAUI C2M ACC (BER <= 10e-12)",
        0x1a, Id100GeDwdm2, "100GE-DWDM2",
        0x1b, Id100GWdm, "100G 1550nm WDM",
        0x1c, Id10GBaseTSr, "10GBASE-T Short Reach",
        0x1d, Id5GBaseT, "5GBASE-T",
        0x1e, Id2p5GBaseT, "2.5GBASE-T",
        0x1f, Id40GSwdm4, "40G SWDM4",
        0x20, Id100GSwdm4, "100G SWDM4",
        0x21, Id100GPam4BiDi, "100G PAM4 BiDi",
        0x37, Id10GBaseBr, "10GBASE-BR",
        0x38, Id25GBaseBr, "25GBASE-BR",
        0x39, Id50GBaseBr, "50GBASE-BR",
        0x22, Id4wdm10, "4WDM-10 MSA",
        0x23, Id4wdm20, "4WDM-20 MSA",
        0x24, Id4wdm40, "4WDM-40 MSA",
        0x25, Id100GBaseDr, "100GBASE-DR",
        0x26, Id100GFr, "100G-FR or 100GBASE-FR1, CAUI-4",
        0x27, Id100GLr, "100G-LR or 100GBASE-LR1, CAUI-4",
        0x28, Id100GBaseSr1, "100GBASE-SR1, CAUI-4",
        0x3a, Id100GBaseVr1, "100GBASE-VR1, CAUI-4",
        0x29, Id100GBaseSr12, "100GBASE-SR1, 200GBASE-SR2 or 400GBASE-SR4",
        0x36, Id100GBaseVr12, "100GBASE-VR1, 200GBASE-VR2 or 400GBASE-VR4",
        0x2a, Id100GBaseFr1, "100GBASE-FR1",
        0x2b, Id100GBaseLr1, "100GBASE-LR1",
        0x2c, Id100GLr120Caui4, "100G-LR1-20 MSA, CAUI-4",
        0x2d, Id100GLr130Caui4, "100G-LR1-30 MSA, CAUI-4",
        0x2e, Id100GLr140Caui4, "100G-LR1-40 MSA, CAUI-4",
        0x2f, Id100GLr120, "100G-LR1-20 MSA",
        0x34, Id100GLr130, "100G-LR1-30 MSA",
        0x35, Id100GLr140, "100G-LR1-40 MSA",
        0x30, IdAcc50GAUI10en6, "Active Copper Cable with 50GAUI, 200GAUI-2 or 200GAUI-4 C2M (BER <= 10e-6)",
        0x31, IdAcc50GAUI10en62, "Active Copper Cable with 50GAUI, 200GAUI-2 or 200GAUI-4 C2M (BER <= 10e-6)",
        0x32, IdAcc50GAUI2p6en4, "Active Copper Cable with 50GAUI, 200GAUI-2 or 200GAUI-4 C2M (BER <= 2.6e-4 or 10e-5)",
        0x33, IdAcc50GAUI2p6en41, "Active Copper Cable with 50GAUI, 200GAUI-2 or 200GAUI-4 C2M (BER <= 2.6e-4 or 10e-5)",
        0x3f, Id100GBaseCr1, "100GBASE-CR1, 200GBASE-CR2 or 400GBASE-CR4",
        0x40, Id50GBaseCr, "50GBASE-CR, 100GBASE-CR2 or 200GBASE-CR4",
        0x41, Id50GBaseSr, "50GBASE-SR, 100GBASE-SR2 or 200GBASE-SR4",
        0x42, Id50GBaseFr, "50GBASE-FR or 200GBASE-DR4",
        0x4a, Id50GBaseEr, "50GBASE-ER",
        0x43, Id200GBaseFr4, "200GBASE-FR4",
        0x44, Id200GPsm4, "200G 1550nm PSM4",
        0x45, Id50GBaseLr, "50GBASE-LR",
        0x46, Id200GBaseLr4, "200GBASE-LR4",
        0x47, Id400GBaseDr4, "400GBASE-DR4",
        0x48, Id400GBaseFr4, "400GBASE-FR4",
        0x49, Id400GBaseLr4, "400GBASE-LR4-6",
        0x4b, Id400GGLr410, "400G-LR4-10",
        0x4c, Id400GBaseZr, "400GBASE-ZR",
        0x7f, Id256GfcSw4, "256GFC-SW4",
        0x80, Id64Gfc, "64GFC",
        0x81, Id128Gfc, "128GFC",
    },
    other_variants = { Reserved : 0x0a | 0x0f | 0x3b..=0x3e | 0x4d..=0x7e | 0x82..=0xff },
}

crate::bitfield_enum! {
    name = HostElectricalInterfaceId,
    description = "The host electrical interface ID.\
    \
    See SFF-8024, table 4-5.",
    variants = {
        0x00, Undefined, "Undefined",
        0x01, Id1000BaseCX, "1000BASE-CX",
        0x02, IdXaui, "XAUI",
        0x03, IdXfi, "XFI",
        0x04, IdSfi, "SFI",
        0x05, Id25Gaui, "25GAUI C2M",
        0x06, IdXlaui, "XLAUI C2M",
        0x07, IdXlppi, "XLPPI",
        0x08, IdXlaui2, "LAUI-2 C2M",
        0x09, Id50Gaui2, "50GAUI-2 C2M",
        0x0a, Id50Gaui1, "50GAUI-1 C2M",
        0x0b, IdCaui4, "CAUI-4 C2M",
        0x41, IdCaui4WithoutFec, "CAUI-4 C2M with out FEC",
        0x42, IdCaui4WithRsFec, "CAUI-4 C2M with RS(528, 514) FEC",
        0x0c, Id100GGaui4, "100GAUI-4 C2M",
        0x0d, Id100GGaui2, "100GAUI-2 C2M",
        0x4b, Id100GGaui1S, "100GAUI-1-S C2M",
        0x4c, Id100GGaui1L, "100GAUI-1-L C2M",
        0x0e, Id200GGaui8, "200GAUI-8 C2M",
        0x0f, Id200GGaui4, "200GAUI-4 C2M",
        0x4d, Id200GGaui2S, "200GAUI-2-S C2M",
        0x4e, Id200GGaui2L, "200GAUI-2-L C2M",
        0x10, Id400Gaui16, "400GAUI-16 C2M",
        0x11, Id400Gaui8, "400GAUI-8 C2M",
        0x4f, Id400Gaui4S, "400GAUI-4-S C2M",
        0x50, Id400Gaui4L, "400GAUI-4-L C2M",
        0x51, Id800GS, "800G S C2M",
        0x52, Id800GL, "800G L C2M",
        0x13, Id10GBaseCx4, "10GBASE-CX4",
        0x14, Id25GBaseCrCa25GL, "25GBASE-CR CA-25G-L",
        0x15, Id25GBaseCrS, "25GBASE-CR or 25GBASE-CR-S CA-25G-S",
        0x16, Id25GBaseCrN, "25GBASE-CR or 25GBASE-CR-S CA-25G-N",
        0x17, Id40GBaseCr4, "40GBASE-CR4",
        0x43, Id50GBaseCr2WithRsFec, "50GBASE-CR2 with RS(528, 514) FEC",
        0x44, Id50GBaseCr2WithFirecodeFec, "50GBASE-CR2 with Firecode FEC",
        0x45, Id50GBaseCr2, "50GBASE-CR2 with no FEC",
        0x18, Id50GBaseCr, "50GBASE-CR",
        0x19, Id100GBaseCr10, "100GBASE-CR10",
        0x1a, Id100GBaseCr4, "100GBASE-CR4",
        0x1b, Id100GBaseCr2, "100GBASE-CR2",
        0x46, Id100GBaseCr1, "100GBASE-CR1",
        0x1c, Id200GBaseCr4, "200GBASE-CR4",
        0x47, Id200GBaseCr2, "200GBASE-CR2",
        0x1d, Id400GCr8, "400G CR8",
        0x48, Id400GBaseCr4, "400GBASE-CR4",
        0x49, Id800GEtcCr8, "800G-ETC-CR8",
        0xff, EndOfList, "End of list",
    },
    other_variants = {
        Reserved : 0x12 | 0x30..=0x36 | 0x54..=0xbf,
        Custom : 0xce..=0xfe,
        Other : _
    },
}

crate::bitfield_enum! {
    name = MediaType,
    description = "The encoding type for a `MediaInterfaceId`.\
    \
    This is used to determine which SFF-8024 table can be used to decode a media\
    interface type. This applies to both host- and media-side interfaces, and\
    eletrical / optical.",
    variants = {
        0x00, Undefined, "Undefined",
        0x01, MultiModeFiber, "Multi-mode fiber",
        0x02, SingleModeFiber, "Single-mode fiber",
        0x03, PassiveCopper, "Passive copper",
        0x04, ActiveCable, "Active cable",
        0x05, BaseT, "BASE-T",
    },
    other_variants = {
        Custom : 0x40..=0x8f,
        Reserved: _,
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

impl fmt::Display for MediaInterfaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MediaInterfaceId::Mmf(inner) => write!(f, "{inner} (MMF)"),
            MediaInterfaceId::Smf(inner) => write!(f, "{inner} (SMF)"),
            MediaInterfaceId::PassiveCopper(inner) => write!(f, "{inner} (Passive copper)"),
            MediaInterfaceId::ActiveCable(inner) => write!(f, "{inner} (Active cable)"),
            MediaInterfaceId::BaseT(inner) => write!(f, "{inner} (BASE-T)"),
        }
    }
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

crate::bitfield_enum! {
    name = MmfMediaInterfaceId,
    description = "Media interface ID for multi-mode fiber media.\
    \
    See SFF-8024 Table 4-6.",
    variants = {
        0x00, Undefined, "Undefined",
        0x01, Id10GBaseSw, "10GBASE-SW",
        0x02, Id10GBaseSr, "10GBASE-SR",
        0x03, Id25GBaseSr, "25GBASE-SR",
        0x04, Id40GBaseSr3, "40GBASE-SR4",
        0x05, Id40GESwdm4, "40GE SWDM4",
        0x06, Id40GEBiDi, "40GE BiDi",
        0x07, Id50GBaseSr, "50GBASE-SR",
        0x08, Id100GBaseSr10, "100GBASE-SR10",
        0x09, Id100GBaseSr4, "100GBASE-SR4",
        0x0a, Id100GBaseSwdm4, "100GE SWDM4",
        0x0b, Id100GEBiDi, "100GE BiDi",
        0x0c, Id100GBaseSr2, "100GBASE-SR2",
        0x0d, Id100GBaseSr1, "100GBASE-SR1",
        0x1d, Id100GBaseVr1, "100GBASE-VR1",
        0x0e, Id200GBaseSr4, "200GBASE-SR4",
        0x1b, Id200GBaseSr2, "200GBASE-SR2",
        0x1e, Id200GBaseVr2, "200GBASE-VR2",
        0x0f, Id400GBaseSr16, "400GBASE-SR16",
        0x10, Id400GBaseSr8, "400GBASE-SR8",
        0x11, Id400GBaseSr4, "400GBASE-SR4",
        0x1f, Id400GBaseVr4, "400GBASE-VR4",
        0x12, Id800GBaseSr8, "800GBASE-SR8",
        0x20, Id800GBaseVr8, "800GBASE-VR8",
        0x1a, Id400GBaseSr42, "400GBASE-SR4.2",
    },
    other_variants = { Reserved : _, }
}

crate::bitfield_enum! {
    name = SmfMediaInterfaceId,
    description = "Media interface ID for single-mode fiber.\
    \
    See SFF-8024 Table 4-7.",
    variants = {
        0x00, Undefined, "Undefined",
        0x01, Id10GBaseLw, "10GBASE-LW",
        0x02, Id10GBaseEw, "10GBASE-EW",
        0x03, Id10GZw, "10G-ZW",
        0x04, Id10GBaseLr, "10GBASE-LR",
        0x05, Id10GBaseEr, "10GBASE-ER",
        0x4e, Id10GBaseBr, "10GBASE-BR",
        0x06, Id10GZr, "10G-ZR",
        0x07, Id25GBaseLr, "25GBASE-LR",
        0x08, Id25GBaseEr, "25GBASE-ER",
        0x4f, Id25GBaseBr, "25GBASE-BR",
        0x09, Id40GBaseLr4, "40GBASE-LR4",
        0x0a, Id40GBaseFr, "40GBASE-FR",
        0x0b, Id50GBaseFr, "50GBASE-FR",
        0x0c, Id50GBaseLr, "50GBASE-LR",
        0x40, Id50GBaseEr, "50GBASE-ER",
        0x50, Id50GBaseBr, "50GBASE-BR",
        0x0d, Id100GBaseLr4, "100GBASE-LR4",
        0x0e, Id100GBaseEr4, "100GBASE-ER4",
        0x0f, Id100GPsm4, "100G PSM4",
        0x34, Id100GCwdm4Ocp, "100G CWDM4-OCP",
        0x10, Id100GCwdm4, "100G CWDM4",
        0x11, Id100G4wdm10, "100G 4WDM-10",
        0x12, Id100G4wdm20, "100G 4WDM-20",
        0x13, Id100G4wdm40, "100G 4WDM-40",
        0x14, Id100GBaseDr, "100GBASE-DR",
        0x15, Id100GFr, "100G-FR / 100GBASE-FR1",
        0x16, Id100GLr, "100G-LR / 100GBASE-LR1",
        0x4a, Id100GLr120, "100G-LR1-20",
        0x4b, Id100GEr130, "100G-ER1-30",
        0x4c, Id100GEr140, "100G-ER1-40",
        0x44, Id100GBaseZr, "100GBASE-ZR",
        0x17, Id200GBaseDr4, "200GBASE-DR4",
        0x18, Id200GBaseFr4, "200GBASE-FR4",
        0x19, Id200GBaseLr4, "200GBASE-LR4",
        0x41, Id200GBaseEr4, "200GBASE-ER4",
        0x1a, Id400GBaseFr8, "400GBASE-FR8",
        0x1b, Id400GBaseLr8, "400GBASE-LR8",
        0x42, Id400GBaseEr8, "400GBASE-ER8",
        0x1c, Id400GBaseDr4, "400GBASE-DR4",
        0x55, Id400GBaseDr42, "400GBASE-DR4-2",
        0x1d, Id400GFr4, "400G-FR4 / 400GBASE-FR4",
        0x43, Id400GBaseLr46, "400GBASE-LR4-6",
        0x1e, Id400GLr410, "400G-LR4-10",
        0x4d, Id400GBaseZr, "400GBASE-ZR",
        0x56, Id800GBaseDr8, "800GBASE-DR8",
        0x57, Id800GBaseDr82, "800GBASE-DR8-2",
    },
    other_variants = { Reserved : _ },
}

crate::bitfield_enum! {
    name = PassiveCopperMediaInterfaceId,
    description = "Media interface ID for passive copper cables.\
    \
    See SFF-8024 Table 4-8.",
    variants = {
        0x00, Undefined, "Undefined",
        0x01, CopperCable, "Copper cable",
        0xbf, PassiveLoopback, "Passive loopback",
    },
    other_variants = { Custom : 0xc0..=0xff, Reserved : 0x02..=0xbf },
}

crate::bitfield_enum! {
    name = ActiveCableMediaInterfaceId,
    description = "Media interface ID for active cable assemblies.\
    \
    See SFF-8024 Table 4-9.",
    variants = {
        0x00, Undefined, "Undefined",
        0x01, ActiveWithBer1en12, "Active Cable assembly with BER < 1e-12",
        0x02, ActiveWithBer5en5, "Active Cable assembly with BER < 5e-5",
        0x03, ActiveWithBer2p6en4, "Active Cable assembly with BER < 2.6e-4",
        0x04, ActiveWithBer10en6, "Active Cable assembly with BER < 10e-6",
        0xbf, ActiveLoopback, "Active loopback",
    },
    other_variants = { Reserved : 0x05..=0xbe, Custom : 0xc0..=0xff },
}

crate::bitfield_enum! {
    name = BaseTMediaInterfaceId,
    description = "Media interface ID for BASE-T.\
    \
    See SFF-8024 Table 4-10.",
    variants = {
        0x00, Undefined, "Undefined",
        0x01, Id1000BaseT, "1000BASE-T",
        0x02, Id2p5GBaseT, "2.5GBASE-T",
        0x03, Id5GBaseT, "5GBASE-T",
        0x04, Id10GBaseT, "10GBASE-T",
        0x05, Id25GBaseT, "25GBASE-T",
        0x06, Id40GBaseT, "40GBASE-T",
        0x07, Id50GBaseT, "50GBASE-T",
    },
    other_variants = { Custom: 0xc0..=0xff, Reserved: 0x08..=0xbf },
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
