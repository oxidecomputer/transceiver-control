// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Decoding of transceiver performance diagnostics control and results

use crate::Error;
use crate::Identifier;
use crate::ParseFromModule;
use transceiver_messages::mgmt::cmis;
use transceiver_messages::mgmt::sff8636;
pub use transceiver_messages::mgmt::ManagementInterface;
use transceiver_messages::mgmt::MemoryRead;

#[derive(Clone, Debug, Default)]
pub struct Performance {
    pub sff: Option<SffPerformance>,
    pub cmis: Option<CmisPerformance>,
}

// SFF-8636

#[derive(Clone, Debug, Default)]
pub struct SffPerformance<'a> {
    pub max_tx_input_eq: TxInputEqualization,
    pub max_rx_output_emphasis: RxOutputEmphasis,
    pub rx_output_emphasis_type: RxOutputEmphasisType,
    pub rx_output_ampl_support: [Option<RxOutputAmplitudeSupport>; 4],
    pub rxlosl_fast_mode_support: bool,
    pub txdis_fast_mode_support: bool,
    pub max_tc_stable_time: Option<u8>,
    pub max_ctle_settle_time: Option<u8>,
    pub host_fec_enabled: Option<bool>,
    pub media_fec_enabled: Option<bool>,
    pub tx_force_squelches: Option<&'a[bool; 4]>,
    pub tx_ae_freezes: Option<&'a[bool; 4]>,
    pub tx_input_eqs: [TxInputEqualization; 4],
    pub rx_output_emphases: [RxOutputEmphasis; 4],
    pub rx_output_ampls: [RxOutputAmplitudeSupport; 4],
    pub rx_squelch_disables: [bool; 4],
    pub tx_squelch_disables: [bool; 4],
    pub rx_output_disables: [bool; 4],
    pub tx_adaptive_eq_enables: Option<&'a[bool; 4]>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum TxInputEqualization {
    #[default]
    NoEq,
    OneDb,
    TwoDb,
    ThreeDb,
    FourDb,
    FiveDb,
    SixDb,
    SevenDb,
    EightDb,
    NineDb,
    TenDb,
    Reserved(u8),
    Unsupported(u8),
}

impl From<u8> for TxInputEqualization {
    fn from(x: u8) -> Self {
        use TxInputEqualization::*;
        match x {
            0b0000 => NoEq,
            0b0001 => OneDb,
            0b0010 => TwoDb,
            0b0011 => ThreeDb,
            0b0100 => FourDb,
            0b0101 => FiveDb,
            0b0110 => SixDb,
            0b0111 => SevenDb,
            0b1000 => EightDb,
            0b1001 => NineDb,
            0b1010 => TenDb,
            0b1011..=0b1111 => Reserved(x),
            _ => Unsupported(x),
        }
    }
}

impl core::fmt::Display for TxInputEqualization {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use TxInputEqualization::*;
        let tmp;
        write!(
            f,
            "{}",
            match self {
                NoEq => "No equalization",
                OneDb => "1 dB",
                TwoDb => "2 dB",
                ThreeDb => "3 dB",
                FourDb => "4 dB",
                FiveDb => "5 dB",
                SixDb => "6 dB",
                SevenDb => "7 dB",
                EightDb => "8 dB",
                NineDb => "9 dB",
                TenDb => "10 dB",
                Reserved(x) => {
                    tmp = format!("Reserved(0x{x:x})");
                    &tmp
                }
                Unsupported(x) => {
                    tmp = format!("Unsupported(0x{x:x})");
                    &tmp
                }
            }
        )
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum RxOutputEmphasis {
    #[default]
    NoEmphasis,
    OneDb,
    TwoDb,
    ThreeDb,
    FourDb,
    FiveDb,
    SixDb,
    SevenDb,
    Reserved(u8),
    Unsupported(u8),
}

impl From<u8> for RxOutputEmphasis {
    fn from(x: u8) -> Self {
        use RxOutputEmphasis::*;
        match x {
            0b0000 => NoEmphasis,
            0b0001 => OneDb,
            0b0010 => TwoDb,
            0b0011 => ThreeDb,
            0b0100 => FourDb,
            0b0101 => FiveDb,
            0b0110 => SixDb,
            0b0111 => SevenDb,
            0b1000..=0b1111 => Reserved(x),
            _ => Unsupported(x),
        }
    }
}

impl core::fmt::Display for RxOutputEmphasis {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use RxOutputEmphasis::*;
        let tmp;
        write!(
            f,
            "{}",
            match self {
                NoEmphasis => "No emphasis",
                OneDb => "1 dB",
                TwoDb => "2 dB",
                ThreeDb => "3 dB",
                FourDb => "4 dB",
                FiveDb => "5 dB",
                SixDb => "6 dB",
                SevenDb => "7 dB",
                Reserved(x) => {
                    tmp = format!("Reserved(0x{x:x})");
                    &tmp
                }
                Unsupported(x) => {
                    tmp = format!("Unsupported(0x{x:x})");
                    &tmp
                }
            }
        )
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub enum RxOutputEmphasisType {
    #[default]
    PkToPkOrNotImplOrNoInfo,
    SteadyState,
    Average,
    Reserved,
    Unsupported(u8),
}

impl From<u8> for RxOutputEmphasisType {
    fn from(x: u8) -> Self {
        use RxOutputEmphasisType::*;
        match x {
            0b00 => PkToPkOrNotImplOrNoInfo,
            0b01 => SteadyState,
            0b10 => Average,
            0b11 => Reserved,
            _ => Unsupported(x),
        }
    }
}

impl core::fmt::Display for RxOutputEmphasisType {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use RxOutputEmphasisType::*;
        let tmp;
        write!(
            f,
            "{}",
            match self {
                PkToPkOrNotImplOrNoInfo =>
                    "Peak-to-peak amplitude stays constant, or not implemented, or no information",
                SteadyState => "Steady state amplitude stays constant",
                Average => "Average of peak-to-peak and steady state amplitude stays constant",
                Reserved => "Reserved",
                Unsupported(x) => {
                    tmp = format!("Unsupported(0x{x:x})");
                    &tmp
                }
            }
        )
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub enum RxOutputAmplitudeSupport {
    #[default]
    OneToFourHundred,
    ThreeToSixHundred,
    FourToEightHundred,
    SixToTwelveHundred,
    Reserved(u8),
    Unsupported(u8),
}

impl From<u8> for RxOutputAmplitudeSupport {
    fn from(x: u8) -> Self {
        use RxOutputAmplitudeSupport::*;
        match x {
            0b0000 => OneToFourHundred,
            0b0001 => ThreeToSixHundred,
            0b0010 => FourToEightHundred,
            0b0011 => SixToTwelveHundred,
            0b0100..=0b1111 => Reserved(x),
            _ => Unsupported(x),
        }
    }
}

impl core::fmt::Display for RxOutputAmplitudeSupport {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use RxOutputAmplitudeSupport::*;
        let tmp;
        write!(
            f,
            "{}",
            match self {
                OneToFourHundred => "100-400 mV(p-p)",
                ThreeToSixHundred => "300-600 mV(p-p)",
                FourToEightHundred => "400-800 mV(p-p)",
                SixToTwelveHundred => "600-1200 mV(p-p)",
                Reserved(x) => {
                    tmp = format!("Reserved(0x{x:x})");
                    &tmp
                }
                Unsupported(x) => {
                    tmp = format!("Unsupported(0x{x:x})");
                    &tmp
                }
            }
        )
    }
}

// CMIS

#[derive(Clone, Debug, Default)]
pub struct CmisPerformance {}
/// Description of transceiver performance diagnostics control
// #[derive(Clone, Copy, Debug, PartialEq)]
// pub struct PerfDiagControl {
//     pub loopback_capability: LoopbackCapabilities,
//     pub diagnostic_measurement: DiagnosticMeasurementCapabilities,
//     pub diagnostic_reporting: DiagnosticReportingCapabilities,
//     pub pattern_location: PatternGenAndCheckLocation,
// }

// /// Loopback capabilties advertisement
// pub struct LoopbackCapabilities {
//     pub simultaneous: bool,
//     pub media_per_lane: bool,
//     pub host_per_lane: bool,
//     pub host_input: bool,
//     pub host_output: bool,
//     pub media_input: bool,
//     pub media_output: bool,
// }

// /// Diagnostic measurement capabilities advertisement
// pub struct DiagnosticMeasurementCapabilities {
//     pub gating: GatingSupport,
//     pub gating_results: bool,
//     pub periodic_updates: bool,
//     pub per_lane_gating: bool,
//     pub auto_restart_gating: bool,
// }

// /// Measurement over a given time interval (gating)
// pub enum GatingSupport {
//     NotSupported = 0b00,
//     LTE2ms = 0b01, // <= 2ms
//     LTE20ms = 0b10, // <= 20ms
//     GT20ms = 0b11, // > 20ms
// }

// /// Diagnostic reporting capabilities advertisement
// pub struct DiagnosticReportingCapabilities {
//     pub media_fec: bool,
//     pub host_fec: bool,
//     pub media_input_snr: bool,
//     pub host_input_snr: bool,
//     pub bits_and_errors_counting: bool,
//     pub bit_err_ratio_results: bool,
// }

// /// Pattern generation and checking location advertisement
// pub struct PatternGenAndCheckLocation {
//     pub media_gen_pre_fec: bool,
//     pub media_gen_post_fec: bool,
//     pub media_check_pre_fec: bool,
//     pub media_check_post_fec: bool,
//     pub host_gen_pre_fec: bool,
//     pub host_gen_post_fec: bool,
//     pub host_check_pre_fec: bool,
//     pub host_check_post_fec: bool,
// }

// /// Pattern generation capabilities advertisement
// pub struct PatternSupport {
//     pub host_gen: Vec<PatternId>,
//     pub media_gen: Vec<PatternId>,
//     pub host_check: Vec<PatternId>,
//     pub media_check: Vec<PatternId>,
// }

// /// PRBS specifications for patterns
// pub enum PatternId {
//     Prbs31Q = 0,
//     Prbs31 = 1,
//     Prbs23Q = 2,
//     Prbs23 = 3,
//     Prbs15Q = 4,
//     Prbs15 = 5,
//     Prbs13Q = 6,
//     Prbs13 = 7,
//     Prbs9Q = 8,
//     Prbs9 = 9,
//     Prbs7Q = 10,
//     Prbs7 = 11,
//     SsprQ = 12,
//     Reserved = 13,
//     Custom = 14,
//     UserPattern = 15,
// }

impl ParseFromModule for Performance {
    fn reads(id: Identifier) -> Result<Vec<MemoryRead>, Error> {
        match id {
            Identifier::QsfpPlusSff8636 | Identifier::Qsfp28 => {
                // Begin by checking a couple of Option Values we care about
                //
                // See SFF-8636 rev 2.11 Table 6-22
                let page = sff8636::Page::Upper(sff8636::UpperPage::new(0).unwrap());
                let support = MemoryRead::new(page, 193, 1).unwrap();

                // Next, we will grab all the Optional Equalizer, Emphasis, and
                // Amplitude Indicators, as well as the Optional Channel
                // Controls
                //
                // See SFF-8636 rev 2.11 Table 6-29 and Table 6-30
                let page = sff8636::Page::Upper(sff8636::UpperPage::new(3).unwrap());
                let bulk = MemoryRead::new(page, 224, 18).unwrap();

                let mut reads = Vec::with_capacity(2);
                reads.push(support);
                reads.push(bulk);
                Ok(reads)
            }
            // Identifier::QsfpPlusCmis | Identifier::QsfpDD => {

            // }
            _ => Err(Error::UnsupportedIdentifier(id)),
        }
    }

    fn parse<'a>(id: Identifier, mut reads: impl Iterator<Item = &'a [u8]>) -> Result<Self, Error> {
        match id {
            Identifier::QsfpPlusSff8636 | Identifier::Qsfp28 => {
                // Expect first read to be page 0h, byte 193
                let byte_193 = reads
                    .next()
                    .ok_or(Error::ParseFailed)?
                    .first()
                    .ok_or(Error::ParseFailed)?;

                let tx_adapt_eq_freeze_supported = (byte_193 & 0x10) != 0;
                let tx_eq_auto_adapt_supported = (byte_193 & 0x08) != 0;

                let mut perf: SffPerformance = Default::default();

                // Expect second read to be page 3h, byte 224-241
                let bytes = reads.next().ok_or(Error::ParseFailed)?;

                // initialize support bits to be filled in by byte 227 below
                let mut host_fec_ctrl_support = false;
                let mut media_fec_ctrl_support = false;
                let mut tx_force_squelch_support = false;

                for idx in 0..18 {
                    let byte = bytes[idx];
                    match idx {
                        // byte 224
                        0 => {
                            perf.max_tx_input_eq = (byte >> 4).into();
                            perf.max_rx_output_emphasis = (byte & 0x0f).into();
                        }
                        // byte 225
                        1 => {
                            perf.rx_output_emphasis_type = ((byte & 0x30) >> 6).into();
                            for i in 0..4 {
                                let ampl = byte & i as u8;
                                let supported = ampl != 0;
                                perf.rx_output_ampl_support[i] = if supported {
                                    Some(ampl.into())
                                } else {
                                    None
                                }
                            }
                        }
                        // byte 227
                        3 => {
                            host_fec_ctrl_support = (byte & 0x80) != 0;
                            media_fec_ctrl_support = (byte & 0x40) != 0;
                            tx_force_squelch_support = (byte & 0x08) != 0;
                            perf.rxlosl_fast_mode_support = (byte & 0x04) != 0;
                            perf.txdis_fast_mode_support = (byte & 0x02) != 0;
                        }
                        // byte 228
                        4 => perf.max_tc_stable_time = if byte != 0 { Some(byte) } else { None },
                        // byte 229
                        5 => perf.max_ctle_settle_time = if byte != 0 { Some(byte) } else { None },
                        // byte 230
                        6 => {
                            perf.host_fec_enabled = if host_fec_ctrl_support {
                                Some((byte & 0x80) != 0)
                            } else {
                                None
                            };
                            perf.media_fec_enabled = if media_fec_ctrl_support {
                                Some((byte & 0x40) != 0)
                            } else {
                                None
                            }
                        }
                        // byte 231
                        7 => {
                            perf.tx_force_squelches = if tx_force_squelch_support {
                                Some([
                                    (byte & 0x01) != 0,
                                    (byte & 0x02) != 0,
                                    (byte & 0x04) != 0,
                                    (byte & 0x08) != 0,
                                ])
                            } else {
                                None
                            }
                        }
                        // byte 233
                        9 => {
                            perf.tx_ae_freezes = if tx_adapt_eq_freeze_supported {
                                Some([
                                    (byte & 0x01) != 0,
                                    (byte & 0x02) != 0,
                                    (byte & 0x04) != 0,
                                    (byte & 0x08) != 0,
                                ])
                            } else {
                                None
                            }
                        }
                        // byte 234
                        10 => {
                            perf.tx_input_eqs[0] = (byte >> 4).into();
                            perf.tx_input_eqs[1] = (byte & 0x0f).into();
                        }
                        // byte 235
                        11 => {
                            perf.tx_input_eqs[2] = (byte >> 4).into();
                            perf.tx_input_eqs[3] = (byte & 0x0f).into();
                        }
                        // byte 236
                        12 => {
                            perf.rx_output_emphases[0] = (byte >> 4).into();
                            perf.rx_output_emphases[1] = (byte & 0x0f).into();
                        }
                        // byte 237
                        13 => {
                            perf.rx_output_emphases[2] = (byte >> 4).into();
                            perf.rx_output_emphases[3] = (byte & 0x0f).into();
                        }
                        // byte 238
                        14 => {
                            perf.rx_output_ampls[0] = (byte >> 4).into();
                            perf.rx_output_ampls[1] = (byte & 0x0f).into();
                        }
                        // byte 239
                        15 => {
                            perf.rx_output_ampls[2] = (byte >> 4).into();
                            perf.rx_output_ampls[3] = (byte & 0x0f).into();
                        }
                        // byte 240
                        16 => {
                            perf.rx_squelch_disables = [
                                (byte & 0x10) != 0,
                                (byte & 0x20) != 0,
                                (byte & 0x40) != 0,
                                (byte & 0x80) != 0,
                            ];
                            perf.tx_squelch_disables = [
                                (byte & 0x01) != 0,
                                (byte & 0x02) != 0,
                                (byte & 0x04) != 0,
                                (byte & 0x08) != 0,
                            ];
                        }
                        // byte 241
                        17 => {
                            perf.rx_output_disables = [
                                (byte & 0x10) != 0,
                                (byte & 0x20) != 0,
                                (byte & 0x40) != 0,
                                (byte & 0x80) != 0,
                            ];
                            perf.tx_adaptive_eq_enables = if tx_eq_auto_adapt_supported {
                                Some([
                                    (byte & 0x01) != 0,
                                    (byte & 0x02) != 0,
                                    (byte & 0x04) != 0,
                                    (byte & 0x08) != 0,
                                ])
                            } else {
                                None
                            };
                        }
                        // skip bytes 226 (index 2) and 232 (index 8) as they are reserved
                        _ => (),
                    }
                }
                Ok(Self {
                    sff: Some(perf),
                    cmis: None,
                })
            }
            _ => Err(Error::UnsupportedIdentifier(id)),
        }
    }
}
