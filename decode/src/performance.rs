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
pub struct SffPerformance {
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
    pub tx_force_squelches: Option<[bool; 4]>,
    pub tx_ae_freezes: Option<[bool; 4]>,
    pub tx_input_eqs: [TxInputEqualization; 4],
    pub rx_output_emphases: [RxOutputEmphasis; 4],
    pub rx_output_ampls: [RxOutputAmplitudeSupport; 4],
    pub rx_squelch_disables: [bool; 4],
    pub tx_squelch_disables: [bool; 4],
    pub rx_output_disables: [bool; 4],
    pub tx_adaptive_eq_enables: Option<[bool; 4]>,
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
    Invalid(u8),
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
            _ => Invalid(x),
        }
    }
}

impl core::fmt::Display for TxInputEqualization {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use TxInputEqualization::*;
        let tmp: String;
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
                Invalid(x) => {
                    tmp = format!("Invalid(0x{x:x})");
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
    Invalid(u8),
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
            _ => Invalid(x),
        }
    }
}

impl core::fmt::Display for RxOutputEmphasis {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use RxOutputEmphasis::*;
        let tmp: String;
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
                Invalid(x) => {
                    tmp = format!("Invalid(0x{x:x})");
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
    Invalid(u8),
}

impl From<u8> for RxOutputEmphasisType {
    fn from(x: u8) -> Self {
        use RxOutputEmphasisType::*;
        match x {
            0b00 => PkToPkOrNotImplOrNoInfo,
            0b01 => SteadyState,
            0b10 => Average,
            0b11 => Reserved,
            _ => Invalid(x),
        }
    }
}

impl core::fmt::Display for RxOutputEmphasisType {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use RxOutputEmphasisType::*;
        let tmp: String;
        write!(
            f,
            "{}",
            match self {
                PkToPkOrNotImplOrNoInfo =>
                    "Peak-to-peak amplitude stays constant, or not implemented, or no information",
                SteadyState => "Steady state amplitude stays constant",
                Average => "Average of peak-to-peak and steady state amplitude stays constant",
                Reserved => "Reserved",
                Invalid(x) => {
                    tmp = format!("Invalid(0x{x:x})");
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
    Invalid(u8),
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
            _ => Invalid(x),
        }
    }
}

impl core::fmt::Display for RxOutputAmplitudeSupport {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use RxOutputAmplitudeSupport::*;
        let tmp: String;
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
                Invalid(x) => {
                    tmp = format!("Invalid(0x{x:x})");
                    &tmp
                }
            }
        )
    }
}

// CMIS

#[derive(Clone, Debug, Default)]
pub struct CmisPerformance {
    pub loopback_support: LoopbackCapabilities,
    pub diag_meas_capability: DiagnosticMeasurementCapabilities,
    pub diag_report_capability: DiagnosticReportingCapabilities,
    pub gen_check_location: PatternGenAndCheckLocation,
    pub gen_check_data_support: PatternGenAndCheckDataSupport,
    pub gen_check_per_lane_support: PatternGenAndCheckPerLaneSupport,
    pub host_gen_support: PatternIdVec,
    pub media_gen_support: PatternIdVec,
    pub host_check_support: PatternIdVec,
    pub media_check_support: PatternIdVec,
    pub recovered_clock_for_generator: RecoveredClockForGenerator,
    pub reference_clock_for_patterns_support: bool,
    pub user_length_support: u8,
    pub host_gen_per_lane_control: PatternPerLaneControls,
    pub host_check_per_lane_control: PatternPerLaneControls,
    pub media_gen_per_lane_control: PatternPerLaneControls,
    pub media_check_per_lane_control: PatternPerLaneControls,
    pub clk_and_measurement_control: ClockingAndMeasurementControls,
    pub loopback_control: LoopbackControls,
    pub diagnostics_masks: DiagnosticsMasks,
}

/// Loopback capabilties advertisement
#[derive(Clone, Copy, Debug, Default)]
pub struct LoopbackCapabilities {
    pub simultaneous: bool,
    pub media_per_lane: bool,
    pub host_per_lane: bool,
    pub host_input: bool,
    pub host_output: bool,
    pub media_input: bool,
    pub media_output: bool,
}

/// Diagnostic measurement capabilities advertisement
#[derive(Clone, Copy, Debug, Default)]
pub struct DiagnosticMeasurementCapabilities {
    pub gating_support: GatingSupport,
    pub gating_results: bool,
    pub periodic_updates: bool,
    pub per_lane_gating: bool,
    pub auto_restart_gating: bool,
}

/// Measurement over a given time interval (gating)
#[derive(Clone, Copy, Debug, Default)]
pub enum GatingSupport {
    #[default]
    NotSupported,
    LTE2ms,  // <= 2ms
    LTE20ms, // <= 20ms
    GT20ms,  // > 20ms
    Invalid(u8),
}

impl From<u8> for GatingSupport {
    fn from(x: u8) -> GatingSupport {
        use GatingSupport::*;
        match x {
            0b00 => NotSupported,
            0b01 => LTE2ms,
            0b10 => LTE20ms,
            0b11 => GT20ms,
            _ => Invalid(x),
        }
    }
}

impl core::fmt::Display for GatingSupport {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use GatingSupport::*;
        let tmp: String;
        write!(
            f,
            "{}",
            match self {
                NotSupported => "--",
                LTE2ms => "time accuracy <= 2 ms",
                LTE20ms => "time accuracy <= 20 ms",
                GT20ms => "time accuracy > 20 ms",
                Invalid(x) => {
                    tmp = format!("Invalid(0x{x:x})");
                    &tmp
                }
            }
        )
    }
}

/// Diagnostic reporting capabilities advertisement
#[derive(Clone, Copy, Debug, Default)]
pub struct DiagnosticReportingCapabilities {
    pub media_fec: bool,
    pub host_fec: bool,
    pub media_input_snr: bool,
    pub host_input_snr: bool,
    pub bits_and_errors_counting: bool,
    pub bit_err_ratio_results: bool,
}

/// Pattern generation and checking location advertisement
#[derive(Clone, Copy, Debug, Default)]
pub struct PatternGenAndCheckLocation {
    pub media_gen_pre_fec: bool,
    pub media_gen_post_fec: bool,
    pub media_check_pre_fec: bool,
    pub media_check_post_fec: bool,
    pub host_gen_pre_fec: bool,
    pub host_gen_post_fec: bool,
    pub host_check_pre_fec: bool,
    pub host_check_post_fec: bool,
}

/// PRBS specifications for patterns
#[derive(Clone, Copy, Debug, Default)]
pub enum PatternId {
    PRBS31Q,
    PRBS31,
    PRBS23Q,
    PRBS23,
    PRBS15Q,
    PRBS15,
    PRBS13Q,
    PRBS13,
    PRBS9Q,
    PRBS9,
    PRBS7Q,
    PRBS7,
    SSPRQ,
    #[default]
    Reserved,
    Custom,
    UserPattern,
    Invalid(u8),
}

impl From<u8> for PatternId {
    fn from(x: u8) -> PatternId {
        use PatternId::*;
        match x {
            0b0000 => PRBS31Q,
            0b0001 => PRBS31,
            0b0010 => PRBS23Q,
            0b0011 => PRBS23,
            0b0100 => PRBS15Q,
            0b0101 => PRBS15,
            0b0110 => PRBS13Q,
            0b0111 => PRBS13,
            0b1000 => PRBS9Q,
            0b1001 => PRBS9,
            0b1010 => PRBS7Q,
            0b1011 => PRBS7,
            0b1100 => SSPRQ,
            0b1101 => Reserved,
            0b1110 => Custom,
            0b1111 => UserPattern,
            _ => Invalid(x),
        }
    }
}

impl core::fmt::Display for PatternId {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use PatternId::*;
        let tmp: String;
        write!(
            f,
            "{}",
            match self {
                PRBS31Q => "PRBS31Q",
                PRBS31 => "PRBS31",
                PRBS23Q => "PRBS23Q",
                PRBS23 => "PRBS23",
                PRBS15Q => "PRBS15Q",
                PRBS15 => "PRBS15",
                PRBS13Q => "PRBS13Q",
                PRBS13 => "PRBS13",
                PRBS9Q => "PRBS9Q",
                PRBS9 => "PRBS9",
                PRBS7Q => "PRBS7Q",
                PRBS7 => "PRBS7",
                SSPRQ => "SSPRQ",
                Reserved => "Reserved",
                Custom => "Custom",
                UserPattern => "UserPattern",
                Invalid(x) => {
                    tmp = format!("Invalid(0x{x:x})");
                    &tmp
                }
            }
        )
    }
}

/// Helper-type to map PatternId support into a Vec datastructure
#[derive(Clone, Debug, Default)]
pub struct PatternIdVec(pub Vec<PatternId>);

impl PatternIdVec {
    /// First byte represents patterns 7..0, second byte 15..8
    ///
    /// Pattern Ids are definied by CMIS 5.0 Table 8-93
    pub fn new(bytes: [u8; 2]) -> Self {
        let ids = u16::from_le_bytes(bytes);
        let mut new_vec = Vec::<PatternId>::new();
        for bit in 0..=15 {
            let mask: u16 = 1 << bit;
            let supported = (ids & mask) != 0;
            if supported {
                match mask {
                    0 => new_vec.push(PatternId::PRBS31Q),
                    1 => new_vec.push(PatternId::PRBS31),
                    2 => new_vec.push(PatternId::PRBS23Q),
                    3 => new_vec.push(PatternId::PRBS23),
                    4 => new_vec.push(PatternId::PRBS15Q),
                    5 => new_vec.push(PatternId::PRBS15),
                    6 => new_vec.push(PatternId::PRBS13Q),
                    7 => new_vec.push(PatternId::PRBS13),
                    8 => new_vec.push(PatternId::PRBS9Q),
                    9 => new_vec.push(PatternId::PRBS9),
                    10 => new_vec.push(PatternId::PRBS7Q),
                    11 => new_vec.push(PatternId::PRBS7),
                    12 => new_vec.push(PatternId::SSPRQ),
                    13 => new_vec.push(PatternId::Reserved),
                    14 => new_vec.push(PatternId::Custom),
                    15 => new_vec.push(PatternId::UserPattern),
                    _ => (),
                }
            }
        }
        Self(new_vec)
    }
}

/// Recovered clock for generator options
#[derive(Clone, Copy, Debug, Default)]
pub enum RecoveredClockForGenerator {
    #[default]
    NotSupported,
    WithoutLoopback,
    WithLoopback,
    WithAndWithoutLoopback,
    Invalid(u8),
}

impl From<u8> for RecoveredClockForGenerator {
    fn from(x: u8) -> RecoveredClockForGenerator {
        use RecoveredClockForGenerator::*;
        match x {
            0b00 => NotSupported,
            0b01 => WithoutLoopback,
            0b10 => WithLoopback,
            0b11 => WithAndWithoutLoopback,
            _ => Invalid(x),
        }
    }
}

impl core::fmt::Display for RecoveredClockForGenerator {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use RecoveredClockForGenerator::*;
        let tmp: String;
        write!(
            f,
            "{}",
            match self {
                NotSupported => "Not supported",
                WithoutLoopback => "Supported without loopback",
                WithLoopback => "Supported with loopback",
                WithAndWithoutLoopback => "Supported with and without loopback",
                Invalid(x) => {
                    tmp = format!("Invalid(0x{x:x})");
                    &tmp
                }
            }
        )
    }
}

/// Pattern generation and checking data swap and inversion advertisement
#[derive(Clone, Copy, Debug, Default)]
pub struct PatternGenAndCheckDataSupport {
    pub media_check_swap: bool,
    pub media_check_invert: bool,
    pub media_gen_swap: bool,
    pub media_gen_invert: bool,
    pub host_check_swap: bool,
    pub host_check_invert: bool,
    pub host_gen_swap: bool,
    pub host_gen_invert: bool,
}

/// Pattern generation and checking per-lane enable and pattern advertisement
#[derive(Clone, Copy, Debug, Default)]
pub struct PatternGenAndCheckPerLaneSupport {
    pub media_check_per_lane_enable: bool,
    pub media_check_per_lane_pattern: bool,
    pub media_gen_per_lane_enable: bool,
    pub media_gen_per_lane_pattern: bool,
    pub host_check_per_lane_enable: bool,
    pub host_check_per_lane_pattern: bool,
    pub host_gen_per_lane_enable: bool,
    pub host_gen_per_lane_pattern: bool,
}

/// Pattern generation and checker controls for both host and media
#[derive(Clone, Copy, Debug, Default)]
pub struct PatternPerLaneControls {
    pub enable: [bool; 8],
    pub invert: [bool; 8],
    pub byte_swap: [bool; 8],
    pub pre_fec_enable: [bool; 8],
    pub pattern_select: [PatternId; 8],
}

impl PatternPerLaneControls {
    /// Bytes is an slice of 8 bytes which contain the per lane pattern controls
    ///
    /// Page 13h bytes 144-151: Host side generator
    /// Page 13h bytes 152-159: Media side generator
    /// Page 13h bytes 160-167: Host side checker
    /// Page 13h bytes 168-175: Media side checker
    ///
    /// Panics if the slice does not contain 8 bytes which would occur as a
    /// programmer error.
    pub fn new(bytes: &[u8]) -> PatternPerLaneControls {
        let bytes: [u8; 8] = match bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => panic!("slice did not contain 8 bytes"),
        };
        let mut ctrl: PatternPerLaneControls = Default::default();
        for bit in 0..=7 {
            let mask = 1 << bit;
            ctrl.enable[bit] = (bytes[0] & mask) != 0;
            ctrl.invert[bit] = (bytes[1] & mask) != 0;
            ctrl.byte_swap[bit] = (bytes[2] & mask) != 0;
            ctrl.pre_fec_enable[bit] = (bytes[3] & mask) != 0;
        }

        let byte = bytes[4];
        ctrl.pattern_select[0] = (byte & 0x0f).into();
        ctrl.pattern_select[1] = (byte & 0xf0).into();

        let byte = bytes[5];
        ctrl.pattern_select[2] = (byte & 0x0f).into();
        ctrl.pattern_select[3] = (byte & 0xf0).into();

        let byte = bytes[6];
        ctrl.pattern_select[4] = (byte & 0x0f).into();
        ctrl.pattern_select[5] = (byte & 0xf0).into();

        let byte = bytes[7];
        ctrl.pattern_select[6] = (byte & 0x0f).into();
        ctrl.pattern_select[7] = (byte & 0xf0).into();

        ctrl
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ClockingAndMeasurementControls {
    pub host_prbs_gen_clk_src: HostPRBSGeneratorClockSource,
    pub media_prbs_gen_clk_src: MediaPRBSGeneratorClockSource,
    pub start_stop_is_global: bool,
    pub reset_error_information: bool,
    pub auto_restart_gating: bool,
    pub measurement_time: MeasurementGatingTime,
    pub update_period_select: UpdatePeriodSelect,
    pub host_prbs_check_clk_src: HostPRBSCheckerClockSource,
    pub media_prbs_check_clk_src: MediaPRBSCheckerClockSource,
}

/// Clock source for Host Side PRBS Pattern Generation
#[derive(Clone, Copy, Debug, Default)]
pub enum HostPRBSGeneratorClockSource {
    #[default]
    InternalClock,
    RefClkMediaLane(u8),
    Reserved(u8),
    RefClkPerMediaLaneOrDataPath,
    Invalid(u8),
}

impl From<u8> for HostPRBSGeneratorClockSource {
    fn from(x: u8) -> Self {
        use HostPRBSGeneratorClockSource::*;
        match x {
            0b0000 => InternalClock,
            0b0001..=0b1000 => RefClkMediaLane(x),
            0b1001..=0b1110 => Reserved(x),
            0b1111 => RefClkPerMediaLaneOrDataPath,
            _ => Invalid(x),
        }
    }
}

impl core::fmt::Display for HostPRBSGeneratorClockSource {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use HostPRBSGeneratorClockSource::*;
        let tmp: String;
        write!(
            f,
            "{}",
            match self {
                InternalClock => "All lanes use Internal Clock",
                RefClkMediaLane(x) => {
                    tmp = format!("All lanes use Reference Clock Media Lane {x}");
                    &tmp
                }
                Reserved(x) => {
                    tmp = format!("Reserved(0x{x:x})");
                    &tmp
                }
                RefClkPerMediaLaneOrDataPath => "Recovered clock per Media Lane or Data Path",
                Invalid(x) => {
                    tmp = format!("Invalid(0x{x:x})");
                    &tmp
                }
            }
        )
    }
}

/// Clock source for Media Side PRBS Pattern Generation
#[derive(Clone, Copy, Debug, Default)]
pub enum MediaPRBSGeneratorClockSource {
    #[default]
    InternalClock,
    RefClk,
    RefClkMediaLane(u8),
    Reserved(u8),
    RefClkPerHostLaneOrDataPath,
    Invalid(u8),
}

impl From<u8> for MediaPRBSGeneratorClockSource {
    fn from(x: u8) -> Self {
        use MediaPRBSGeneratorClockSource::*;
        match x {
            0b0000 => InternalClock,
            0b0001 => RefClk,
            0b0010..=0b1001 => RefClkMediaLane(x - 1),
            0b1010..=0b1110 => Reserved(x),
            0b1111 => RefClkPerHostLaneOrDataPath,
            _ => Invalid(x),
        }
    }
}

impl core::fmt::Display for MediaPRBSGeneratorClockSource {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use MediaPRBSGeneratorClockSource::*;
        let tmp: String;
        write!(
            f,
            "{}",
            match self {
                InternalClock => "All lanes use Internal Clock",
                RefClk => "All lanes use Reference CLock",
                RefClkMediaLane(x) => {
                    tmp = format!("All lanes use Reference Clock Host Lane {x}");
                    &tmp
                }
                Reserved(x) => {
                    tmp = format!("Reserved(0x{x:x})");
                    &tmp
                }
                RefClkPerHostLaneOrDataPath => "Recovered clock per Host Lane or Data Path",
                Invalid(x) => {
                    tmp = format!("Invalid(0x{x:x})");
                    &tmp
                }
            }
        )
    }
}

/// Measurement (gating) time for one complete result over a defined period
#[derive(Clone, Copy, Debug, Default)]
pub enum MeasurementGatingTime {
    #[default]
    Ungated,
    Gate5Sec,
    Gate10Sec,
    Gate30Sec,
    Gate60Sec,
    Gate120Sec,
    Gate300Sec,
    Custom,
    Invalid(u8),
}

impl From<u8> for MeasurementGatingTime {
    fn from(x: u8) -> Self {
        use MeasurementGatingTime::*;
        match x {
            0b000 => Ungated,
            0b001 => Gate5Sec,
            0b010 => Gate10Sec,
            0b011 => Gate30Sec,
            0b100 => Gate60Sec,
            0b101 => Gate120Sec,
            0b110 => Gate300Sec,
            0b111 => Custom,
            _ => Invalid(x),
        }
    }
}

impl core::fmt::Display for MeasurementGatingTime {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use MeasurementGatingTime::*;
        let tmp: String;
        write!(
            f,
            "{}",
            match self {
                Ungated => "Ungated, counters accrue indefinitely (infinite gate time)",
                Gate5Sec => "5 sec gate time",
                Gate10Sec => "10 sec gate time",
                Gate30Sec => "30 sec gate time",
                Gate60Sec => "60 sec gate time",
                Gate120Sec => "120 sec gate time",
                Gate300Sec => "300 sec gate time",
                Custom => "Custom",
                Invalid(x) => {
                    tmp = format!("Invalid(0x{x:x})");
                    &tmp
                }
            }
        )
    }
}

/// Time between incremental updates to intermediate error counting results during a longer gating period
#[derive(Clone, Copy, Debug, Default)]
pub enum UpdatePeriodSelect {
    #[default]
    Interval1Sec,
    Interval5Sec,
    Invalid(u8),
}

impl From<u8> for UpdatePeriodSelect {
    fn from(x: u8) -> Self {
        use UpdatePeriodSelect::*;
        match x {
            0b0 => Interval1Sec,
            0b1 => Interval5Sec,
            _ => Invalid(x),
        }
    }
}

impl core::fmt::Display for UpdatePeriodSelect {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use UpdatePeriodSelect::*;
        let tmp: String;
        write!(
            f,
            "{}",
            match self {
                Interval1Sec => "1 sec update interval",
                Interval5Sec => "5 sec update interval",
                Invalid(x) => {
                    tmp = format!("Invalid(0x{x:x})");
                    &tmp
                }
            }
        )
    }
}

/// The clock source used for the Host PRBS Pattern Checker
#[derive(Clone, Copy, Debug, Default)]
pub enum MediaPRBSCheckerClockSource {
    #[default]
    RecoveredClkFromMediaLane,
    InternalClock,
    RefClk,
    Reserved,
    Invalid(u8),
}

impl From<u8> for MediaPRBSCheckerClockSource {
    fn from(x: u8) -> Self {
        use MediaPRBSCheckerClockSource::*;
        match x {
            0b00 => RecoveredClkFromMediaLane,
            0b01 => InternalClock,
            0b10 => RefClk,
            0b11 => Reserved,
            _ => Invalid(x),
        }
    }
}

impl core::fmt::Display for MediaPRBSCheckerClockSource {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use MediaPRBSCheckerClockSource::*;
        let tmp: String;
        write!(
            f,
            "{}",
            match self {
                RecoveredClkFromMediaLane => "Recovered clocks from Media Lane/Data paths",
                InternalClock => "All lanes use Internal Clock",
                RefClk => "All lanes use Reference Clock",
                Reserved => "Reserved",
                Invalid(x) => {
                    tmp = format!("Invalid(0x{x:x})");
                    &tmp
                }
            }
        )
    }
}

/// The clock source used for the Media PRBS Pattern Checker
#[derive(Clone, Copy, Debug, Default)]
pub enum HostPRBSCheckerClockSource {
    #[default]
    RecoveredClkFromHostLane,
    InternalClock,
    RefClk,
    Reserved,
    Invalid(u8),
}

impl From<u8> for HostPRBSCheckerClockSource {
    fn from(x: u8) -> Self {
        use HostPRBSCheckerClockSource::*;
        match x {
            0b00 => RecoveredClkFromHostLane,
            0b01 => InternalClock,
            0b10 => RefClk,
            0b11 => Reserved,
            _ => Invalid(x),
        }
    }
}

impl core::fmt::Display for HostPRBSCheckerClockSource {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use HostPRBSCheckerClockSource::*;
        let tmp: String;
        write!(
            f,
            "{}",
            match self {
                RecoveredClkFromHostLane => "Recovered clocks from Host Lane/Data paths",
                InternalClock => "All lanes use Internal Clock",
                RefClk => "All lanes use Reference Clock",
                Reserved => "Reserved",
                Invalid(x) => {
                    tmp = format!("Invalid(0x{x:x})");
                    &tmp
                }
            }
        )
    }
}

/// Host and Media side loopback control
#[derive(Clone, Copy, Debug, Default)]
pub struct LoopbackControls {
    pub media_output_loopback_per_lane_enable: Option<[bool; 8]>,
    pub media_input_loopback_per_lane_enable: Option<[bool; 8]>,
    pub host_output_loopback_per_lane_enable: Option<[bool; 8]>,
    pub host_input_loopback_per_lane_enable: Option<[bool; 8]>,
}

/// Mask bits for all diagnostiscs flags
#[derive(Clone, Copy, Debug, Default)]
pub struct DiagnosticsMasks {
    pub loss_of_ref_clk_mask: bool,
    pub pattern_check_gating_complete_host: [bool; 8],
    pub pattern_check_gating_complete_media: [bool; 8],
    pub pattern_gen_lol_host: [bool; 8],
    pub pattern_gen_lol_media: [bool; 8],
    pub pattern_check_lol_host: [bool; 8],
    pub pattern_check_lol_media: [bool; 8],
}

const BIT0: u8 = 1 << 0;
const BIT1: u8 = 1 << 1;
const BIT2: u8 = 1 << 2;
const BIT3: u8 = 1 << 3;
const BIT4: u8 = 1 << 4;
const BIT5: u8 = 1 << 5;
const BIT6: u8 = 1 << 6;
const BIT7: u8 = 1 << 7;

// A common construct in the memory map is to have a bit represent state for a
// single lane, meaning all 8 lanes can be represented in a single byte. This is
// a handy function for that.
fn bool_per_lane(byte: u8) -> [bool; 8] {
    let mut a: [bool; 8] = [false; 8];
    for i in 0..=7 {
        a[i] = (byte & (1 << i)) != 0;
    }
    a
}

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
            Identifier::QsfpPlusCmis | Identifier::QsfpDD => {
                // The goal here is grabbing most of the Module Performance and
                // Diagnostics Control page as most of it is of interest. This
                // will be done with a series of reads as CMIS only allows
                // 8-byte reads.
                //
                // See CMIS rev 5.0 Table 8-66 for an overview.
                let page = cmis::Page::Upper(cmis::UpperPage::new_banked(0x13, 0x0).unwrap());

                // bytes 128->183 in 8-byte reads
                let step: u8 = 8;
                let first_block = (128..183)
                    .step_by(usize::from(step))
                    .map(|offset| MemoryRead::new(page, offset, step).unwrap());
                // bytes 184->205 are reserved or custom, so we skip them
                // bytes 206->213 in a single 8-byte read
                let second_block = MemoryRead::new(page, 206, 8);

                let mut reads = Vec::with_capacity(1);
                reads.extend(first_block);
                reads.extend(second_block);
                Ok(reads)
            }
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

                let tx_adapt_eq_freeze_supported = (byte_193 & BIT4) != 0;
                let tx_eq_auto_adapt_supported = (byte_193 & BIT3) != 0;

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
                                perf.rx_output_ampl_support[i] =
                                    if supported { Some(ampl.into()) } else { None }
                            }
                        }
                        // byte 227
                        3 => {
                            host_fec_ctrl_support = (byte & BIT7) != 0;
                            media_fec_ctrl_support = (byte & BIT6) != 0;
                            tx_force_squelch_support = (byte & BIT3) != 0;
                            perf.rxlosl_fast_mode_support = (byte & BIT2) != 0;
                            perf.txdis_fast_mode_support = (byte & BIT1) != 0;
                        }
                        // byte 228
                        4 => perf.max_tc_stable_time = if byte != 0 { Some(byte) } else { None },
                        // byte 229
                        5 => perf.max_ctle_settle_time = if byte != 0 { Some(byte) } else { None },
                        // byte 230
                        6 => {
                            perf.host_fec_enabled = if host_fec_ctrl_support {
                                Some((byte & BIT7) != 0)
                            } else {
                                None
                            };
                            perf.media_fec_enabled = if media_fec_ctrl_support {
                                Some((byte & BIT6) != 0)
                            } else {
                                None
                            }
                        }
                        // byte 231
                        7 => {
                            perf.tx_force_squelches = if tx_force_squelch_support {
                                Some([
                                    (byte & BIT0) != 0,
                                    (byte & BIT1) != 0,
                                    (byte & BIT2) != 0,
                                    (byte & BIT3) != 0,
                                ])
                            } else {
                                None
                            }
                        }
                        // byte 233
                        9 => {
                            perf.tx_ae_freezes = if tx_adapt_eq_freeze_supported {
                                Some([
                                    (byte & BIT0) != 0,
                                    (byte & BIT1) != 0,
                                    (byte & BIT2) != 0,
                                    (byte & BIT3) != 0,
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
                                (byte & BIT4) != 0,
                                (byte & BIT5) != 0,
                                (byte & BIT6) != 0,
                                (byte & BIT7) != 0,
                            ];
                            perf.tx_squelch_disables = [
                                (byte & BIT0) != 0,
                                (byte & BIT1) != 0,
                                (byte & BIT2) != 0,
                                (byte & BIT3) != 0,
                            ];
                        }
                        // byte 241
                        17 => {
                            perf.rx_output_disables = [
                                (byte & BIT4) != 0,
                                (byte & BIT5) != 0,
                                (byte & BIT6) != 0,
                                (byte & BIT7) != 0,
                            ];
                            perf.tx_adaptive_eq_enables = if tx_eq_auto_adapt_supported {
                                Some([
                                    (byte & BIT0) != 0,
                                    (byte & BIT1) != 0,
                                    (byte & BIT2) != 0,
                                    (byte & BIT3) != 0,
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
            Identifier::QsfpPlusCmis | Identifier::QsfpDD => {
                // We do a number of reads to get all the bytes we intend to
                // decode here and they don't fall nicely into 8-byte groups,
                // so before we start the decode we unpack them into a single
                // structure
                let mut bytes: Vec<u8> = Vec::new();
                for read in reads {
                    for byte in read {
                        bytes.push(*byte);
                    }
                }

                let mut perf: CmisPerformance = Default::default();

                // byte 128
                let byte = bytes[0];
                perf.loopback_support.simultaneous = (byte & BIT6) != 0;
                perf.loopback_support.media_per_lane = (byte & BIT5) != 0;
                perf.loopback_support.host_per_lane = (byte & BIT4) != 0;
                perf.loopback_support.host_input = (byte & BIT3) != 0;
                perf.loopback_support.host_output = (byte & BIT2) != 0;
                perf.loopback_support.media_input = (byte & BIT1) != 0;
                perf.loopback_support.media_output = (byte & BIT0) != 0;

                // byte 129
                let byte = bytes[1];
                perf.diag_meas_capability.gating_support = (byte >> 6).into();
                perf.diag_meas_capability.gating_results = (byte & BIT5) != 0;
                perf.diag_meas_capability.periodic_updates = (byte & BIT4) != 0;
                perf.diag_meas_capability.per_lane_gating = (byte & BIT3) != 0;
                perf.diag_meas_capability.auto_restart_gating = (byte & BIT2) != 0;

                // byte 130
                let byte = bytes[2];
                perf.diag_report_capability.media_fec = (byte & BIT7) != 0;
                perf.diag_report_capability.host_fec = (byte & BIT6) != 0;
                perf.diag_report_capability.media_input_snr = (byte & BIT5) != 0;
                perf.diag_report_capability.host_input_snr = (byte & BIT4) != 0;
                perf.diag_report_capability.bits_and_errors_counting = (byte & BIT1) != 0;
                perf.diag_report_capability.bit_err_ratio_results = (byte & BIT0) != 0;

                // byte 131
                let byte = bytes[3];
                perf.gen_check_location.media_gen_pre_fec = (byte & BIT7) != 0;
                perf.gen_check_location.media_gen_post_fec = (byte & BIT6) != 0;
                perf.gen_check_location.media_check_pre_fec = (byte & BIT5) != 0;
                perf.gen_check_location.media_check_post_fec = (byte & BIT4) != 0;
                perf.gen_check_location.host_gen_pre_fec = (byte & BIT3) != 0;
                perf.gen_check_location.host_gen_post_fec = (byte & BIT2) != 0;
                perf.gen_check_location.host_check_pre_fec = (byte & BIT1) != 0;
                perf.gen_check_location.host_check_post_fec = (byte & BIT0) != 0;

                // bytes 132 & 133
                perf.host_gen_support = PatternIdVec::new([bytes[4], bytes[5]]);
                // bytes 134 & 135
                perf.media_gen_support = PatternIdVec::new([bytes[6], bytes[7]]);
                // bytes 136 & 137
                perf.host_check_support = PatternIdVec::new([bytes[8], bytes[9]]);
                // bytes 138 & 139
                perf.media_check_support = PatternIdVec::new([bytes[10], bytes[11]]);

                // byte 140
                let byte = bytes[12];
                perf.recovered_clock_for_generator = (byte >> 6).into();
                perf.reference_clock_for_patterns_support = (byte & BIT5) != 0;
                perf.user_length_support = 2 * ((byte & 0x0f) + 1);

                // byte 141
                let byte = bytes[13];
                perf.gen_check_data_support.media_check_swap = (byte & BIT7) != 0;
                perf.gen_check_data_support.media_check_invert = (byte & BIT6) != 0;
                perf.gen_check_data_support.media_gen_swap = (byte & BIT5) != 0;
                perf.gen_check_data_support.media_gen_invert = (byte & BIT4) != 0;
                perf.gen_check_data_support.host_check_swap = (byte & BIT3) != 0;
                perf.gen_check_data_support.host_check_invert = (byte & BIT2) != 0;
                perf.gen_check_data_support.host_gen_swap = (byte & BIT1) != 0;
                perf.gen_check_data_support.host_gen_invert = (byte & BIT0) != 0;

                // byte 142
                let byte = bytes[14];
                perf.gen_check_per_lane_support.media_check_per_lane_enable = (byte & BIT7) != 0;
                perf.gen_check_per_lane_support.media_check_per_lane_pattern = (byte & BIT6) != 0;
                perf.gen_check_per_lane_support.media_gen_per_lane_enable = (byte & BIT5) != 0;
                perf.gen_check_per_lane_support.media_gen_per_lane_pattern = (byte & BIT4) != 0;
                perf.gen_check_per_lane_support.host_check_per_lane_enable = (byte & BIT3) != 0;
                perf.gen_check_per_lane_support.host_check_per_lane_pattern = (byte & BIT2) != 0;
                perf.gen_check_per_lane_support.host_gen_per_lane_enable = (byte & BIT1) != 0;
                perf.gen_check_per_lane_support.host_gen_per_lane_pattern = (byte & BIT0) != 0;

                // byte 143 is reserved, skip it

                // bytes 144-151
                perf.host_gen_per_lane_control = PatternPerLaneControls::new(&bytes[16..=23]);

                // bytes 152-159
                perf.media_gen_per_lane_control = PatternPerLaneControls::new(&bytes[24..=31]);

                // bytes 160-167
                perf.host_check_per_lane_control = PatternPerLaneControls::new(&bytes[32..=39]);

                // bytes 168-175
                perf.media_check_per_lane_control = PatternPerLaneControls::new(&bytes[40..=47]);

                // byte 176
                let byte = bytes[48];
                perf.clk_and_measurement_control.host_prbs_gen_clk_src =
                    ((byte & 0xf0) >> 4).into();
                perf.clk_and_measurement_control.media_prbs_gen_clk_src = (byte & 0x0f).into();

                // byte 177
                let byte = bytes[49];
                perf.clk_and_measurement_control.start_stop_is_global = (byte & BIT7) != 0;
                perf.clk_and_measurement_control.reset_error_information = (byte & BIT5) != 0;
                perf.clk_and_measurement_control.auto_restart_gating = (byte & BIT4) != 0;
                perf.clk_and_measurement_control.measurement_time =
                    (byte & (BIT3 | BIT2 | BIT1)).into();
                perf.clk_and_measurement_control.update_period_select = (byte & BIT0).into();

                // byte 178
                let byte = bytes[50];
                perf.clk_and_measurement_control.host_prbs_check_clk_src =
                    (byte & (BIT3 | BIT2)).into();
                perf.clk_and_measurement_control.media_prbs_check_clk_src =
                    (byte & (BIT1 | BIT0)).into();

                // byte 179 is reserved, skip it

                // byte 180
                perf.loopback_control.media_output_loopback_per_lane_enable =
                    match perf.loopback_support.media_output {
                        true => Some(bool_per_lane(bytes[52])),
                        false => None,
                    };

                // byte 181
                perf.loopback_control.media_input_loopback_per_lane_enable =
                    match perf.loopback_support.media_input {
                        true => Some(bool_per_lane(bytes[53])),
                        false => None,
                    };

                // byte 182
                perf.loopback_control.host_output_loopback_per_lane_enable =
                    match perf.loopback_support.host_output {
                        true => Some(bool_per_lane(bytes[54])),
                        false => None,
                    };

                // byte 183
                perf.loopback_control.host_input_loopback_per_lane_enable =
                    match perf.loopback_support.host_input {
                        true => Some(bool_per_lane(bytes[55])),
                        false => None,
                    };

                // The reads used to created the bytes buffer now jump to byte
                // 206.
                let byte = bytes[56];
                perf.diagnostics_masks.loss_of_ref_clk_mask = (byte & BIT7) != 0;

                // byte 207 is reserved, skip it

                // byte 208
                let byte = bytes[58];
                for i in 0..=7 {
                    perf.diagnostics_masks.pattern_check_gating_complete_host[i] =
                        (byte & (1 << i)) != 0;
                }

                // byte 209
                let byte = bytes[59];
                for i in 0..=7 {
                    perf.diagnostics_masks.pattern_check_gating_complete_media[i] =
                        (byte & (1 << i)) != 0;
                }

                // byte 210
                let byte = bytes[60];
                for i in 0..=7 {
                    perf.diagnostics_masks.pattern_check_lol_host[i] = (byte & (1 << i)) != 0;
                }

                // byte 211
                let byte = bytes[61];
                for i in 0..=7 {
                    perf.diagnostics_masks.pattern_check_lol_media[i] = (byte & (1 << i)) != 0;
                }

                // byte 212
                let byte = bytes[62];
                for i in 0..=7 {
                    perf.diagnostics_masks.pattern_gen_lol_host[i] = (byte & (1 << i)) != 0;
                }

                // byte 213
                let byte = bytes[63];
                for i in 0..=7 {
                    perf.diagnostics_masks.pattern_gen_lol_media[i] = (byte & (1 << i)) != 0;
                }

                Ok(Self {
                    sff: None,
                    cmis: Some(perf),
                })
            }
            _ => Err(Error::UnsupportedIdentifier(id)),
        }
    }
}
