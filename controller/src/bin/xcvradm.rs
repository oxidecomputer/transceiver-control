// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Command-line tool to administer optical transceivers.

use anyhow::ensure;
use anyhow::Context;
use clap::ArgGroup;
use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;
use slog::Drain;
use slog::Level;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::stdin;
use std::io::Read;
use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::time::Duration;
use tabled::builder::Builder;
use tabled::settings::Style;
use tokio::sync::mpsc;
use transceiver_controller::Config;
use transceiver_controller::Controller;
use transceiver_controller::DatapathResult;
use transceiver_controller::ExtendedStatusResult;
use transceiver_controller::FailedModules;
use transceiver_controller::IdentifierResult;
use transceiver_controller::LargeMemoryAccess;
use transceiver_controller::LedStateResult;
use transceiver_controller::MemoryModelResult;
use transceiver_controller::MonitorResult;
use transceiver_controller::PowerModeResult;
use transceiver_controller::PowerState;
use transceiver_controller::ReadResult;
use transceiver_controller::SpRequest;
use transceiver_controller::VendorInfoResult;
use transceiver_decode::Aux1Monitor;
use transceiver_decode::Aux2Monitor;
use transceiver_decode::Aux3Monitor;
use transceiver_decode::CmisLaneStatus;
use transceiver_decode::ConnectorType;
use transceiver_decode::Datapath;
use transceiver_decode::ReceiverPower;
use transceiver_decode::Sff8636Datapath;
use transceiver_decode::SffComplianceCode;
use transceiver_messages::filter_module_data;
use transceiver_messages::mac::MacAddrs;
use transceiver_messages::message::ExtendedStatus;
use transceiver_messages::message::LedState;
use transceiver_messages::message::Status;
use transceiver_messages::mgmt::cmis;
use transceiver_messages::mgmt::sff8636;
use transceiver_messages::mgmt::ManagementInterface;
use transceiver_messages::mgmt::MemoryRead;
use transceiver_messages::mgmt::MemoryWrite;
use transceiver_messages::ModuleId;

fn parse_log_level(s: &str) -> Result<Level, String> {
    s.parse().map_err(|_| String::from("invalid log level"))
}

// Method for addressing a set of transceivers by index or state.
#[derive(Clone, Debug, PartialEq)]
enum Transceivers {
    // All transceivers on a Sidecar, the default.
    All,
    // All present transceivers on a Sidecar.
    Present,
    // All transceivers in a specific power state.
    PowerState(PowerState),
    // All transceivers of a specific kind.
    Kind(ManagementInterface),
    // A comma-separated list of transceiver indices. These can be specified as
    // single integers, e.g., `4,5,6` or an inclusive range, e.g., `4-6`.
    Index(ModuleId),
}

fn parse_transceivers(s: &str) -> Result<Transceivers, String> {
    let s = s.to_lowercase();
    match s.as_str() {
        "all" => Ok(Transceivers::All),
        "present" => Ok(Transceivers::Present),
        "off" => Ok(Transceivers::PowerState(PowerState::Off)),
        "low-power" | "lp" => Ok(Transceivers::PowerState(PowerState::Low)),
        "hi-power" | "high-power" | "hp" => Ok(Transceivers::PowerState(PowerState::High)),
        "sff" => Ok(Transceivers::Kind(ManagementInterface::Sff8636)),
        "cmis" => Ok(Transceivers::Kind(ManagementInterface::Cmis)),
        _maybe_list => {
            let parts = s.split(',').map(|p| p.trim());
            let mut indices: Vec<u8> = Vec::new();
            for part in parts {
                // Try to convert to a simple index first.
                if let Ok(ix) = part.parse() {
                    indices.push(ix);
                    continue;
                }

                // Check for a range, e.g., `x-y`.
                if let Some((start, end)) = part.split_once('-') {
                    if start.is_empty() || end.is_empty() {
                        return Err(String::from("transceiver ranges must include both bounds"));
                    }
                    match (start.trim().parse::<u8>(), end.trim().parse::<u8>()) {
                        (Ok(x), Ok(y)) => {
                            if x >= y {
                                return Err(String::from("transceiver ranges must be increasing"));
                            }
                            indices.extend(x..=y);
                        }
                        _ => {
                            return Err(String::from("transceiver ranges must have integer bounds"))
                        }
                    }
                    continue;
                }

                return Err(format!(
                    "invalid transceiver list: '{s}', \
                    transceivers must be specified as a \
                    comma-separated list of integers or ranges, \
                    e.g., '0-3'"
                ));
            }
            ModuleId::from_indices(&indices)
                .map(Transceivers::Index)
                .map_err(|e| format!("invalid port indices: {e:?}"))
        }
    }
}

/// Administer optical network transceiver modules.
///
/// This tool communicates with the SP on an attached Sidecar to query and
/// control the optical transceivers attached to its front IO board.
#[derive(Parser)]
#[command(version, about, long_about)]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,

    /// The list of transcievers on the Sidecar to address.
    ///
    /// Transceivers may be addressed in a number of ways:
    ///
    /// - "all" addresses all transceivers on the Sidecar. This is the default.
    ///
    /// - "present" addresses all present transceivers on the Sidecar.
    ///
    /// - "off", "low-power", "hi-power" address the transceivers in the given
    ///   power mode.
    ///
    /// - "cmis" and "sff" address all transceivers of the provided management
    ///   interface.
    ///
    /// - A comma-separated list of integers or integer ranges. E.g., `0,1,2` or
    ///   `0-2,4`. Ranges are inclusive of both ends.
    #[arg(short, long, value_parser = parse_transceivers)]
    transceivers: Option<Transceivers>,

    /// The source IP address on which to listen for messages.
    #[arg(short, long, default_value_t = Ipv6Addr::UNSPECIFIED)]
    address: Ipv6Addr,

    /// The source interface on which to listen for messages.
    #[arg(short, long)]
    interface: String,

    /// The source UDP port from which to send messages.
    #[arg(short = 'P', long, default_value_t = 0)]
    port: u16,

    /// The unicast peer address to assume.
    ///
    /// The protocol is normally run using a multicast address, but a single
    /// peer may optionally be specified.
    #[arg(short, long)]
    peer: Option<Ipv6Addr>,

    /// The destination UDP port to which to send messages.
    #[arg(long, default_value_t = transceiver_messages::PORT)]
    peer_port: u16,

    /// The maximum number of retries before failing a request.
    #[arg(short, long)]
    n_retries: Option<usize>,

    /// The retry interval for requests, in milliseconds.
    #[arg(
        short,
        long,
        default_value_t = 1000,
        value_parser = clap::value_parser!(u64).range(1..=10000)
    )]
    retry_interval: u64,

    /// The log-level.
    #[arg(
        short,
        long,
        default_value_t = Level::Info,
        value_parser = parse_log_level
    )]
    log_level: Level,

    /// Do not print error messages.
    ///
    /// When any module fails the command, the normal opration is to print the
    /// module index along with the reason for failure on the standard error
    /// stream. This suppresses printing these messages.
    #[arg(short = 'E', long, default_value_t = false)]
    ignore_errors: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum InputKind {
    /// Input is raw binary data.
    Binary,
    /// Input is decimal text, space-delimited.
    Decimal,
    /// Input is hexadecimal text, with or without a leading `0x`,
    /// space-delimited.
    Hex,
    /// Input is a binary string, e.g., `0b0100`.
    BinaryString,
}

#[derive(Clone, Debug, PartialEq)]
enum OutputKind<T> {
    Default,
    Parseable {
        fields: Vec<T>,
        separator: ParseableOutputSeparator,
    },
}

impl<T> OutputKind<T> {
    fn parseable(fields: Vec<T>, separator: Option<String>) -> Self {
        OutputKind::Parseable { fields, separator: ParseableOutputSeparator::new(separator) }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum ParseableOutputSeparator {
    Default,
    Custom(String),
}

impl ParseableOutputSeparator {
    fn new(custom_value: Option<String>) -> Self {
        match custom_value {
            Some(value) => ParseableOutputSeparator::Custom(value),
            None => ParseableOutputSeparator::Default,
        }
    }
}

impl ParseableOutputSeparator {
    fn as_str(&self) -> &str {
        match self {
            ParseableOutputSeparator::Default => ":::",
            ParseableOutputSeparator::Custom(s) => s.as_str(),
        }
    }
}

// How to print the `Status`.
#[derive(Clone, Debug)]
enum StatusKind {
    // Print the usual Display representation of each set of status bits.
    Normal,
    // Print the truth value of a set of status bits, from all modules.
    Limited {
        with: ExtendedStatus,
        without: ExtendedStatus,
    },
    // Print all bits from all modules.
    All,
    // Print the parseable representation of each set of status bits.
    Parseable { separator: ParseableOutputSeparator },
}

#[derive(Clone, Copy, Debug, clap::Parser)]
struct StatusFlags {
    /// Find modules with the provided flags set.
    #[arg(short, value_parser = parse_status)]
    with: Option<ExtendedStatus>,
    /// Find modules without the provided flags set.
    #[arg(short, value_parser = parse_status)]
    without: Option<ExtendedStatus>,
}

fn parse_status(s: &str) -> Result<ExtendedStatus, String> {
    s.parse::<ExtendedStatus>().map_err(|e| e.to_string())
}

fn read_u8(s: &str) -> Result<u8, String> {
    let (s, radix) = s
        .strip_prefix("0x")
        .map(|hex| (hex, 16))
        .unwrap_or_else(|| (s, 10));
    u8::from_str_radix(s, radix).map_err(|e| e.to_string())
}

#[derive(Subcommand)]
enum Cmd {
    /// Return the status of the addressed modules, such as presence, power
    /// enable, and power mode.
    Status {
        /// Print the truth value of a set of status bits, from all modules.
        ///
        /// Any set of valid status bits may be used. For each module, a "1"
        /// will be printed where the status of that module contains the
        /// provided bits, otherwise a "0" will be printed. Note that bitflags
        /// are written in ALL_CAPS, and separated by a pipe "|". To avoid the
        /// shell interpreting that as a shell-pipeline, the bits should be
        /// quoted -- for example: "PRESENT | RESET".
        #[arg(long, value_parser = parse_status, conflicts_with = "all")]
        with: Option<ExtendedStatus>,
        #[arg(long, value_parser = parse_status, conflicts_with = "all")]
        without: Option<ExtendedStatus>,

        /// Print all bits from all modules.
        ///
        /// This shows a table, where rows are modules and columns the status
        /// bit. For each module, if the module contains the relevant status bit
        /// a "1" is printed. Otherwise a "0" is printed.
        #[arg(long)]
        all: bool,
        
        /// Print the output in a parseable format.
        #[arg(long, short, conflicts_with_all = ["all", "with", "without"])]
        parseable: bool,

        /// Select the output fields to be displayed.
        #[arg(long, short, requires = "parseable")]
        output: Vec<StatusFields>,

        /// Character used to separate output fields. (Default: :::)
        #[arg(long, requires = "parseable")]
        output_separator: Option<String>,
    },

    /// Reset the addressed modules.
    ///
    /// A reset returns the module to its default state, clearing all module
    /// settings and data. This may take up to 2s to complete.
    Reset,

    /// Set the power state of the addressed modules.
    SetPower {
        /// The desired power state.
        #[arg(value_enum)]
        state: PowerState,
    },

    /// Return the power mode of the addressed modules.
    ///
    /// This takes into account whether a module has specified software override
    /// of power control, and may take up to 2s to complete.
    Power {
        /// Print the output in a parseable format.
        #[arg(long, short)]
        parseable: bool,

        /// Select the output fields to be displayed.
        #[arg(long, short, requires = "parseable")]
        output: Vec<PowerFields>,

        /// Character used to separate output fields. (Default: :::)
        #[arg(long, requires = "parseable")]
        output_separator: Option<String>,
    },

    /// Enable the hot swap controller for the addressed modules.
    ///
    /// Note that this is a lower-level method for specifically controlling the
    /// hot swap controller directly. See the `set-power` subcommand for a
    /// higher-level interface to set the module power to a specific state.
    EnablePower,

    /// Disable the hot swap controller for the addressed modules.
    ///
    /// Note that this is a lower-level method for specifically controlling the
    /// hot swap controller directly. See the `set-power` subcommand for a
    /// higher-level interface to set the module power to a specific state.
    DisablePower,

    /// Assert ResetL for the addressed modules.
    AssertReset,

    /// Deassert ResetL for the addressed modules.
    DeassertReset,

    /// Assert LpMode for the addressed modules.
    ///
    /// Note that this is a lower-level method for specifically controlling the
    /// LPMode hardware signal directly. See the `set-power` subcommand for a
    /// higher-level interface to set the module power to a specific state.
    AssertLpMode,

    /// Deassert LpMode for the addressed modules.
    ///
    /// Note that this is a lower-level method for specifically controlling the
    /// LPMode hardware signal directly. See the `set-power` subcommand for a
    /// higher-level interface to set the module power to a specific state.
    DeassertLpMode,

    /// Read the SFF-8024 identifier for a set of modules.
    Identify {
        /// Print the output in a parseable format.
        #[arg(long, short)]
        parseable: bool,

        /// Select the output fields to be displayed.
        #[arg(long, short, requires = "parseable")]
        output: Vec<IdentifyFields>,

        /// Character used to separate output fields. (Default: :::)
        #[arg(long, requires = "parseable")]
        output_separator: Option<String>,
    },

    /// Read the vendor information for a set of modules.
    VendorInfo {
        /// Print the output in a parseable format.
        #[arg(long, short)]
        parseable: bool,

        /// Select the output fields to be displayed.
        #[arg(long, short, requires = "parseable")]
        output: Vec<VendorInfoFields>,

        /// Character used to separate output fields. (Default: :::)
        #[arg(long, requires = "parseable")]
        output_separator: Option<String>,
    },

    /// Read the lower page of a set of transceiver modules.
    #[command(group(ArgGroup::new("interface").required(true).args(["sff", "cmis"])))]
    ReadLower {
        /// Interpret the module's memory map as SFF-8636.
        #[arg(long)]
        sff: bool,

        /// Interpret the module's memory map as CMIS.
        #[arg(long)]
        cmis: bool,

        /// Print the data in binary (hex is the default).
        #[arg(long)]
        binary: bool,

        /// The offset to start reading from.
        ///
        /// This may be specified in hex, starting with `0x`, or in decimal.
        #[arg(value_parser = read_u8)]
        offset: u8,

        /// The number of bytes to read.
        ///
        /// This may be specified in hex, starting with `0x`, or in decimal.
        #[arg(value_parser = read_u8)]
        len: u8,
    },

    /// Write the lower page of a set of transceiver modules.
    ///
    /// This takes data from stdin until EOF, or from a named file, and writes
    /// bytes to the provided locations.
    ///
    /// Input data may be specified in either binary or text formats. If the
    /// input is from a file, the input kind _must_ be specified. If the input
    /// is from stdin, then the kind may be omitted for _text_ input. The radix
    /// will be interpreted from the input, where:
    ///
    /// - `0x...` implies hex
    /// - `0b...` implies a binary string,
    /// - and anything else is read as decimal.
    ///
    /// Note that raw binary input from stdin will only be correctly interpreted
    /// if the `--input-kind binary` flag is provided.
    #[command(group(ArgGroup::new("interface").required(true).args(["sff", "cmis"])))]
    WriteLower {
        /// Interpret the module's memory map as SFF-8636.
        #[arg(long)]
        sff: bool,

        /// Interpret the module's memory map as CMIS.
        #[arg(long)]
        cmis: bool,

        /// The input file for data, defaulting to stdin.
        #[arg(short, long, requires = "input_kind")]
        input: Option<PathBuf>,

        /// How to interpret the input data.
        #[arg(long, value_enum)]
        input_kind: Option<InputKind>,

        /// The offset to start writing to.
        ///
        /// This may be specified in hex, starting with `0x`, or in decimal.
        #[arg(value_parser = read_u8)]
        offset: u8,
    },

    /// Read data from an upper memory page.
    #[command(group(ArgGroup::new("interface").required(true).args(["sff", "cmis"])))]
    ReadUpper {
        /// Interpret the module's memory map as SFF-8636.
        #[arg(long)]
        sff: bool,

        /// Interpret the module's memory map as CMIS.
        #[arg(long)]
        cmis: bool,

        /// Print the data in binary (hex is the default).
        #[arg(long)]
        binary: bool,

        /// The upper page to read from.
        #[arg(short, long, default_value_t = 0, value_parser = read_u8)]
        page: u8,

        /// For CMIS modules, the bank of the upper page to read from.
        ///
        /// Note that some pages require a bank and others may not have a bank.
        /// The validity will be checked at runtime.
        ///
        /// This may be specified in hex, starting with `0x`, or in decimal.
        #[arg(short, long, conflicts_with("sff"), value_parser = read_u8)]
        bank: Option<u8>,

        /// The offset to start reading from.
        ///
        /// Note that offsets are always specified as relative to the full
        /// 256-byte transceiver memory map. E.g., to read starting from the
        /// first byte of an upper page, the value `128` should be specified.
        ///
        /// This may be specified in hex, starting with `0x`, or in decimal.
        #[arg(value_parser = read_u8)]
        offset: u8,

        /// The number of bytes to read.
        ///
        /// This may be specified in hex, starting with `0x`, or in decimal.
        #[arg(value_parser = read_u8)]
        len: u8,
    },

    /// Write the upper page of a set of transceiver modules.
    ///
    /// This takes data from stdin until EOF, or from a named file, and writes
    /// bytes to the provided locations.
    ///
    /// Input data may be specified in either binary or text formats. If the
    /// input is from a file, the input kind _must_ be specified. If the input
    /// is from stdin, then the kind may be omitted for _text_ input. The radix
    /// will be interpreted from the input, where:
    ///
    /// - `0x...` implies hex
    /// - `0b...` implies a binary string,
    /// - and anything else is read as decimal.
    ///
    /// Note that raw binary input from stdin will only be correctly interpreted
    /// if the `--input-kind binary` flag is provided.
    #[command(group(ArgGroup::new("interface").required(true).args(["sff", "cmis"])))]
    WriteUpper {
        /// Interpret the module's memory map as SFF-8636.
        #[arg(long)]
        sff: bool,

        /// Interpret the module's memory map as CMIS.
        #[arg(long)]
        cmis: bool,

        /// The input file for data, defaulting to stdin.
        #[arg(short, long, requires = "input_kind")]
        input: Option<PathBuf>,

        /// How to interpret the input data.
        #[arg(long, value_enum)]
        input_kind: Option<InputKind>,

        /// The upper page to read from.
        ///
        /// This may be specified in hex, starting with `0x`, or in decimal.
        #[arg(short, long, default_value_t = 0, value_parser = read_u8)]
        page: u8,

        /// For CMIS modules, the bank of the upper page to read from.
        ///
        /// Note that some pages require a bank and others may not have a bank.
        /// The validity will be checked at runtime.
        ///
        /// This may be specified in hex, starting with `0x`, or in decimal.
        #[arg(short, long, conflicts_with("sff"), value_parser = read_u8)]
        bank: Option<u8>,

        /// The offset to start writing to.
        ///
        /// Note that offsets are always specified as relative to the full
        /// 256-byte transceiver memory map. E.g., to read starting from the
        /// first byte of an upper page, the value `128` should be specified.
        ///
        /// This may be specified in hex, starting with `0x`, or in decimal.
        #[arg(value_parser = read_u8)]
        offset: u8,
    },

    /// Describe the memory model of a set of modules.
    ///
    /// If a module supports paged memory, the list of pages is printed. For
    /// modules which support banked pages (CMIS only), the maximum supported
    /// bank is also printed following each banked page. For example, `0x10/1`
    /// indicates that page `0x10` is supported, and the module implements banks
    /// 0 and 1 (16 lanes).
    MemoryModel {
        /// Print the output in a parseable format.
        #[arg(long, short)]
        parseable: bool,

        /// Select the output fields to be displayed.
        #[arg(long, short, requires = "parseable")]
        output: Vec<MemoryModelFields>,

        /// Character used to separate output fields. (Default: :::)
        #[arg(long, requires = "parseable")]
        output_separator: Option<String>,
    },

    /// Return the MAC addresses for the particular system allotted by its
    /// FRUID.
    Macs {
        /// Print a summary of the MAC range, rather than each address.
        #[arg(short, long, default_value_t = false)]
        summary: bool,
    },

    /// Clears a power fault on a set of modules.
    ///
    /// When a power fault has occurred, the transceiver's power supply will not
    /// re-enable as long as the fault is latched. Clearing the fault allows the
    /// power supply to be enabled again.
    ClearPowerFault,

    /// Clears the "disabled" latch on a set of modules
    ///
    /// The SP may make a policy decision to disable modules (e.g. if they
    /// aren't reporting temperatures to the thermal loop).  Clearing the latch
    /// allows them to be powered on again.
    ClearDisableLatch,

    /// Return the state of the addressed modules' attention LEDs.
    Leds {
        /// Print the output in a parseable format.
        #[arg(long, short)]
        parseable: bool,

        /// Select the output fields to be displayed.
        #[arg(long, short, requires = "parseable")]
        output: Vec<LedFields>,

        /// Character used to separate output fields. (Default: :::)
        #[arg(long, requires = "parseable")]
        output_separator: Option<String>,
    },

    /// Set the state of the addressed modules' attention LEDs.
    SetLeds {
        /// The state to which to set the LEDs.
        state: LedState,
    },

    /// Return the core transceiver monitoring data a set of modules.
    ///
    /// For each module this prints:
    ///
    /// - Temperature (C)
    /// - Supply voltage
    /// - Average receiver power (mW)
    /// - Transmitter bias (mA) and power (mW)
    /// - One of several auxiliary monitors.
    ///
    /// Note that if the data is not supported by the module, `--` is printed.
    /// Unfortunately, modules are not required to advertise whether they
    /// support receiver power measurements, so that is always printed. Values
    /// near zero should be treated with caution, and the datasheet should be
    /// consulted for details.
    Monitors {
        /// Print the output in a parseable format.
        #[arg(long, short)]
        parseable: bool,

        /// Select the output fields to be displayed.
        #[arg(long, short, requires = "parseable")]
        output: Vec<MonitorFields>,

        /// Character used to separate output fields. (Default: :::)
        #[arg(long, requires = "parseable")]
        output_separator: Option<String>,
    },

    /// Return information about the datapath of a set of modules.
    ///
    /// This prints information about the state of the datapath, including:
    ///
    /// - Number of lanes (for CMIS modules only)
    /// - Host-side electrical interface
    /// - Media-side interface
    /// - Transmitter state (enabled or disabled)
    /// - Tx and Rx loss-of-signal (LOS) and loss-of-lock (LOL) information
    /// - Datapath state (for CMIS modules only)
    Datapath,
}

// Maximum number of bytes to read from input source for writing to module.
const MAX_BYTES: usize = 128;

// Load data from a reader, once the input kind is known.
fn load_known_write_data<R: Read>(rdr: &mut R, kind: InputKind) -> anyhow::Result<Vec<u8>> {
    match kind {
        InputKind::Binary => {
            let mut data = vec![0; MAX_BYTES];
            let n_bytes = rdr.read(&mut data)?;
            data.truncate(n_bytes);
            Ok(data)
        }
        text => {
            let conv = match text {
                InputKind::Decimal => |x: &str| x.parse::<u8>().map_err(anyhow::Error::from),
                InputKind::Hex => |x: &str| {
                    u8::from_str_radix(x.trim_start_matches("0x"), 16).map_err(anyhow::Error::from)
                },
                InputKind::BinaryString => |x: &str| {
                    u8::from_str_radix(x.trim_start_matches("0b"), 2).map_err(anyhow::Error::from)
                },
                InputKind::Binary => unreachable!(),
            };
            let mut buf = String::with_capacity(MAX_BYTES * 4);
            rdr.take(buf.capacity().try_into().unwrap())
                .read_to_string(&mut buf)?;
            let data = buf
                .split_whitespace()
                .map(conv)
                .collect::<anyhow::Result<Vec<_>>>()?;
            ensure!(data.len() <= MAX_BYTES, "Input data too large");
            Ok(data)
        }
    }
}

#[derive(Clone, ValueEnum, PartialEq)]
enum StatusFields {
    /// The port number of the switch.
    Port,
    /// The power state of the transceiver module.
    Status,
}

#[derive(Clone, ValueEnum, PartialEq)]
enum PowerFields {
    /// The port number of the switch.
    Port,
    /// The power state of the transceiver module.
    Power,
    /// Flag to indicate a software override of the modules power state.
    Override,
}

#[derive(Clone, ValueEnum, PartialEq)]
enum IdentifyFields {
    /// The port number of the switch.
    Port,
    /// SFF-8024 identifier of the transceiver module.
    Ident,
    /// ??? - Needs details
    Description,
}

#[derive(Clone, ValueEnum, PartialEq)]
enum VendorInfoFields {
    /// The port number of the switch.
    Port,
    /// Identifier of the transceiver module.
    Identifier,
    /// Manufacturer of the transceiver module.
    Vendor,
    /// Manufacturer part number.
    Part,
    /// Revision number of the transceiver module.
    Rev,
    /// Serial number of the transceiver module.
    Serial,
    /// ??? - Needs details
    ManufacturedDate,
}

#[derive(Clone, ValueEnum, PartialEq)]
enum ReadLowerFields {
}

#[derive(Clone, ValueEnum, PartialEq)]
enum ReadUpperFields {
}

#[derive(Clone, ValueEnum, PartialEq)]
enum MemoryModelFields {
    /// The port number of the switch.
    Port,
    /// The model number of the transceiver module.
    Model,
}

#[derive(Clone, ValueEnum, PartialEq)]
enum MacFields {
    /// The port number of the switch.
    Port,
    /// The model number of the transceiver module.
    Model,
}

#[derive(Clone, ValueEnum, PartialEq)]
enum LedFields {
    /// The port number of the switch.
    Port,
    /// State of th transceiver modules status LED.
    Led,
}

#[derive(Clone, ValueEnum, PartialEq)]
enum MonitorFields {
    /// The port number of the switch.
    Port,
    /// The temperature of the transceiver module.
    Temperature,
    /// ??? - Is this power being supplied to the module?
    SupplyVoltage,
    /// Average received power of the transceiver module in mW.
    AverageRxPower,
    /// Transmit bias current of the transceiver module in mA.
    TxBias,
    /// Transmit power of the transceiver module in mW.
    TxPower,
    /// ???
    Aux1,
    /// ???
    Aux2,
    /// ???
    Aux3,
}

// Try to autodetect the input kind, based on the first few
// characters.
//
// 0b -> binary string
// 0x -> hex
// _ -> decimal
fn load_write_data_autodetect_kind(buf: String) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(!buf.is_empty(), "No input provided on stdin");
    let kind = match &buf[..2] {
        "0b" => InputKind::BinaryString,
        "0x" => InputKind::Hex,
        _ => InputKind::Decimal,
    };
    let mut cursor = std::io::Cursor::new(buf);
    load_known_write_data(&mut cursor, kind)
}

fn load_write_data(file: Option<PathBuf>, kind: Option<InputKind>) -> anyhow::Result<Vec<u8>> {
    if let Some(path) = file {
        let kind = kind.context("clap failed to ensure required argument")?;
        let mut f = File::open(path).context("failed to open data file")?;
        load_known_write_data(&mut f, kind)
    } else {
        let mut stdin = stdin();
        // If provided, directly use the input kind.
        if let Some(kind) = kind {
            load_known_write_data(&mut stdin, kind)
        } else {
            let mut buf = String::with_capacity(MAX_BYTES);
            stdin
                .read_to_string(&mut buf)
                .context("failed to read from stdin")?;
            load_write_data_autodetect_kind(buf)
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let config = Config {
        address: args.address,
        interface: args.interface,
        port: args.port,
        peer: args
            .peer
            .unwrap_or_else(|| Ipv6Addr::from(transceiver_messages::ADDR)),
        peer_port: args.peer_port,
        n_retries: args.n_retries,
        retry_interval: Duration::from_millis(args.retry_interval),
    };

    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let drain = slog::LevelFilter::new(drain, args.log_level).fuse();
    let log = slog::Logger::root(drain, slog::o!());

    // Create a dummy request handler that just logs and drops all messages.
    let request_log = log.new(slog::o!("name" => "request_handler"));
    let (request_tx, mut request_rx) = mpsc::channel(1);
    let _request_handler = tokio::spawn(async move {
        loop {
            while let Some(SpRequest {
                request,
                response_tx,
            }) = request_rx.recv().await
            {
                slog::debug!(
                    request_log,
                    "incoming request, dropping";
                    "request" => ?request
                );
                // Drop the message.
                if let Err(e) = response_tx.send(Ok(None)).await {
                    slog::error!(
                        request_log,
                        "failed to send response";
                        "reason" => ?e
                    );
                }
            }
        }
    });

    let controller = Controller::new(config, log.clone(), request_tx)
        .await
        .context("Failed to initialize transceiver controller")?;

    // Determine the actual module ID of the transceivers the caller requested
    // we operate on. Note that this may result in zero transceivers being
    // addressed. We're choosing not to return an error in this case, so that
    // callers can distinguish between a successful "request for status of all
    // low-power module transceivers" from a failure to do so (e.g., a network
    // error), _without_ having to parse stderr.
    let transceivers = args.transceivers.unwrap_or(Transceivers::All);
    let modules = address_transceivers(&controller, transceivers).await?;

    match args.cmd {
        Cmd::Status { with, without, all, parseable, output, output_separator } => {
            let kind = match (with, without, all, parseable) {
                (None, None, false, true) => StatusKind::Parseable { separator: ParseableOutputSeparator::new(output_separator) },
                (None, None, false, false) => StatusKind::Normal,
                (None, None, true, false) => StatusKind::All,
                (maybe_with, maybe_without, false, false) => {
                    let with = maybe_with.unwrap_or_else(ExtendedStatus::empty);
                    let without = maybe_without.unwrap_or_else(ExtendedStatus::empty);
                    if with.is_empty() && without.is_empty() {
                        eprintln!(
                            "If specified, one of `--with` and `--without` \
                            must be non-empty"
                        );
                    }
                    StatusKind::Limited { with, without }
                }
                _ => unreachable!("clap didn't do its job"),
            };
            let status_result = match controller.extended_status(modules).await {
                Ok(v) => v,
                Err(err) => {
                    slog::warn!(
                        &log,
                        "could not read extended status ({err}); reading status instead",
                    );
                    let r = controller
                        .status(modules)
                        .await
                        .context("Failed to retrieve module status")?;
                    ExtendedStatusResult {
                        modules: r.modules,
                        data: r.data.into_iter().map(Into::into).collect(),
                        failures: r.failures,
                    }
                }
            };

            print_module_status(&status_result, kind, &output);
            if !args.ignore_errors {
                print_failures(&status_result.failures);
            }
        }

        Cmd::Reset => {
            let ack_result = controller
                .reset(modules)
                .await
                .context("Failed to reset modules")?;
            if !args.ignore_errors {
                print_failures(&ack_result.failures);
            }
        }

        Cmd::SetPower { state } => {
            let ack_result = controller
                .set_power(modules, state)
                .await
                .context("Failed to set power state")?;
            if !args.ignore_errors {
                print_failures(&ack_result.failures);
            }
        }

        Cmd::Power { parseable, output, output_separator } => {
            let kind = if parseable {
                OutputKind::parseable(output, output_separator)
            } else {
                OutputKind::Default
            };

            let mode_result = controller
                .power(modules)
                .await
                .context("Failed to get power mode")?;
            print_power_mode(&mode_result, &kind);
            if !args.ignore_errors {
                print_failures(&mode_result.failures);
            }
        }

        Cmd::EnablePower => {
            let ack_result = controller
                .enable_power(modules)
                .await
                .context("Failed to enable power for modules")?;
            if !args.ignore_errors {
                print_failures(&ack_result.failures);
            }
        }

        Cmd::DisablePower => {
            let ack_result = controller
                .disable_power(modules)
                .await
                .context("Failed to disable power for modules")?;
            if !args.ignore_errors {
                print_failures(&ack_result.failures);
            }
        }

        Cmd::AssertReset => {
            let ack_result = controller
                .assert_reset(modules)
                .await
                .context("Failed to assert reset for modules")?;
            if !args.ignore_errors {
                print_failures(&ack_result.failures);
            }
        }

        Cmd::DeassertReset => {
            let ack_result = controller
                .deassert_reset(modules)
                .await
                .context("Failed to deassert reset for modules")?;
            if !args.ignore_errors {
                print_failures(&ack_result.failures);
            }
        }

        Cmd::AssertLpMode => {
            let ack_result = controller
                .assert_lpmode(modules)
                .await
                .context("Failed to assert lpmode for modules")?;
            if !args.ignore_errors {
                print_failures(&ack_result.failures);
            }
        }

        Cmd::DeassertLpMode => {
            let ack_result = controller
                .deassert_lpmode(modules)
                .await
                .context("Failed to deassert lpmode for modules")?;
            if !args.ignore_errors {
                print_failures(&ack_result.failures);
            }
        }

        Cmd::Identify { parseable, output, output_separator } => {
            let kind = if parseable {
                OutputKind::parseable(output, output_separator)
            } else {
                OutputKind::Default
            };

            let ident_result = controller
                .identifier(modules)
                .await
                .context("Failed to identify transceiver modules")?;
            print_module_identifier(&ident_result, &kind);
            if !args.ignore_errors {
                print_failures(&ident_result.failures);
            }
        }

        Cmd::VendorInfo { parseable, output, output_separator } => {
            let kind = if parseable {
                OutputKind::parseable(output, output_separator)
            } else {
                OutputKind::Default
            };

            let info_result = controller
                .vendor_info(modules)
                .await
                .context("Failed to fetch vendor information for transceiver modules")?;
            print_vendor_info(&info_result, &kind);
            if !args.ignore_errors {
                print_failures(&info_result.failures);
            }
        }

        Cmd::ReadLower {
            sff,
            cmis,
            binary,
            offset,
            len,
        } => {
            if len == 0 {
                return Ok(());
            }
            let reads = match (sff, cmis) {
                (true, false) => MemoryRead::build_many(sff8636::Page::Lower, offset, len)
                    .context("Failed to setup lower page memory read")?,
                (false, true) => MemoryRead::build_many(cmis::Page::Lower, offset, len)
                    .context("Failed to setup lower page memory read")?,
                (_, _) => unreachable!("clap didn't do its job"),
            };
            let mut read_result =
                ReadResult::success(modules, vec![vec![]; modules.selected_transceiver_count()])
                    .unwrap();
            for read in reads.into_iter() {
                let res = controller
                    .read(modules, read)
                    .await
                    .context("Failed to read transceiver modules")?;
                read_result = read_result.append(&res).unwrap();
            }
            print_read_data(&read_result, binary);
            if !args.ignore_errors {
                print_failures(&read_result.failures);
            }
        }

        Cmd::WriteLower {
            sff,
            cmis,
            input,
            input_kind,
            offset,
        } => {
            let data = load_write_data(input, input_kind).context("Failed to load input data")?;
            let len = data.len().try_into().context("Input data too long")?;
            let write = match (sff, cmis) {
                (true, false) => MemoryWrite::new(sff8636::Page::Lower, offset, len)
                    .context("Failed to setup lower page memory write")?,
                (false, true) => MemoryWrite::new(cmis::Page::Lower, offset, len)
                    .context("Failed to setup lower page memory write")?,
                (_, _) => unreachable!("clap didn't do its job"),
            };
            let write_result = controller
                .write(modules, write, &data)
                .await
                .context("Failed to write transceiver modules")?;
            if !args.ignore_errors {
                print_failures(&write_result.failures);
            }
        }

        Cmd::ReadUpper {
            sff,
            cmis,
            binary,
            page,
            bank,
            offset,
            len,
        } => {
            if len == 0 {
                return Ok(());
            }
            let reads = match (sff, cmis) {
                (true, false) => {
                    let page =
                        sff8636::UpperPage::new(page).context("Invalid SFF-8636 upper page")?;
                    MemoryRead::build_many(sff8636::Page::Upper(page), offset, len)
                        .context("Failed to setup upper page memory read")?
                }
                (false, true) => {
                    let page = if let Some(bank) = bank {
                        cmis::UpperPage::new_banked(page, bank)
                    } else {
                        cmis::UpperPage::new_unbanked(page)
                    }
                    .context("Invalid CMIS upper page")?;
                    MemoryRead::build_many(cmis::Page::Upper(page), offset, len)
                        .context("Failed to setup upper page memory read")?
                }
                (_, _) => unreachable!("clap didn't do its job"),
            };
            let mut read_result =
                ReadResult::success(modules, vec![vec![]; modules.selected_transceiver_count()])
                    .unwrap();
            for read in reads.into_iter() {
                let res = controller
                    .read(modules, read)
                    .await
                    .context("Failed to read transceiver modules")?;
                read_result = read_result.append(&res).unwrap();
            }
            print_read_data(&read_result, binary);
            if !args.ignore_errors {
                print_failures(&read_result.failures);
            }
        }

        Cmd::WriteUpper {
            sff,
            cmis,
            input,
            input_kind,
            page,
            bank,
            offset,
        } => {
            let data = load_write_data(input, input_kind).context("Failed to load input data")?;
            let len = data.len().try_into().context("Input data too long")?;
            let write = match (sff, cmis) {
                (true, false) => {
                    let page =
                        sff8636::UpperPage::new(page).context("Invalid SFF-8636 upper page")?;
                    MemoryWrite::new(sff8636::Page::Upper(page), offset, len)
                        .context("Failed to setup upper page memory write")?
                }
                (false, true) => {
                    let page = if let Some(bank) = bank {
                        cmis::UpperPage::new_banked(page, bank)
                    } else {
                        cmis::UpperPage::new_unbanked(page)
                    }
                    .context("Invalid CMIS upper page")?;
                    MemoryWrite::new(cmis::Page::Upper(page), offset, len)
                        .context("Failed to setup upper page memory write")?
                }
                (_, _) => unreachable!("clap didn't do its job"),
            };
            let write_result = controller
                .write(modules, write, &data)
                .await
                .context("Failed to write transceiver modules")?;
            if !args.ignore_errors {
                print_failures(&write_result.failures);
            }
        }
        Cmd::MemoryModel { parseable, output, output_separator } => {
            let kind = if parseable {
                OutputKind::parseable(output, output_separator)
            } else {
                OutputKind::Default
            };

            let layout_result = controller
                .memory_model(modules)
                .await
                .context("Failed to get memory model")?;
            print_module_memory_model(&layout_result, &kind);
            if !args.ignore_errors {
                print_failures(&layout_result.failures);
            }
        }
        Cmd::Macs { summary } => {
            let macs = controller
                .mac_addrs()
                .await
                .context("Failed to get MAC addresses")?;
            print_mac_address_range(macs, summary);
        }
        Cmd::ClearPowerFault => {
            let ack_result = controller
                .clear_power_fault(modules)
                .await
                .context("Failed to clear power fault for modules")?;
            if !args.ignore_errors {
                print_failures(&ack_result.failures);
            }
        }
        Cmd::ClearDisableLatch => {
            let ack_result = controller
                .clear_disable_latch(modules)
                .await
                .context("Failed to clear disable latch for modules")?;
            if !args.ignore_errors {
                print_failures(&ack_result.failures);
            }
        }
        Cmd::Leds { parseable, output, output_separator } => {
            let kind = if parseable {
                OutputKind::parseable(output, output_separator)
            } else {
                OutputKind::Default
            };

            let state_result = controller
                .leds(modules)
                .await
                .context("Failed to get LED state")?;
            print_led_state(&state_result, &kind);
            if !args.ignore_errors {
                print_failures(&state_result.failures);
            }
        }
        Cmd::SetLeds { state } => {
            let ack_result = controller
                .set_leds(modules, state)
                .await
                .context("Failed to set LED state")?;
            if !args.ignore_errors {
                print_failures(&ack_result.failures);
            }
        }
        Cmd::Monitors { parseable, output, output_separator } => {
            let kind = if parseable {
                OutputKind::parseable(output, output_separator)
            } else {
                OutputKind::Default
            };

            let monitor_result = controller
                .monitors(modules)
                .await
                .context("Failed to get monitoring data")?;
            print_monitors(&monitor_result, &kind);
            if !args.ignore_errors {
                print_failures(&monitor_result.failures);
            }
        }
        Cmd::Datapath => {
            let datapath_result = controller
                .datapath(modules)
                .await
                .context("Failed to get datapath state")?;
            print_datapath(&datapath_result);
            if !args.ignore_errors {
                print_failures(&datapath_result.failures);
            }
        }
    }
    Ok(())
}

async fn address_transceivers(
    controller: &Controller,
    transceivers: Transceivers,
) -> anyhow::Result<ModuleId> {
    let modules = match transceivers {
        Transceivers::All => {
            // "All" here means all bits, but Sidecar only has 32 QSFP ports
            // right now, and for the forseeable future. Limit this to 32-bits.
            ModuleId(u64::from(u32::MAX))
        }
        Transceivers::Present => {
            // Fetch all status bits, and find those which match.
            let modules = ModuleId::all_sidecar();
            let status_result = controller
                .status(modules)
                .await
                .context("Failed to retrieve module status")?;
            filter_module_data(
                status_result.modules,
                status_result.status().iter(),
                |_, st| st.contains(Status::PRESENT),
            )
            .0
        }
        Transceivers::PowerState(state) => {
            // Fetch all power states, and find those which match.
            let modules = ModuleId::all_sidecar();
            let mode_result = controller
                .power(modules)
                .await
                .context("Failed to retrieve module power state")?;
            filter_module_data(
                mode_result.modules,
                mode_result.power_modes().iter(),
                |_, s| s.state == state,
            )
            .0
        }
        Transceivers::Kind(kind) => {
            // Read the identifier for all modules, and return those that we can
            // read and are of the requested kind.
            let ident_result = controller
                .identifier(ModuleId::all_sidecar())
                .await
                .context("Failed to retrieve module identifiers")?;
            filter_module_data(
                ident_result.modules,
                ident_result.identifiers().iter(),
                |_, id| {
                    if let Ok(iface) = id.management_interface() {
                        iface == kind
                    } else {
                        false
                    }
                },
            )
            .0
        }
        Transceivers::Index(p) => p,
    };
    Ok(modules)
}

// Column width for printing data below.
const WIDTH: usize = 4;
const POWER_WIDTH: usize = 5;

fn print_failures(failures: &FailedModules) {
    if failures.modules.selected_transceiver_count() > 0 {
        eprintln!("Some operations failed, errors below");
        eprintln!("Port Error");
        for (port, err) in failures.modules.to_indices().zip(failures.errors.iter()) {
            eprintln!("{port:>WIDTH$} {err}");
        }
    }
}

fn print_power_mode(mode_result: &PowerModeResult, kind: &OutputKind<PowerFields>) {
    match kind {
        OutputKind::Default => println!("Port  Power  Software-override"),
        OutputKind::Parseable { fields, separator } => print_parseable_header(fields, separator),
    }

    for (port, mode) in mode_result
        .modules
        .to_indices()
        .zip(mode_result.power_modes().iter())
    {
        let over = match mode.software_override {
            None => "-",
            Some(true) => "Yes",
            Some(false) => "No",
        };
        let state = format!("{:?}", mode.state);
        match kind {
            OutputKind::Default => {
                println!("{port:>WIDTH$}  {state:POWER_WIDTH$}  {over}",);
            }
            OutputKind::Parseable { fields, separator } => {
                fields.iter().map(|field| match field {
                    PowerFields::Port => port.to_string(),
                    PowerFields::Power => state.clone(),
                    PowerFields::Override => over.to_string(),
                }).collect::<Vec<_>>().join(separator.as_str());
            }
        }
    }
}

fn print_module_status(status_result: &ExtendedStatusResult, kind: StatusKind, output: &[StatusFields]) {
    match kind {
        StatusKind::Parseable { separator } => {
            println!("{}", output.iter().map(|field| match field {
                StatusFields::Port => "port",
                StatusFields::Status => "status",
            }).collect::<Vec<_>>().join(separator.as_str()));

            for (port, status) in status_result.iter() {
                println!("{}", output.iter().map(|field| match field {
                    StatusFields::Port => port.to_string(),
                    StatusFields::Status => status.to_string(),
                }).collect::<Vec<_>>().join(separator.as_str()));
            }
        }
        StatusKind::Normal => {
            println!("Port Status");
            for (port, status) in status_result.iter() {
                println!("{port:>WIDTH$} {}", status);
            }
        }
        StatusKind::Limited { with, without } => {
            let status_str = match (with.is_empty(), without.is_empty()) {
                (true, true) => unreachable!("verified in caller"),
                (false, true) => format!("{with}"),
                (true, false) => format!("!({without})"),
                (false, false) => format!("{with} && !({without})"),
            };
            println!("Port {status_str}");
            for (port, status) in status_result.iter() {
                let yes = match (with.is_empty(), without.is_empty()) {
                    (true, true) => unreachable!("verified in caller"),
                    (false, true) => status.contains(with),
                    (true, false) => !status.contains(without),
                    (false, false) => status.contains(with) && !status.contains(without),
                };
                println!("{port:>WIDTH$} {}", if yes { "1" } else { "0" });
            }
        }
        StatusKind::All => print_all_status(status_result),
    }
}

// NOTE: Skip formatting this function because the exact representation here is
// useful to see how we print the table header itself.
#[rustfmt::skip]
fn print_all_status_header() {
    println!(" +------------------------------------- Port");
    println!(" |   +--------------------------------- {}", ExtendedStatus::PRESENT);
    println!(" |   |   +----------------------------- {}", ExtendedStatus::ENABLED);
    println!(" |   |   |   +------------------------- {}", ExtendedStatus::RESET);
    println!(" |   |   |   |   +--------------------- {}", ExtendedStatus::LOW_POWER_MODE);
    println!(" |   |   |   |   |   +----------------- {}", ExtendedStatus::INTERRUPT);
    println!(" |   |   |   |   |   |   +------------- {}", ExtendedStatus::POWER_GOOD);
    println!(" |   |   |   |   |   |   |   +--------- {}", ExtendedStatus::FAULT_POWER_TIMEOUT);
    println!(" |   |   |   |   |   |   |   |   +----- {}", ExtendedStatus::FAULT_POWER_LOST);
    println!(" |   |   |   |   |   |   |   |   |   +- {}", ExtendedStatus::DISABLED_BY_SP);
    println!(" v   v   v   v   v   v   v   v   v   v");
}

fn print_all_status(status_result: &ExtendedStatusResult) {
    print_all_status_header();
    for (port, status) in status_result
        .modules
        .to_indices()
        .zip(status_result.status().iter())
    {
        print!("{port:>2}   ");
        for bit in ExtendedStatus::all().iter() {
            let word = if status.contains(bit) { "1" } else { "0" };
            print!("{word:<WIDTH$}");
        }
        println!();
    }
}

fn print_read_data(read_result: &ReadResult, binary: bool) {
    println!("Port Data");
    let fmt_data = if binary {
        |byte| format!("0b{byte:08b}")
    } else {
        |byte| format!("0x{byte:02x}")
    };
    for (port, each) in read_result
        .modules
        .to_indices()
        .zip(read_result.data().iter())
    {
        let formatted_data = each.iter().map(fmt_data).collect::<Vec<_>>().join(",");
        println!("{port:>WIDTH$} [{formatted_data}]",);
    }
}

const ID_BYTE_WIDTH: usize = 5;
const ID_DEBUG_WIDTH: usize = 24;
const VENDOR_WIDTH: usize = 16;
const PART_WIDTH: usize = 16;
const REV_WIDTH: usize = 4;
const SERIAL_WIDTH: usize = 16;
const DATE_WIDTH: usize = 20;

fn print_module_identifier(ident_result: &IdentifierResult, kind: &OutputKind<IdentifyFields>) {
    match kind {
        OutputKind::Default => println!("Port Ident Description"),
        OutputKind::Parseable { fields, separator } => print_parseable_header(fields, separator),
    }

    for (port, id) in ident_result
        .modules
        .to_indices()
        .zip(ident_result.identifiers().iter())
    {
        let ident = format!("0x{:02x}", u8::from(*id));
        match kind {
            OutputKind::Default => {
                println!("{port:>WIDTH$} {ident:ID_BYTE_WIDTH$} {id}");
            }
            OutputKind::Parseable { fields, separator } => {
                fields.iter().map(|field| match field {
                    IdentifyFields::Port => port.to_string(),
                    IdentifyFields::Ident => ident.clone(),
                    IdentifyFields::Description => id.to_string(),
                }).collect::<Vec<_>>().join(separator.as_str());
            }
        }
    }
}

fn print_vendor_info(vendor_result: &VendorInfoResult, kind: &OutputKind<VendorInfoFields>) {
    match kind {
        OutputKind::Default => 
        println!(
            "Port {:ID_DEBUG_WIDTH$} {:VENDOR_WIDTH$} {:PART_WIDTH$} \
            {:REV_WIDTH$} {:SERIAL_WIDTH$} {:DATE_WIDTH$}",
            "Identifier", "Vendor", "Part", "Rev", "Serial", "Mfg date"
        ),
        OutputKind::Parseable { fields, separator } => print_parseable_header(fields, separator),
    }

    for (port, info) in vendor_result
        .modules
        .to_indices()
        .zip(vendor_result.vendor_info().iter())
    {
        let ident = format!(
            "{:?} (0x{:02x})",
            info.identifier,
            u8::from(info.identifier)
        );
        let date = info.vendor.date.as_deref().unwrap_or("Unknown");

        match kind {
            OutputKind::Default => {
                println!(
                    "{port:>WIDTH$} {:ID_DEBUG_WIDTH$} {:VENDOR_WIDTH$} \
                    {:PART_WIDTH$} {:REV_WIDTH$} {:SERIAL_WIDTH$} {:DATE_WIDTH$}",
                    ident, info.vendor.name, info.vendor.part, info.vendor.revision, info.vendor.serial, date,
                );
            }
            OutputKind::Parseable { fields, separator } => {
                println!("{}", fields.iter().map(|field| match field  {
                    VendorInfoFields::Port => port.to_string(),
                    VendorInfoFields::Identifier => ident.clone(),
                    VendorInfoFields::Vendor => info.vendor.name.clone(),
                    VendorInfoFields::Part => info.vendor.part.clone(),
                    VendorInfoFields::Rev => info.vendor.revision.clone(),
                    VendorInfoFields::Serial => info.vendor.serial.clone(),
                    VendorInfoFields::ManufacturedDate => date.to_string(),
                }).collect::<Vec<_>>().join(separator.as_str()));
            }
        }
    }
}

fn print_module_memory_model(model_result: &MemoryModelResult, kind: &OutputKind<MemoryModelFields>) {
    match kind {
        OutputKind::Default => println!("Port Model"),
        OutputKind::Parseable { fields, separator } => print_parseable_header(fields, separator),
    }

    for (port, model) in model_result
        .modules
        .to_indices()
        .zip(model_result.memory_models().iter())
    {
        match kind {
            OutputKind::Default => println!("{port:>WIDTH$} {model}"),
            OutputKind::Parseable { fields, separator } => {
                println!("{}", fields.iter().map(|field| match field  {
                    MemoryModelFields::Port => port.to_string(),
                    MemoryModelFields::Model => model.to_string(),
                }).collect::<Vec<_>>().join(separator.as_str()));
            }
        }
    }
}

fn print_mac_address_range(macs: MacAddrs, summary: bool) {
    if summary {
        let base: String = macs
            .base_mac()
            .iter()
            .map(|octet| format!("{octet:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        println!("Base:   {base}");
        println!("Count:  {}", macs.count());
        println!("Stride: {}", macs.stride());
    } else {
        for mac in macs.iter() {
            let mac_s: String = mac
                .iter()
                .map(|octet| format!("{octet:02x}"))
                .collect::<Vec<_>>()
                .join(":");
            println!("{mac_s}");
        }
    }
}

fn print_led_state(result: &LedStateResult, kind: &OutputKind<LedFields>) {
    match kind {
        OutputKind::Default => println!("Port LED"),
        OutputKind::Parseable { fields, separator } => print_parseable_header(fields, separator),
    }

    for (port, state) in result.iter() {
        println!("{port:>WIDTH$} {state:?}");
    }
}

// Helper to join a list of Display items with `,`.
fn display_list<T: std::fmt::Display>(items: impl Iterator<Item = T>) -> String {
    items
        .map(|i| format!("{i:0.4}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn print_monitors(monitor_result: &MonitorResult, kind: &OutputKind<MonitorFields>) {
    if let OutputKind::Parseable { fields, separator } = kind {
        print_parseable_header(fields, separator)
    }

    const NAME_WIDTH: usize = 22;
    let unsupported = String::from("--");
    let mut need_newline = false;
    for (port, monitor) in monitor_result.iter() {
        match kind {
            OutputKind::Default => {
                if need_newline {
                    println!();
                }
        
                // Start by printing the module address.
                println!("Port {port}");
        
                // Print module temperature, if supported.
                print!("  {:>NAME_WIDTH$}: ", "Temperature (C)");
                if let Some(temp) = monitor.temperature {
                    println!("{temp}");
                } else {
                    println!("{unsupported}");
                }
        
                // Print supply voltage, if supported.
                print!("  {:>NAME_WIDTH$}: ", "Supply voltage (V)");
                if let Some(volt) = monitor.supply_voltage {
                    println!("{volt}");
                } else {
                    println!("{unsupported}");
                }
        
                // Print the receiver power per-lane.
                //
                // Rx power is measured in one of two ways, either an average or
                // peak-to-peak measurement. Print that in the field name, followed by
                // the per-lane values themselves.
                if let Some(rx_pow) = &monitor.receiver_power {
                    let name = if matches!(rx_pow[0], ReceiverPower::Average(_)) {
                        "Avg Rx power (mW)"
                    } else {
                        "P-P Rx power (mW)"
                    };
                    let values = rx_pow.iter().map(|x| x.value());
                    println!("  {:>NAME_WIDTH$}: [{}]", name, display_list(values),);
                } else {
                    print!("  {:>NAME_WIDTH$}: ", "Rx power (mW)");
                    println!("{unsupported}");
                }
        
                // Print the Tx bias current.
                print!("  {:>NAME_WIDTH$}: ", "Tx bias (mA)");
                if let Some(tx_bias) = &monitor.transmitter_bias_current {
                    println!("[{}]", display_list(tx_bias.iter()));
                } else {
                    println!("{unsupported}");
                }
        
                // Print the Tx output power.
                print!("  {:>NAME_WIDTH$}: ", "Tx power (mW)");
                if let Some(tx_pow) = &monitor.transmitter_power {
                    println!("[{}]", display_list(tx_pow.iter()));
                } else {
                    println!("{unsupported}");
                }
        
                // Print each auxiliary monitor.
                //
                // The requires that we print the "observable", the thing being measured
                // as well. Each line is formatted like:
                //
                // Aux N, <observable> (<units>): <value>
                if let Some(Some(aux1)) = monitor.aux_monitors.map(|aux| aux.aux1) {
                    let (name, value) = match aux1 {
                        Aux1Monitor::TecCurrent(c) => ("Aux 1, TEC current (mA)", format!("{c}")),
                        Aux1Monitor::Custom(c) => {
                            ("Aux 1, Custom", format!("[0x{:02x},0x{:02x}]", c[0], c[1]))
                        }
                    };
                    println!("  {name:>NAME_WIDTH$}: {value}");
                } else {
                    println!("  {:>NAME_WIDTH$}: {unsupported}", "Aux 1");
                }
        
                if let Some(Some(aux2)) = monitor.aux_monitors.map(|aux| aux.aux2) {
                    let (name, value) = match aux2 {
                        Aux2Monitor::TecCurrent(c) => ("Aux 2, TEC current (mA)", format!("{c}")),
                        Aux2Monitor::LaserTemperature(t) => ("Aux 2, Laser temp (C)", format!("{t}")),
                    };
                    println!("  {name:>NAME_WIDTH$}: {value}");
                } else {
                    println!("  {:>NAME_WIDTH$}: {unsupported}", "Aux 2");
                }
        
                if let Some(Some(aux3)) = monitor.aux_monitors.map(|aux| aux.aux3) {
                    let (name, value) = match aux3 {
                        Aux3Monitor::LaserTemperature(t) => ("Aux 3, Laser temp (C)", format!("{t}")),
                        Aux3Monitor::AdditionalSupplyVoltage(v) => {
                            ("Aux 3, Supply voltage 2 (V)", format!("{v}"))
                        }
                    };
                    println!("  {name:>NAME_WIDTH$}: {value}");
                } else {
                    println!("  {:>NAME_WIDTH$}: {unsupported}", "Aux 3");
                }
                // Print additional newline between each port for clarity.
                need_newline = true;
            }
            OutputKind::Parseable { fields, separator } => {
                println!("{}", fields.iter().map(|field| match field {
                    MonitorFields::Port => port.to_string(),
                    MonitorFields::Temperature => monitor.temperature.map(|t| t.to_string()).unwrap_or_else(|| String::from("unsupported")),
                    MonitorFields::SupplyVoltage => monitor.supply_voltage.map(|v| v.to_string()).unwrap_or_else(|| String::from("unsupported")),
                    MonitorFields::AverageRxPower => monitor.receiver_power.as_ref().map(|rx| {
                        format!("[{}]", display_list(rx.iter().map(|x| x.value())))
                    }).unwrap_or_else(|| String::from("unsupported")),
                    MonitorFields::TxBias => monitor.transmitter_bias_current.as_ref().map(|tx| {
                        format!("[{}]", display_list(tx.iter()))
                    }).unwrap_or_else(|| String::from("unsupported")),
                    MonitorFields::TxPower => monitor.transmitter_power.as_ref().map(|tx| {
                        format!("[{}]", display_list(tx.iter()))
                    }).unwrap_or_else(|| String::from("unsupported")),
                    // MonitorFields::Aux1 => monitor.temperature.map(|t| t.to_string()).unwrap_or_else(|| String::from("unsupported")),
                    MonitorFields::Aux1 => unimplemented!(),
                    // MonitorFields::Aux2 => monitor.temperature.map(|t| t.to_string()).unwrap_or_else(|| String::from("unsupported")),
                    MonitorFields::Aux2 => unimplemented!(),
                    // MonitorFields::Aux3 => monitor.temperature.map(|t| t.to_string()).unwrap_or_else(|| String::from("unsupported")),
                    MonitorFields::Aux3 => unimplemented!(),
                }).collect::<Vec<_>>().join(separator.as_str()));
            }
        }
    }
}

fn print_datapath(datapath: &DatapathResult) {
    let mut need_newline = false;
    for (port, path) in datapath.iter() {
        if need_newline {
            println!();
        }

        match path {
            Datapath::Sff8636 {
                specification,
                lanes,
                connector,
            } => print_sff8636_datapath(port, connector, specification, lanes),
            Datapath::Cmis {
                connector,
                supported_lanes,
                datapaths,
            } => print_cmis_datapath(port, connector, *supported_lanes, datapaths),
        }

        need_newline = true;
    }
}

type CmisLaneStatusPrinter = fn(&CmisLaneStatus) -> String;
type CmisRowPrinter<'a> = (&'a str, CmisLaneStatusPrinter);

fn print_cmis_datapath(
    port: u8,
    connector: &ConnectorType,
    supported_lanes: u8,
    datapaths: &BTreeMap<u8, transceiver_decode::CmisDatapath>,
) {
    println!("Port {port}");
    println!("        Connector: {connector}");
    for (id, datapath) in datapaths.iter() {
        println!("   Application ID: {}", id);
        println!(
            "  Supported lanes: [{}]",
            (0..8u8)
                .filter(|bit| supported_lanes & (1 << bit) != 0)
                .map(|index| (index + 1).to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        println!("   Host interface: {}", datapath.application.host_id);
        println!("  Media interface: {}", datapath.application.media_id);
        const ROWS: &[CmisRowPrinter] = &[
            ("State", |st| st.state.to_string()),
            ("Tx enabled", |st| {
                st.tx_output_enabled
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| String::from("Unsupported"))
            }),
            ("Tx input polarity", |st| {
                st.tx_input_polarity
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| String::from("Unsupported"))
            }),
            ("Tx auto-squelch", |st| {
                st.tx_auto_squelch_disable
                    .map(|p| {
                        if p {
                            String::from("Disabled")
                        } else {
                            String::from("Enabled")
                        }
                    })
                    .unwrap_or_else(|| String::from("Unsupported"))
            }),
            ("Tx force-squelch", |st| {
                st.tx_force_squelch
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| String::from("Unsupported"))
            }),
            ("Tx output", |st| st.tx_output_status.to_string()),
            ("Tx failure", |st| {
                st.tx_failure
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| String::from("Unsupported"))
            }),
            ("Tx LOS", |st| {
                st.tx_los
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| String::from("Unsupported"))
            }),
            ("Tx LOL", |st| {
                st.tx_lol
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| String::from("Unsupported"))
            }),
            ("Tx adaptive EQ fail", |st| {
                st.tx_adaptive_eq_fail
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| String::from("Unsupported"))
            }),
            ("Rx enabled", |st| {
                st.rx_output_enabled
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| String::from("Unsupported"))
            }),
            ("Rx output polarity", |st| {
                st.rx_output_polarity
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| String::from("Unsupported"))
            }),
            ("Rx auto-squelch", |st| {
                st.rx_auto_squelch_disable
                    .map(|p| {
                        if p {
                            String::from("Disabled")
                        } else {
                            String::from("Enabled")
                        }
                    })
                    .unwrap_or_else(|| String::from("Unsupported"))
            }),
            ("Rx output", |st| st.rx_output_status.to_string()),
            ("Rx LOS", |st| {
                st.rx_los
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| String::from("Unsupported"))
            }),
            ("Rx LOL", |st| {
                st.rx_lol
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| String::from("Unsupported"))
            }),
        ];
        if !datapath.lane_status.is_empty() {
            let mut builder = Builder::new();
            // Push header row
            let mut header = vec![String::new()];
            header.extend(
                datapath
                    .lane_status
                    .keys()
                    .map(|lane| format!("Lane {lane}")),
            );
            builder.push_record(header);
            for (name, getter) in ROWS.iter() {
                let mut row = vec![String::from(*name)];
                for (_, status) in datapath.lane_status.iter() {
                    row.push(getter(status).to_string());
                }
                builder.push_record(row);
            }
            println!("{}", builder.build().with(Style::empty()));
        }
        println!();
    }
}

type SffDatapathFlagGetter = fn(&Sff8636Datapath) -> bool;
type SffDatapathRowGetter<'a> = (&'a str, SffDatapathFlagGetter);

fn print_sff8636_datapath(
    port: u8,
    connector: &ConnectorType,
    specification: &SffComplianceCode,
    lanes: &[Sff8636Datapath; 4],
) {
    println!("Port {port}");
    println!("        Connector: {connector}");
    println!("    Specification: {specification}");
    println!();
    let mut builder = Builder::with_capacity(9, 5);
    let mut headers = vec![String::new()];
    headers.extend((0..4).map(|lane| format!("Lane {lane}")));
    builder.push_record(headers);
    const ROWS: &[SffDatapathRowGetter] = &[
        ("Tx enabled", |p| p.tx_enabled),
        ("Tx LOS", |p| p.tx_los),
        ("Tx LOL", |p| p.tx_lol),
        ("Tx CDR enabled", |p| p.tx_cdr_enabled),
        ("Tx adapt EQ fault", |p| p.tx_adaptive_eq_fault),
        ("Tx fault", |p| p.tx_fault),
        ("Rx LOS", |p| p.rx_los),
        ("Rx LOL", |p| p.rx_lol),
        ("Rx CDR enabled", |p| p.rx_cdr_enabled),
    ];
    for (name, getter) in ROWS.iter() {
        let mut row = vec![String::from(*name)];
        for lane in lanes.iter() {
            row.push(getter(lane).to_string());
        }
        builder.push_record(row);
    }
    println!("{}", builder.build().with(Style::empty()));
}

fn print_parseable_header<T>(fields: &[T], separator: &ParseableOutputSeparator) where T: ValueEnum {
    let header = fields.iter().map(|field| {
        field
            .to_possible_value()
            .map(|value| value.get_name().to_string())
            .expect("Unknown field {:field?}")
    })
    .collect::<Vec<_>>().join(separator.as_str());

    println!("{}", header);
}

#[cfg(test)]
mod tests {
    use crate::read_u8;

    use super::load_write_data;
    use super::load_write_data_autodetect_kind;
    use super::parse_transceivers;
    use super::InputKind;
    use super::ManagementInterface;
    use super::ModuleId;
    use super::PowerState;
    use super::Transceivers;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Read from file:
    //
    // binary
    // hex with prefix / without prefix
    // decimal
    // binary string with / without prefix
    //
    // Read from stdin

    #[test]
    fn test_load_write_data_binary() {
        let mut f = NamedTempFile::new().unwrap();
        f.write(&[1, 2, 3]).unwrap();
        assert_eq!(
            load_write_data(Some(f.path().to_path_buf()), Some(InputKind::Binary)).unwrap(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn test_load_write_data_binary_string() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "0b00 0b01 0b11").unwrap();
        assert_eq!(
            load_write_data(Some(f.path().to_path_buf()), Some(InputKind::BinaryString)).unwrap(),
            vec![0b00, 0x01, 0b11]
        );
    }

    #[test]
    fn test_load_write_data_binary_string_with_0b_prefix() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "00 01 11").unwrap();
        assert_eq!(
            load_write_data(Some(f.path().to_path_buf()), Some(InputKind::BinaryString)).unwrap(),
            vec![0b00, 0b01, 0b11]
        );
    }

    #[test]
    fn test_load_write_data_hex() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "aa bb cc").unwrap();
        assert_eq!(
            load_write_data(Some(f.path().to_path_buf()), Some(InputKind::Hex)).unwrap(),
            vec![0xaa, 0xbb, 0xcc]
        );
    }

    #[test]
    fn test_load_write_data_hex_with_0x_prefix() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "0xaa 0xbb 0xcc").unwrap();
        assert_eq!(
            load_write_data(Some(f.path().to_path_buf()), Some(InputKind::Hex)).unwrap(),
            vec![0xaa, 0xbb, 0xcc]
        );
    }

    #[test]
    fn test_load_write_data_decimal() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "10 20 30").unwrap();
        assert_eq!(
            load_write_data(Some(f.path().to_path_buf()), Some(InputKind::Decimal)).unwrap(),
            vec![10, 20, 30]
        );
    }

    #[test]
    fn test_load_write_data_decimal_trailing_newline() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "10 20 30\n").unwrap();
        assert_eq!(
            load_write_data(Some(f.path().to_path_buf()), Some(InputKind::Decimal)).unwrap(),
            vec![10, 20, 30]
        );
    }

    #[test]
    fn test_load_write_data_autodetect() {
        let data = [10, 20, 30];
        test_load_autodetect(&data, InputKind::BinaryString);
        test_load_autodetect(&data, InputKind::Hex);
        test_load_autodetect(&data, InputKind::Decimal);
    }

    fn test_load_autodetect(data: &[u8], kind: InputKind) {
        let data_as_string: Vec<String> = match kind {
            InputKind::Decimal => data.iter().map(ToString::to_string).collect(),
            InputKind::Hex => data.iter().map(|x| format!("0x{x:x}")).collect(),
            InputKind::BinaryString => data.iter().map(|x| format!("0b{x:b}")).collect(),
            _ => unimplemented!(),
        };
        let all_data = data_as_string.join(" ");
        let loaded = load_write_data_autodetect_kind(all_data.clone()).unwrap();
        assert_eq!(
            data, loaded,
            "failed to autodetect / load data for input kind {:?}",
            kind,
        );
    }

    #[test]
    fn test_parse_transceivers() {
        assert_eq!(parse_transceivers("all").unwrap(), Transceivers::All);
        assert_eq!(
            parse_transceivers("present").unwrap(),
            Transceivers::Present
        );
        assert_eq!(
            parse_transceivers("off").unwrap(),
            Transceivers::PowerState(PowerState::Off)
        );
        assert_eq!(
            parse_transceivers("low-power").unwrap(),
            Transceivers::PowerState(PowerState::Low)
        );
        assert_eq!(
            parse_transceivers("hi-power").unwrap(),
            Transceivers::PowerState(PowerState::High)
        );
        assert_eq!(
            parse_transceivers("cmis").unwrap(),
            Transceivers::Kind(ManagementInterface::Cmis)
        );
        assert_eq!(
            parse_transceivers("sff").unwrap(),
            Transceivers::Kind(ManagementInterface::Sff8636)
        );

        let test_data = &[
            ("0", ModuleId(0b1)),
            ("0,1,2", ModuleId(0b111)),
            ("0-2", ModuleId(0b111)),
            ("0,1-2", ModuleId(0b111)),
            ("0,0-2", ModuleId(0b111)),
            ("0,1,2,0-3", ModuleId(0b1111)),
        ];
        for (s, m) in test_data.iter() {
            assert_eq!(parse_transceivers(s).unwrap(), Transceivers::Index(*m));
        }

        assert!(parse_transceivers(" ").is_err());
        assert!(parse_transceivers("10000000").is_err());
        assert!(parse_transceivers("0,-1").is_err());
        assert!(parse_transceivers("1-").is_err());
        assert!(parse_transceivers("1-0").is_err());
        assert!(parse_transceivers("0,1000000").is_err());
        assert!(parse_transceivers("0-10,1000000").is_err());
        assert!(parse_transceivers("0-100").is_err());
    }

    #[test]
    fn test_read_u8() {
        assert_eq!(read_u8("01").unwrap(), 1);
        assert_eq!(read_u8("0x01").unwrap(), 1);
        assert!(read_u8("ff").is_err());
        assert_eq!(read_u8("0xff").unwrap(), 0xff);
    }
}
