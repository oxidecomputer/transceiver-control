// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Command-line tool to administer optical transceivers.

use anyhow::ensure;
use anyhow::Context;
use clap::ArgGroup;
use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;
use slog::Drain;
use slog::Level;
use std::fs::File;
use std::io::stdin;
use std::io::Read;
use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::mpsc;
use transceiver_controller::Config;
use transceiver_controller::Controller;
use transceiver_controller::FailedModules;
use transceiver_controller::IdentifierResult;
use transceiver_controller::MemoryModelResult;
use transceiver_controller::PowerModeResult;
use transceiver_controller::PowerState;
use transceiver_controller::ReadResult;
use transceiver_controller::SpRequest;
use transceiver_controller::StatusResult;
use transceiver_controller::VendorInfoResult;
use transceiver_decode::VendorInfo;
use transceiver_messages::filter_module_data;
use transceiver_messages::mac::MacAddrs;
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
    /// power mode.
    ///
    /// - "cmis" and "sff" address all transceivers of the provided management
    /// interface.
    ///
    /// - A comma-separated list of integers or integer ranges. E.g., `0,1,2` or
    /// `0-2,4`. Ranges are inclusive of both ends.
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
    /// Input is decimal text.
    Decimal,
    /// Input is hexadecimal text.
    Hex,
}

// How to print the `Status`.
#[derive(Clone, Copy, Debug)]
enum StatusKind {
    // Print the usual Display representation of each set of status bits.
    Normal,
    // Print the truth value of a set of status bits, from all modules.
    Limited { with: Status, without: Status },
    // Print all bits from all modules.
    All,
}

#[derive(Clone, Copy, Debug, clap::Parser)]
struct StatusFlags {
    /// Find modules with the provided flags set.
    #[arg(short, value_parser = parse_status)]
    with: Option<Status>,
    /// Find modules without the provided flags set.
    #[arg(short, value_parser = parse_status)]
    without: Option<Status>,
}

fn parse_status(s: &str) -> Result<Status, String> {
    s.parse::<Status>().map_err(|e| e.to_string())
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
        with: Option<Status>,
        #[arg(long, value_parser = parse_status, conflicts_with = "all")]
        without: Option<Status>,

        /// Print all bits from all modules.
        ///
        /// This shows a table, where rows are modules and columns the status
        /// bit. For each module, if the module contains the relevant status bit
        /// a "1" is printed. Otherwise a "0" is printed.
        #[arg(long)]
        all: bool,
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
    Power,

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
    Identify,

    /// Read the vendor information for a set of modules.
    VendorInfo,

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
        offset: u8,

        /// The number of bytes to read.
        len: u8,
    },

    /// Write the lower page of a set of transceiver modules.
    #[command(group(ArgGroup::new("interface").required(true).args(["sff", "cmis"])))]
    WriteLower {
        /// Interpret the module's memory map as SFF-8636.
        #[arg(long)]
        sff: bool,

        /// Interpret the module's memory map as CMIS.
        #[arg(long)]
        cmis: bool,

        /// The input file for data, defaulting to stdin.
        #[arg(short, long)]
        input: Option<PathBuf>,

        /// How to interpret the input data.
        #[arg(long, default_value_t = InputKind::Binary, value_enum)]
        input_kind: InputKind,

        /// The offset to start writing to.
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
        #[arg(short, long, default_value_t = 0)]
        page: u8,

        /// For CMIS modules, the bank of the upper page to read from.
        ///
        /// Note that some pages require a bank and others may not have a bank.
        /// The validity will be checked at runtime.
        #[arg(short, long, conflicts_with("sff"))]
        bank: Option<u8>,

        /// The offset to start reading from.
        ///
        /// Note that offsets are always specified as relative to the full
        /// 256-byte transceiver memory map. E.g., to read starting from the
        /// first byte of an upper page, the value `128` should be specified.
        offset: u8,

        /// The number of bytes to read.
        len: u8,
    },

    /// Write the upper page of a set of transceiver modules.
    #[command(group(ArgGroup::new("interface").required(true).args(["sff", "cmis"])))]
    WriteUpper {
        /// Interpret the module's memory map as SFF-8636.
        #[arg(long)]
        sff: bool,

        /// Interpret the module's memory map as CMIS.
        #[arg(long)]
        cmis: bool,

        /// The input file for data, defaulting to stdin.
        #[arg(short, long)]
        input: Option<PathBuf>,

        /// How to interpret the input data.
        #[arg(long, default_value_t = InputKind::Binary, value_enum)]
        input_kind: InputKind,

        /// The upper page to read from.
        #[arg(short, long, default_value_t = 0)]
        page: u8,

        /// For CMIS modules, the bank of the upper page to read from.
        ///
        /// Note that some pages require a bank and others may not have a bank.
        /// The validity will be checked at runtime.
        #[arg(short, long, conflicts_with("sff"))]
        bank: Option<u8>,

        /// The offset to start writing to.
        ///
        /// Note that offsets are always specified as relative to the full
        /// 256-byte transceiver memory map. E.g., to read starting from the
        /// first byte of an upper page, the value `128` should be specified.
        offset: u8,
    },

    /// Describe the memory model of a set of modules.
    ///
    /// If a module supports paged memory, the list of pages is printed. For
    /// modules which support banked pages (CMIS only), the maximum supported
    /// bank is also printed following each banked page. For example, `0x10/1`
    /// indicates that page `0x10` is supported, and the module implements banks
    /// 0 and 1 (16 lanes).
    MemoryModel,

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
}

fn load_write_data(file: Option<PathBuf>, kind: InputKind) -> anyhow::Result<Vec<u8>> {
    let mut rdr: Box<dyn Read> = if let Some(path) = file {
        Box::new(File::open(path)?)
    } else {
        Box::new(stdin())
    };

    const MAX_BYTES: usize = 128;
    match kind {
        InputKind::Binary => {
            let mut data = vec![0; MAX_BYTES];
            let n_bytes = rdr.read(&mut data)?;
            data.truncate(n_bytes);
            Ok(data)
        }
        text => {
            let radix = if matches!(text, InputKind::Decimal) {
                10
            } else {
                16
            };
            let conv = |x| u8::from_str_radix(x, radix).map_err(anyhow::Error::from);
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
        Cmd::Status { with, without, all } => {
            let kind = match (with, without, all) {
                (None, None, false) => StatusKind::Normal,
                (None, None, true) => StatusKind::All,
                (maybe_with, maybe_without, false) => {
                    let with = maybe_with.unwrap_or_else(Status::empty);
                    let without = maybe_without.unwrap_or_else(Status::empty);
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
            let status_result = controller
                .status(modules)
                .await
                .context("Failed to retrieve module status")?;
            print_module_status(&status_result, kind);
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

        Cmd::Power => {
            let mode_result = controller
                .power(modules)
                .await
                .context("Failed to get power mode")?;
            print_power_mode(&mode_result);
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

        Cmd::Identify => {
            let ident_result = controller
                .identifier(modules)
                .await
                .context("Failed to identify transceiver modules")?;
            print_module_identifier(&ident_result);
            if !args.ignore_errors {
                print_failures(&ident_result.failures);
            }
        }

        Cmd::VendorInfo => {
            let info_result = controller
                .vendor_info(modules)
                .await
                .context("Failed to fetch vendor information for transceiver modules")?;
            print_vendor_info(&info_result);
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
            let read = match (sff, cmis) {
                (true, false) => MemoryRead::new(sff8636::Page::Lower, offset, len)
                    .context("Failed to setup lower page memory read")?,
                (false, true) => MemoryRead::new(cmis::Page::Lower, offset, len)
                    .context("Failed to setup lower page memory read")?,
                (_, _) => unreachable!("clap didn't do its job"),
            };
            let read_result = controller
                .read(modules, read)
                .await
                .context("Failed to read transceiver modules")?;
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
            let read = match (sff, cmis) {
                (true, false) => {
                    let page =
                        sff8636::UpperPage::new(page).context("Invalid SFF-8636 upper page")?;
                    MemoryRead::new(sff8636::Page::Upper(page), offset, len)
                        .context("Failed to setup upper page memory read")?
                }
                (false, true) => {
                    let page = if let Some(bank) = bank {
                        cmis::UpperPage::new_banked(page, bank)
                    } else {
                        cmis::UpperPage::new_unbanked(page)
                    }
                    .context("Invalid CMIS upper page")?;
                    MemoryRead::new(cmis::Page::Upper(page), offset, len)
                        .context("Failed to setup upper page memory read")?
                }
                (_, _) => unreachable!("clap didn't do its job"),
            };
            let read_result = controller
                .read(modules, read)
                .await
                .context("Failed to read transceiver modules")?;
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
        Cmd::MemoryModel => {
            let layout_result = controller
                .memory_model(modules)
                .await
                .context("Failed to get memory model")?;
            print_module_memory_model(&layout_result);
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
            print_failures(&ack_result.failures);
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
            let modules = ModuleId::all();
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
            let modules = ModuleId::all();
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
                .identifier(ModuleId::all())
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

fn print_power_mode(mode_result: &PowerModeResult) {
    println!("Port  Power  Software-override");
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
        println!("{port:>WIDTH$}  {state:POWER_WIDTH$}  {over}",);
    }
}

fn print_module_status(status_result: &StatusResult, kind: StatusKind) {
    match kind {
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
    println!(" +--------------------------------- Port");
    println!(" |   +----------------------------- {}", Status::PRESENT);
    println!(" |   |   +------------------------- {}", Status::ENABLED);
    println!(" |   |   |   +--------------------- {}", Status::RESET);
    println!(" |   |   |   |   +----------------- {}", Status::LOW_POWER_MODE);
    println!(" |   |   |   |   |   +------------- {}", Status::INTERRUPT);
    println!(" |   |   |   |   |   |   +--------- {}", Status::POWER_GOOD);
    println!(" |   |   |   |   |   |   |   +----- {}", Status::FAULT_POWER_TIMEOUT);
    println!(" |   |   |   |   |   |   |   |   +- {}", Status::FAULT_POWER_LOST);
    println!(" v   v   v   v   v   v   v   v   v");
}

fn print_all_status(status_result: &StatusResult) {
    print_all_status_header();
    for (port, status) in status_result
        .modules
        .to_indices()
        .zip(status_result.status().iter())
    {
        print!("{port:>2}   ");
        for bit in Status::all().iter() {
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

fn print_module_identifier(ident_result: &IdentifierResult) {
    println!("Port Ident Description");
    for (port, id) in ident_result
        .modules
        .to_indices()
        .zip(ident_result.identifiers().iter())
    {
        let ident = format!("0x{:02x}", u8::from(*id));
        println!("{port:>WIDTH$} {ident:ID_BYTE_WIDTH$} {id}");
    }
}

fn print_vendor_info(vendor_result: &VendorInfoResult) {
    println!(
        "Port {:ID_DEBUG_WIDTH$} {:VENDOR_WIDTH$} {:PART_WIDTH$} \
        {:REV_WIDTH$} {:SERIAL_WIDTH$} {:DATE_WIDTH$}",
        "Identifier", "Vendor", "Part", "Rev", "Serial", "Mfg date"
    );
    for (port, inf) in vendor_result
        .modules
        .to_indices()
        .zip(vendor_result.vendor_info().iter())
    {
        print_single_module_vendor_info(port, inf);
    }
}

fn print_single_module_vendor_info(port: u8, info: &VendorInfo) {
    let ident = format!(
        "{:?} (0x{:02x})",
        info.identifier,
        u8::from(info.identifier)
    );
    let date = info.vendor.date.as_deref().unwrap_or("Unknown");
    println!(
        "{port:>WIDTH$} {:ID_DEBUG_WIDTH$} {:VENDOR_WIDTH$} \
        {:PART_WIDTH$} {:REV_WIDTH$} {:SERIAL_WIDTH$} {:DATE_WIDTH$}",
        ident, info.vendor.name, info.vendor.part, info.vendor.revision, info.vendor.serial, date,
    );
}

fn print_module_memory_model(model_result: &MemoryModelResult) {
    println!("Port Model");
    for (port, model) in model_result
        .modules
        .to_indices()
        .zip(model_result.memory_models().iter())
    {
        println!("{port:>WIDTH$} {model}");
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

#[cfg(test)]
mod tests {
    use super::load_write_data;
    use super::parse_transceivers;
    use super::InputKind;
    use super::ManagementInterface;
    use super::ModuleId;
    use super::PowerState;
    use super::Transceivers;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_write_data_binary() {
        let mut f = NamedTempFile::new().unwrap();
        f.write(&[1, 2, 3]).unwrap();
        assert_eq!(
            load_write_data(Some(f.path().to_path_buf()), InputKind::Binary).unwrap(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn test_load_write_data_hex() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "aa bb cc").unwrap();
        assert_eq!(
            load_write_data(Some(f.path().to_path_buf()), InputKind::Hex).unwrap(),
            vec![0xaa, 0xbb, 0xcc]
        );
    }

    #[test]
    fn test_load_write_data_decimal() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "10 20 30").unwrap();
        assert_eq!(
            load_write_data(Some(f.path().to_path_buf()), InputKind::Decimal).unwrap(),
            vec![10, 20, 30]
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
}
