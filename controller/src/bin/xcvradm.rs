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
use transceiver_controller::PowerMode;
use transceiver_controller::SpRequest;
use transceiver_decode::Identifier;
use transceiver_decode::MemoryModel;
use transceiver_decode::VendorInfo;
use transceiver_messages::message::Status;
use transceiver_messages::mgmt::cmis;
use transceiver_messages::mgmt::sff8636;
use transceiver_messages::mgmt::ManagementInterface;
use transceiver_messages::mgmt::MemoryRead;
use transceiver_messages::mgmt::MemoryWrite;
use transceiver_messages::MacAddrs;
use transceiver_messages::ModuleId;
use transceiver_messages::PortMask;

fn parse_log_level(s: &str) -> Result<Level, String> {
    s.parse().map_err(|_| String::from("invalid log level"))
}

// Method for addressing a set of transceivers by index or state.
#[derive(Clone, Debug, PartialEq)]
enum Transceivers {
    // All transceivers on an FPGA, the default.
    All,
    // All present transceivers on an FGPA.
    Present,
    // All transceivers in a specific power mode.
    PowerMode(PowerMode),
    // All transceivers of a specific kind.
    Kind(ManagementInterface),
    // A comma-separated list of transceiver indices. These can be specified as
    // single integers, e.g., `4,5,6` or an inclusive range, e.g., `4-6`.
    Ports(PortMask),
}

fn parse_transceivers(s: &str) -> Result<Transceivers, String> {
    let s = s.to_lowercase();
    match s.as_str() {
        "all" => Ok(Transceivers::All),
        "present" => Ok(Transceivers::Present),
        "off" => Ok(Transceivers::PowerMode(PowerMode::Off)),
        "low-power" | "lp" => Ok(Transceivers::PowerMode(PowerMode::Low)),
        "hi-power" | "high-power" | "hp" => Ok(Transceivers::PowerMode(PowerMode::High)),
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
            PortMask::from_indices(&indices)
                .map(|p| Transceivers::Ports(p))
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

    /// The FPGA whose transceivers to address.
    #[arg(short, long, default_value_t = 0)]
    fpga_id: u8,

    /// The list of transcievers on the FPGA to address.
    ///
    /// Transceivers may be addressed in a number of ways:
    ///
    /// - "all" addresses all transceivers on the FPGA. This is the default.
    ///
    /// - "present" addresses all present transceivers on the FPGA.
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

#[derive(Subcommand)]
enum Cmd {
    /// Return the status of the addressed modules, such as presence, power
    /// enable, and power mode.
    Status,

    /// Have the SP execute a reset of the addressed modules.
    Reset,

    /// Set the power module of the addressed modules.
    SetPower {
        /// The desired power mode.
        #[arg(value_enum)]
        mode: PowerMode,
    },

    /// Return the power mode of the addressed modules.
    ///
    /// This takes into account whether a module has specified software override
    /// of power control.
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
    let modules = address_transceivers(&controller, args.fpga_id, transceivers).await?;

    match args.cmd {
        Cmd::Status => {
            let status = controller
                .status(modules)
                .await
                .context("Failed to retrieve module status")?;
            print_module_status(modules, status);
        }

        Cmd::Reset => {
            controller
                .reset(modules)
                .await
                .context("Failed to reset modules")?;
        }

        Cmd::SetPower { mode } => {
            controller
                .set_power_mode(modules, mode)
                .await
                .context("Failed to set power mode")?;
        }

        Cmd::Power => {
            let states = controller
                .power_mode(modules)
                .await
                .context("Failed to get power mode")?;
            print_power_mode(modules, states);
        }

        Cmd::EnablePower => {
            controller
                .enable_power(modules)
                .await
                .context("Failed to enable power for modules")?;
        }

        Cmd::DisablePower => {
            controller
                .disable_power(modules)
                .await
                .context("Failed to disable power for modules")?;
        }

        Cmd::AssertReset => {
            controller
                .assert_reset(modules)
                .await
                .context("Failed to assert reset for modules")?;
        }

        Cmd::DeassertReset => {
            controller
                .deassert_reset(modules)
                .await
                .context("Failed to deassert reset for modules")?;
        }

        Cmd::AssertLpMode => {
            controller
                .assert_lpmode(modules)
                .await
                .context("Failed to assert lpmode for modules")?;
        }

        Cmd::DeassertLpMode => {
            controller
                .deassert_lpmode(modules)
                .await
                .context("Failed to deassert lpmode for modules")?;
        }

        Cmd::Identify => {
            let ids = controller
                .identifier(modules)
                .await
                .context("Failed to identify transceiver modules")?;
            print_module_identifier(modules, ids);
        }

        Cmd::VendorInfo => {
            let info = controller
                .vendor_info(modules)
                .await
                .context("Failed to fetch vendor information for transceiver modules")?;
            print_vendor_info(modules, info);
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
            let data = controller
                .read(modules, read)
                .await
                .context("Failed to read transceiver modules")?;
            print_read_data(modules, data, binary);
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
            controller
                .write(modules, write, &data)
                .await
                .context("Failed to write transceiver modules")?;
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
            let data = controller
                .read(modules, read)
                .await
                .context("Failed to read transceiver modules")?;
            print_read_data(modules, data, binary);
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
            controller
                .write(modules, write, &data)
                .await
                .context("Failed to write transceiver modules")?;
        }
        Cmd::MemoryModel => {
            let layout = controller
                .memory_model(modules)
                .await
                .context("Failed to get memory model")?;
            print_module_memory_model(modules, layout);
        }
        Cmd::Macs { summary } => {
            let macs = controller
                .mac_addrs()
                .await
                .context("Failed to get MAC addresses")?;
            print_mac_address_range(macs, summary);
        }
    }
    Ok(())
}

async fn address_transceivers(
    controller: &Controller,
    fpga_id: u8,
    transceivers: Transceivers,
) -> anyhow::Result<ModuleId> {
    fn filter_ports<D: IntoIterator>(
        ports: PortMask,
        data: D,
        predicate: impl Fn(D::Item) -> bool,
    ) -> PortMask {
        let ix: Vec<_> = ports
            .to_indices()
            .zip(data.into_iter())
            .filter_map(|(ix, datum)| if predicate(datum) { Some(ix) } else { None })
            .collect();
        PortMask::from_indices(&ix).unwrap()
    }

    let ports = match transceivers {
        Transceivers::All => PortMask::all(),
        Transceivers::Present => {
            // Fetch all status bits, and find those which match.
            let modules = ModuleId::all_transceivers(fpga_id);
            let status = controller
                .status(modules)
                .await
                .context("Failed to retrieve module status")?;
            filter_ports(modules.ports, status, |st| st.contains(Status::PRESENT))
        }
        Transceivers::PowerMode(mode) => {
            // Fetch all power modes, and find those which match.
            let modules = ModuleId::all_transceivers(fpga_id);
            let module_modes = controller
                .power_mode(modules)
                .await
                .context("Failed to retrieve module power mode")?;
            filter_ports(modules.ports, module_modes, |m| m.0 == mode)
        }
        Transceivers::Kind(kind) => {
            // Fetch all modules that are in at least low-power mode, and thus
            // readable.
            let modules = ModuleId::all_transceivers(fpga_id);
            let power_modes = controller
                .power_mode(modules)
                .await
                .context("Failed to retrieve module power mode")?;
            let readable = filter_ports(modules.ports, power_modes, |m| {
                matches!(m.0, PowerMode::Low | PowerMode::High)
            });

            // Then the management interface for those.
            let modules = ModuleId {
                fpga_id,
                ports: readable,
            };
            let identifiers = controller
                .identifier(modules)
                .await
                .context("Failed to retrieve module identifiers")?;
            let predicate = |id: Identifier| {
                if let Ok(iface) = id.management_interface() {
                    iface == kind
                } else {
                    false
                }
            };
            filter_ports(modules.ports, identifiers, predicate)
        }
        Transceivers::Ports(p) => p,
    };
    Ok(ModuleId { fpga_id, ports })
}

// Column width for printing data below.
const WIDTH: usize = 4;
const POWER_WIDTH: usize = 5;

fn print_power_mode(modules: ModuleId, modes: Vec<(PowerMode, Option<bool>)>) {
    println!("FPGA  Port  Power  Software-override");
    for (port, (mode, override_)) in modules.ports.to_indices().zip(modes.into_iter()) {
        let over = match override_ {
            None => "-",
            Some(true) => "Yes",
            Some(false) => "No",
        };
        let mode = format!("{mode:?}");
        println!(
            "{:>WIDTH$}  {port:>WIDTH$}  {mode:POWER_WIDTH$}  {over}",
            modules.fpga_id
        );
    }
}

fn print_module_status(modules: ModuleId, status: Vec<Status>) {
    println!("FPGA Port Status");
    for (port, status) in modules.ports.to_indices().zip(status.into_iter()) {
        println!("{:>WIDTH$} {port:>WIDTH$} {status:?}", modules.fpga_id);
    }
}

fn print_read_data(modules: ModuleId, data: Vec<Vec<u8>>, binary: bool) {
    println!("FPGA Port Data");
    let fmt_data = if binary {
        |byte| format!("0b{byte:08b}")
    } else {
        |byte| format!("0x{byte:02x}")
    };
    for (port, each) in modules.ports.to_indices().zip(data.into_iter()) {
        let formatted_data = each.into_iter().map(fmt_data).collect::<Vec<_>>().join(",");
        println!(
            "{:>WIDTH$} {port:>WIDTH$} [{formatted_data}]",
            modules.fpga_id
        );
    }
}

const ID_BYTE_WIDTH: usize = 5;
const ID_DEBUG_WIDTH: usize = 20;
const VENDOR_WIDTH: usize = 16;
const PART_WIDTH: usize = 16;
const REV_WIDTH: usize = 4;
const SERIAL_WIDTH: usize = 16;
const DATE_WIDTH: usize = 20;

fn print_module_identifier(modules: ModuleId, ids: Vec<Identifier>) {
    println!("FPGA Port Ident Description");
    let fpga_id = modules.fpga_id;
    for (port, id) in modules.ports.to_indices().zip(ids.into_iter()) {
        let ident = format!("0x{:02x}", u8::from(id));
        println!("{fpga_id:>WIDTH$} {port:>WIDTH$} {ident:ID_BYTE_WIDTH$} {id}");
    }
}

fn print_vendor_info(modules: ModuleId, info: Vec<VendorInfo>) {
    println!(
        "FPGA Port {:ID_DEBUG_WIDTH$} {:VENDOR_WIDTH$} {:PART_WIDTH$} \
        {:REV_WIDTH$} {:SERIAL_WIDTH$} {:DATE_WIDTH$}",
        "Identifier", "Vendor", "Part", "Rev", "Serial", "Mfg date"
    );
    let fpga_id = modules.fpga_id;
    for (port, inf) in modules.ports.to_indices().zip(info.into_iter()) {
        print_single_module_vendor_info(fpga_id, port, inf);
    }
}

fn print_single_module_vendor_info(fpga_id: u8, port: u8, info: VendorInfo) {
    let ident = format!(
        "{:?} (0x{:02x})",
        info.identifier,
        u8::from(info.identifier)
    );
    println!(
        "{fpga_id:>WIDTH$} {port:>WIDTH$} {:ID_DEBUG_WIDTH$} {:VENDOR_WIDTH$} \
        {:PART_WIDTH$} {:REV_WIDTH$} {:SERIAL_WIDTH$} {:DATE_WIDTH$}",
        ident,
        info.vendor.name,
        info.vendor.part,
        info.vendor.revision,
        info.vendor.serial,
        info.vendor.date,
    );
}

fn print_module_memory_model(modules: ModuleId, models: Vec<MemoryModel>) {
    println!("FPGA Port Model");
    let fpga_id = modules.fpga_id;
    for (port, model) in modules.ports.to_indices().zip(models.into_iter()) {
        println!("{fpga_id:>WIDTH$} {port:>WIDTH$} {model}");
    }
}

fn print_mac_address_range(macs: MacAddrs, summary: bool) {
    if summary {
        let base: String = macs
            .base_mac
            .iter()
            .map(|octet| format!("{octet:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        println!("Base:   {base}");
        println!("Count:  {}", macs.count);
        println!("Stride: {}", macs.stride);
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
    use super::PortMask;
    use super::PowerMode;
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
            Transceivers::PowerMode(PowerMode::Off)
        );
        assert_eq!(
            parse_transceivers("low-power").unwrap(),
            Transceivers::PowerMode(PowerMode::Low)
        );
        assert_eq!(
            parse_transceivers("hi-power").unwrap(),
            Transceivers::PowerMode(PowerMode::High)
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
            ("0", PortMask(0b1)),
            ("0,1,2", PortMask(0b111)),
            ("0-2", PortMask(0b111)),
            ("0,1-2", PortMask(0b111)),
            ("0,0-2", PortMask(0b111)),
            ("0,1,2,0-3", PortMask(0b1111)),
        ];
        for (s, m) in test_data.iter() {
            assert_eq!(parse_transceivers(s).unwrap(), Transceivers::Ports(*m));
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
