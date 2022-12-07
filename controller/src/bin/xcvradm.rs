// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

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
use transceiver_controller::Config;
use transceiver_controller::Controller;
use transceiver_controller::Error;
use transceiver_controller::HostRpcResponse;
use transceiver_controller::SpRpcRequest;
use transceiver_decode::Identity;
use transceiver_decode::MemoryModel;
use transceiver_messages::message::PowerMode;
use transceiver_messages::message::Status;
use transceiver_messages::mgmt::cmis;
use transceiver_messages::mgmt::sff8636;
use transceiver_messages::mgmt::MemoryRead;
use transceiver_messages::mgmt::MemoryWrite;
use transceiver_messages::Error as MessageError;
use transceiver_messages::ModuleId;
use transceiver_messages::PortMask;

// Handler for SP requests which only logs them and returns an error.
#[derive(Debug)]
struct DummyHandler {
    log: slog::Logger,
}

#[async_trait::async_trait]
impl transceiver_controller::RequestHandler for DummyHandler {
    async fn handle_request(&self, request: SpRpcRequest) -> Result<HostRpcResponse, Error> {
        slog::debug!(
            self.log,
            "Received SP request, ignoring";
            "request" => ?request
        );
        Err(Error::Protocol(MessageError::ProtocolError))
    }
}

fn parse_log_level(s: &str) -> Result<Level, String> {
    s.parse().map_err(|_| String::from("invalid log level"))
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

    /// The comma-separated list of transcievers on the FPGA to address.
    ///
    /// The default is all transceivers on an FPGA.
    #[arg(short, long, use_value_delimiter = true)]
    transceivers: Option<Vec<u8>>,

    /// The source IP address on which to listen for messages.
    #[arg(short, long, default_value_t = Ipv6Addr::UNSPECIFIED)]
    address: Ipv6Addr,

    /// The source interface on which to listen for messages.
    #[arg(short, long)]
    interface: String,

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

    /// Reset the addressed modules.
    Reset,

    /// Set the power module of the addressed modules.
    SetPower {
        /// The desired power mode.
        #[arg(value_enum)]
        mode: PowerMode,
    },

    /// Extract the identity information for a set of modules.
    Identify,

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

    let h = DummyHandler {
        log: log.new(slog::o!("name" => "request_handler")),
    };

    let ports = args
        .transceivers
        .map(|ix| PortMask::from_indices(&ix).unwrap())
        .unwrap_or_else(PortMask::all);
    let modules = ModuleId {
        fpga_id: args.fpga_id,
        ports,
    };
    let controller = Controller::new(config, log.clone(), h)
        .await
        .context("Failed to initialize transceiver controller")?;

    match args.cmd {
        Cmd::Status => {
            let status = controller
                .status(modules)
                .await
                .context("Failed to retrieve module status")?;
            print_module_status(modules, status);
        }

        Cmd::Reset => controller
            .reset(modules)
            .await
            .context("Failed to reset modules")?,

        Cmd::SetPower { mode } => {
            controller
                .set_power_mode(modules, mode)
                .await
                .context("Failed to set power mode")?;
        }

        Cmd::Identify => {
            let ids = controller
                .identify(modules)
                .await
                .context("Failed to identify transceiver modules")?;
            print_module_identity(modules, ids);
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
                        .context("Failed to setup upper page memory read")?
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
    }
    Ok(())
}

// Column width for printing data below.
const WIDTH: usize = 4;

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

const ID_WIDTH: usize = 20;
const VENDOR_WIDTH: usize = 16;
const PART_WIDTH: usize = 16;
const REV_WIDTH: usize = 4;
const SERIAL_WIDTH: usize = 16;
const DATE_WIDTH: usize = 20;

fn print_module_identity(modules: ModuleId, ids: Vec<Identity>) {
    println!(
        "FPGA Port {:ID_WIDTH$} {:VENDOR_WIDTH$} {:PART_WIDTH$} \
        {:REV_WIDTH$} {:SERIAL_WIDTH$} {:DATE_WIDTH$}",
        "Identifier", "Vendor", "Part", "Rev", "Serial", "Mfg date"
    );
    let fpga_id = modules.fpga_id;
    for (port, id) in modules.ports.to_indices().zip(ids.into_iter()) {
        print_single_module_identity(fpga_id, port, id);
    }
}

fn print_single_module_identity(fpga_id: u8, port: u8, id: Identity) {
    let ident = format!("{:?} (0x{:02x})", id.identifier, u8::from(id.identifier));
    println!(
        "{fpga_id:>WIDTH$} {port:>WIDTH$} {:ID_WIDTH$} {:VENDOR_WIDTH$} \
        {:PART_WIDTH$} {:REV_WIDTH$} {:SERIAL_WIDTH$} {:DATE_WIDTH$}",
        ident, id.vendor.name, id.vendor.part, id.vendor.revision, id.vendor.serial, id.vendor.date,
    );
}

fn print_module_memory_model(modules: ModuleId, models: Vec<MemoryModel>) {
    println!("FPGA Port Model");
    let fpga_id = modules.fpga_id;
    for (port, model) in modules.ports.to_indices().zip(models.into_iter()) {
        println!("{fpga_id:>WIDTH$} {port:>WIDTH$} {model}");
    }
}

#[cfg(test)]
mod tests {
    use super::load_write_data;
    use super::InputKind;
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
}
