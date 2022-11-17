use clap::Parser;
use clap::Subcommand;
use slog::Drain;
use slog::Level;
use std::net::Ipv6Addr;
use std::time::Duration;
use transceiver_controller::Config;
use transceiver_controller::Controller;
use transceiver_controller::Error;
use transceiver_controller::HostRpcResponse;
use transceiver_controller::SpRpcRequest;
use transceiver_messages::message::Status;
use transceiver_messages::mgmt::sff8636;
use transceiver_messages::mgmt::MemoryRead;
use transceiver_messages::Error as MessageError;
use transceiver_messages::ModuleId;
use transceiver_messages::PortMask;

async fn request_handler(_: SpRpcRequest) -> Result<HostRpcResponse, Error> {
    Err(Error::Protocol(MessageError::ProtocolError))
}

fn parse_xvcr_list(s: &str) -> Result<Vec<u8>, String> {
    s.split(",")
        .map(|x| {
            x.parse()
                .map_err(|_| String::from("invalid transceiver index"))
        })
        .collect()
}

fn parse_log_level(s: &str) -> Result<Level, String> {
    s.parse().map_err(|_| String::from("invalid log level"))
}

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,

    /// The FPGA whose transceivers to address.
    #[arg(short, long, default_value_t = 0)]
    fpga_id: u8,

    /// The comma-separated list of transcievers on the FPGA to address.
    ///
    /// The default is all transceivers on an FPGA.
    #[arg(short, long)]
    transceivers: Option<String>,

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

#[derive(Subcommand)]
enum Cmd {
    /// Return the status of the addressed modules, such as presence, power
    /// enable, and power mode.
    Status,

    /// Read the lower page of a set of transceiver modules.
    ReadLower { offset: u8, len: u8 },
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let config = Config {
        address: args.address,
        interface: args.interface,
        peer: args
            .peer
            .unwrap_or(Ipv6Addr::from(transceiver_messages::ADDR)),
        n_retries: args.n_retries,
        retry_interval: Duration::from_millis(args.retry_interval),
    };

    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let drain = slog::LevelFilter::new(drain, args.log_level).fuse();
    let log = slog::Logger::root(drain, slog::o!());

    let request_handler_log = log.new(slog::o!("name" => "request_handler"));
    let handler = move |message| {
        slog::info!(request_handler_log, "received sp request"; "message" => ?message);
        async move { request_handler(message).await }
    };

    let ports = args
        .transceivers
        .map(|list| PortMask::from_indices(&parse_xvcr_list(&list).unwrap()).unwrap())
        .unwrap_or_else(|| PortMask::all());
    let modules = ModuleId {
        fpga_id: args.fpga_id,
        ports,
    };
    let controller = Controller::new(config, log.clone(), handler).await.unwrap();

    match args.cmd {
        Cmd::Status => {
            let status = controller.status(modules).await.unwrap();
            print_module_status(modules, status);
        }
        Cmd::ReadLower { offset, len } => {
            let read = MemoryRead::new(sff8636::Page::Lower, offset, len).unwrap();
            let data = controller.read(modules, read).await.unwrap();
            print_read_data(modules, data);
        }
    }
}

fn print_module_status(modules: ModuleId, status: Vec<Status>) {
    println!("FPGA\tPort\tStatus");
    for (port, status) in modules.ports.to_indices().zip(status.into_iter()) {
        println!("{}\t{port}\t{status:?}", modules.fpga_id);
    }
}

fn print_read_data(modules: ModuleId, data: Vec<Vec<u8>>) {
    println!("FPGA\tPort\tData");
    for (port, each) in modules.ports.to_indices().zip(data.into_iter()) {
        let hex_data = each
            .into_iter()
            .map(|byte| format!("0x{byte:02x}"))
            .collect::<Vec<_>>()
            .join(",");
        println!("{}\t{port}\t[{hex_data}]", modules.fpga_id);
    }
}
