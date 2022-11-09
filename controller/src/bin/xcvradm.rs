use slog::Drain;
use transceiver_controller::Controller;
use transceiver_controller::Error;
use transceiver_controller::HostRpcResponse;
use transceiver_controller::SpRpcRequest;
use transceiver_messages::mgmt::sff8636;
use transceiver_messages::mgmt::MemoryRead;
use transceiver_messages::Error as MessageError;
use transceiver_messages::ModuleId;
use transceiver_messages::PortMask;

async fn request_handler(_: SpRpcRequest) -> Result<HostRpcResponse, Error> {
    Err(Error::Protocol(MessageError::ProtocolError))
}

#[tokio::main]
async fn main() {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let log = slog::Logger::root(drain, slog::o!());

    let request_handler_log = log.new(slog::o!("name" => "request_handler"));
    let handler = move |message| {
        slog::info!(request_handler_log, "received sp request"; "message" => ?message);
        async move { request_handler(message).await }
    };
    let controller = Controller::new(log.clone(), handler).await.unwrap();
    let read = MemoryRead::new(sff8636::Page::Lower, 0, 4).unwrap();
    let data = controller
        .read(
            ModuleId {
                fpga_id: 0,
                ports: PortMask(0b11),
            },
            read,
        )
        .await
        .unwrap();
    slog::info!(log, "data: {:?}", data);
}
