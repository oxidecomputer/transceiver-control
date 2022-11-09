//! Mock SP server that dummies up basic QSFP memory map.

use std::net::Ipv6Addr;
use std::net::SocketAddrV6;
use tokio::net::UdpSocket;
use transceiver_messages::message::HostRequest;
use transceiver_messages::message::Message;
use transceiver_messages::message::MessageBody;
use transceiver_messages::message::SpResponse;
use transceiver_messages::MAX_PAYLOAD_SIZE;
use transceiver_messages::PORT;

const PEER: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0x1de, 2);

#[tokio::main]
async fn main() {
    let sock = UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, PORT, 0, 0))
        .await
        .unwrap();
    sock.join_multicast_v6(&PEER, 0).unwrap();

    let mut buf = [0; MAX_PAYLOAD_SIZE * 2];
    loop {
        match sock.recv_from(&mut buf).await {
            Err(e) => println!("{e:?}"),
            Ok((n_bytes, peer)) => {
                let (message, _) = hubpack::deserialize::<Message>(&buf[..n_bytes]).unwrap();
                println!("=> {message:?}");
                match message.body {
                    MessageBody::HostRequest(HostRequest::Read(read)) => {
                        let response = Message {
                            header: message.header,
                            modules: message.modules,
                            body: MessageBody::SpResponse(SpResponse::Read(read)),
                        };
                        // Flat array of data.
                        let data = vec![
                            0;
                            usize::from(read.len())
                                * message.modules.ports.0.count_ones() as usize
                        ];
                        println!("data size: {}", data.len());
                        println!("<= {response:?}");
                        let n_bytes = hubpack::serialize(&mut buf, &response).unwrap();
                        buf[n_bytes..n_bytes + data.len()].copy_from_slice(&data);
                        sock.send_to(&buf[..n_bytes + data.len()], &peer)
                            .await
                            .unwrap();
                    }
                    _ => {}
                }
            }
        }
    }
}
