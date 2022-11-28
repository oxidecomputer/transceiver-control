// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::{ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};
use structopt::StructOpt;

use hubpack::SerializedSize;
use transceiver_messages::{
    message::*,
    mgmt::{sff8636, MemoryRead, MemoryWrite},
    ModuleId, PortMask,
};

#[derive(StructOpt)]
struct Args {
    #[structopt(long)]
    source: Option<String>,

    #[structopt(short)]
    read: bool,

    #[structopt(short)]
    write: bool,

    target: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::from_args();

    let dest = args.target.to_socket_addrs()?.collect::<Vec<_>>();

    let socket = if let Some(src) = args.source {
        UdpSocket::bind(src)?
    } else {
        UdpSocket::bind("[::]:0")?
    };
    socket.set_read_timeout(Some(Duration::from_millis(2500)))?;
    socket.connect(&dest[..])?;

    let peer = socket.peer_addr()?;
    println!("Sending to {} from {}", peer, socket.local_addr()?);
    println!("------------------------------------------------------------");

    const MAX_SIZE: usize =
        Message::MAX_SIZE + transceiver_messages::MAX_PAYLOAD_SIZE;
    let mut buf = [0; MAX_SIZE];

    let mut message_id = 0x1234;
    loop {
        if args.read || !args.write {
            test_read(&socket, &mut buf, message_id)?;
        } else {
            test_write(&socket, &mut buf, message_id)?;
        }
        message_id += 1;

        println!(
            "------------------------------------------------------------"
        );
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn test_read(
    socket: &UdpSocket,
    buf: &mut [u8],
    message_id: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    for fpga in [0, 1] {
        for port in 0..16 {
            let msg = Message {
                header: Header {
                    version: version::CURRENT,
                    message_id,
                },
                modules: ModuleId {
                    fpga_id: fpga,
                    ports: PortMask::single(port).unwrap(),
                },
                body: MessageBody::HostRequest(HostRequest::Status),
            };
            println!("FPGA {}, port {}: {:?}", fpga, port, msg.body);

            let (reply, rest) = send_message(buf, socket, msg, &[]);
            let status = Status::from_bits(rest[0]).unwrap();
            println!("  => {:?}; {:?}", reply.body, status);

            if status.contains(Status::PRESENT) {
                if status.contains(Status::RESET) {
                    let msg = Message {
                        header: Header {
                            version: version::CURRENT,
                            message_id,
                        },
                        modules: ModuleId {
                            fpga_id: fpga,
                            ports: PortMask::single(port).unwrap(),
                        },
                        body: MessageBody::HostRequest(
                            HostRequest::SetPowerMode(PowerMode::Low),
                        ),
                    };
                    println!("Setting PowerMode::Low: {:?}", msg);
                    let (reply, rest) = send_message(buf, socket, msg, &[]);
                    assert!(rest.is_empty());
                    println!("   Got reply {:?}", reply.body);
                }
                let msg = Message {
                    header: Header {
                        version: version::CURRENT,
                        message_id,
                    },
                    modules: ModuleId {
                        fpga_id: fpga,
                        ports: PortMask::single(port).unwrap(),
                    },
                    body: MessageBody::HostRequest(HostRequest::Read(
                        MemoryRead::new(sff8636::Page::Lower, 0, 128).unwrap(),
                    )),
                };
                println!("Reading memory: {:?}", msg.body);
                let (reply, rest) = send_message(buf, socket, msg, &[]);
                println!("    => {:?}\n       {:?}", reply.body, rest);
            }
        }
    }
    Ok(())
}

fn test_write(
    socket: &UdpSocket,
    buf: &mut [u8],
    message_id: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    for fpga in [0, 1] {
        for port in 0..16 {
            let msg = Message {
                header: Header {
                    version: version::CURRENT,
                    message_id,
                },
                modules: ModuleId {
                    fpga_id: fpga,
                    ports: PortMask::single(port).unwrap(),
                },
                body: MessageBody::HostRequest(HostRequest::Status),
            };
            println!("FPGA {}, port {}: {:?}", fpga, port, msg.body);

            let (reply, rest) = send_message(buf, socket, msg, &[]);
            let status = Status::from_bits(rest[0]).unwrap();
            println!("  => {:?}; {:?}", reply.body, status);

            if !status.contains(Status::PRESENT) {
                continue;
            }
            if status.contains(Status::RESET) {
                let msg = Message {
                    header: Header {
                        version: version::CURRENT,
                        message_id,
                    },
                    modules: ModuleId {
                        fpga_id: fpga,
                        ports: PortMask::single(port).unwrap(),
                    },
                    body: MessageBody::HostRequest(HostRequest::SetPowerMode(
                        PowerMode::Low,
                    )),
                };
                println!("Setting PowerMode::Low: {:?}", msg);
                let (reply, rest) = send_message(buf, socket, msg, &[]);
                assert!(rest.is_empty());
                println!("   Got reply {:?}", reply.body);
            }

            let msg = Message {
                header: Header {
                    version: version::CURRENT,
                    message_id,
                },
                modules: ModuleId {
                    fpga_id: fpga,
                    ports: PortMask::single(port).unwrap(),
                },
                body: MessageBody::HostRequest(HostRequest::Read(
                    MemoryRead::new(
                        sff8636::Page::Upper(
                            sff8636::UpperPage::new(0).unwrap(),
                        ),
                        128,
                        128,
                    )
                    .unwrap(),
                )),
            };

            println!("Reading page 2 memory: {:?}", msg.body);
            let (reply, rest) = send_message(buf, socket, msg, &[]);
            println!("    => {:?}\n       {:?}", reply.body, rest);

            // Write to page 2, which is a user-writable EEPROM
            let msg = Message {
                header: Header {
                    version: version::CURRENT,
                    message_id,
                },
                modules: ModuleId {
                    fpga_id: fpga,
                    ports: PortMask::single(port).unwrap(),
                },
                body: MessageBody::HostRequest(HostRequest::Write(
                    MemoryWrite::new(
                        sff8636::Page::Upper(
                            sff8636::UpperPage::new(0).unwrap(),
                        ),
                        128,
                        4,
                    )
                    .unwrap(),
                )),
            };
            println!("Reading memory: {:?}", msg.body);
            let (reply, rest) = send_message(buf, socket, msg, &[5, 6, 7, 8]);
            println!("    => {:?}\n       {:?}", reply.body, rest);
            return Ok(());
        }
    }
    Ok(())
}

fn send_message<'a>(
    buf: &'a mut [u8],
    socket: &'a UdpSocket,
    msg: Message,
    data: &'a [u8],
) -> (Message, &'a [u8]) {
    let size = hubpack::serialize(buf, &msg).unwrap();
    buf[size..][..data.len()].copy_from_slice(data);

    socket.send(&buf[..(size + data.len())]).unwrap();

    let timeout = Instant::now() + Duration::from_secs(1);

    loop {
        match socket.recv(buf) {
            Ok(n) => {
                let (reply, rest): (Message, _) =
                    hubpack::deserialize(&buf[0..n]).unwrap();
                return (reply, rest);
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                if timeout <= Instant::now() {
                    panic!("Timeout!");
                }
            }
            Err(e) => {
                panic!("Got err {:?}", e);
            }
        }
    }
}
