// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! A host-side control interface to the SP for managing Sidecar transceivers.

#![cfg_attr(not(usdt_stable_asm), feature(asm))]
#![cfg_attr(all(target_os = "macos", not(usdt_stable_asm_sym)), feature(asm_sym))]

use hubpack::SerializedSize;
use nix::net::if_::if_nametoindex;
use serde::Deserialize;
use serde::Serialize;
use slog::debug;
use slog::error;
use slog::info;
use slog::trace;
use slog::warn;
use slog::Logger;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV6;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::interval;
use tokio::time::Interval;
use transceiver_decode::Error as DecodeError;
use transceiver_decode::Identifier;
use transceiver_decode::MemoryModel;
use transceiver_decode::ParseFromModule;
use transceiver_decode::Vendor;
use transceiver_decode::VendorInfo;
use transceiver_messages::message;
use transceiver_messages::message::Header;
use transceiver_messages::message::HostRequest;
use transceiver_messages::message::HostResponse;
use transceiver_messages::message::Message;
use transceiver_messages::message::MessageBody;
use transceiver_messages::message::SpResponse;
pub use transceiver_messages::message::Status;
pub use transceiver_messages::mgmt;
use transceiver_messages::mgmt::sff8636;
use transceiver_messages::mgmt::ManagementInterface;
use transceiver_messages::mgmt::MemoryRead;
use transceiver_messages::mgmt::MemoryWrite;
use transceiver_messages::mgmt::Page;
pub use transceiver_messages::Error as MessageError;
pub use transceiver_messages::ModuleId;
pub use transceiver_messages::PortMask;
use transceiver_messages::ADDR;
use transceiver_messages::MAX_PAYLOAD_SIZE;
use transceiver_messages::PORT;

#[usdt::provider(provider = "xcvr__ctl")]
mod probes {
    fn packet__received(peer: IpAddr, n_bytes: u64, data: *const u8) {}
    fn packet__sent(peer: IpAddr, n_bytes: u64, data: *const u8) {}
    fn message__received(peer: IpAddr, message: &Message) {}
    fn message__sent(peer: IpAddr, message: &Message) {}
    fn bad__message(peer: IpAddr, reason: &str) {}
}

/// An error related to managing the transceivers.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Network protocol error")]
    Protocol(#[from] transceiver_messages::Error),

    #[error("Network or I/O error")]
    Io(#[from] std::io::Error),

    #[error("Message type requires data, but none provided")]
    MessageRequiresData,

    #[error("Interface not found or lacks correct IPv6 link-local address")]
    BadInterface(String),

    #[error("Maximum number of retries ({0}) reached without a response")]
    MaxRetries(usize),

    #[error("Received an unexpected message type in response: {0:?}")]
    UnexpectedMessage(MessageBody),

    #[error("Transceiver memory map decoding error")]
    Decode(#[from] DecodeError),

    #[error("Incorrect data length for memory write")]
    InvalidWriteData,

    #[error(
        "An addressed module does not use the \
        management interface for the specified \
        memory operation ({0:?})"
    )]
    InvalidInterfaceForModule(ManagementInterface),
}

/// An allowed power mode for the module.
#[derive(Clone, Debug,)]
#[cfg_attr(feature = "std", derive(clap::ValueEnum))]
pub enum PowerMode {
    /// A module is entirely powered off, using the EFuse.
    Off,

    /// Power is enabled to the module, but the `LPMode` pin is set to high.
    ///
    /// Note: This requires that we never set the `Power_override` bit (SFF-8636
    /// rev 2.10a, section 6.2.6, byte 93 bit 2), as that defeats the purpose of
    /// hardware control.
    Low,

    /// The module is in high-power mode.
    ///
    /// Note that additional configuration may be required to correctly
    /// configure the module, such as described in SFF-8636 rev 2.10a table
    /// 6-10, and that the _host side_ is responsible for ensuring that the
    /// relevant configuration is applied.
    High,
}

// A request sent from host to SP, possibly with trailing data.
#[derive(Clone, Debug)]
struct HostRpcRequest {
    pub message: Message,
    pub data: Option<Vec<u8>>,
}

// A response sent from SP to host, possibly with trailing data.
#[derive(Clone, Debug)]
#[allow(dead_code)]
struct SpRpcResponse {
    pub message: Message,
    pub data: Option<Vec<u8>>,
}

/// A request sent from SP to host, possibly with trailing data.
#[derive(Clone, Debug)]
pub struct SpRpcRequest {
    pub message: Message,
    pub data: Option<Vec<u8>>,
}

/// A response sent from host to SP, possibly with trailing data.
#[derive(Clone, Debug)]
pub struct HostRpcResponse {
    pub message: Message,
    pub data: Option<Vec<u8>>,
}

// A request from host to SP that has not yet been completed.
#[derive(Debug)]
struct OutstandingHostRequest {
    // The actual request object we're sending. It's stored so that we can
    // resend it if needed.
    request: HostRpcRequest,
    // The number of attempts to submit and process `request`.
    n_retries: usize,
    // The channel on which the eventual reply will be sent.
    response_tx: oneshot::Sender<Result<SpRpcResponse, Error>>,
}

/// A type for communicating requests from the SP to the host and submitting the
/// responses.
///
/// When the `Controller` receives a request from the SP, the message will be
/// placed on the `request_channel` channel provided at construction. The
/// host-side task responsible for processing those requests will receive an
/// `SpRequest` object; generate a response, if needed; and submit that back on
/// the `response_tx` field of this type. The `Controller` will await that
/// response on the receiving end of `response_tx`, and send it back to the SP.
///
/// Note that `response_tx` takes an optional response. If the host wishes to
/// drop the message and do nothing, `None` should be returned. This might be
/// the case, for example, if the message cannot be processed correctly.
#[derive(Clone, Debug)]
pub struct SpRequest {
    /// The actual request message received from the host.
    pub request: SpRpcRequest,
    /// A channel on which the response should sent.
    pub response_tx: mpsc::Sender<Result<Option<HostRpcResponse>, Error>>,
}

// We limit ourselves to a single outstanding request in either direction at
// this point.
const NUM_OUTSTANDING_REQUESTS: usize = 1;
const RESEND_INTERVAL: Duration = Duration::from_secs(1);
const MAX_PACKET_SIZE: usize = MAX_PAYLOAD_SIZE + Message::MAX_SIZE;

/// Return the default retry interval for resending messages.
pub const fn default_retry_interval() -> Duration {
    RESEND_INTERVAL
}

/// Return the default address of the peer.
pub fn default_peer_addr() -> Ipv6Addr {
    Ipv6Addr::from(ADDR)
}

/// Configuration for a `Controller`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    /// The address on which to listen for messages.
    pub address: Ipv6Addr,

    /// The source UDP port.
    ///
    /// This _must_ be [`PORT`] in order to receive unsolicited messages, but
    /// may be anything else if one only cares about responses to outgoing
    /// requests.
    pub port: u16,

    /// The name of the interface on which to listen.
    pub interface: String,

    /// The IPv6 address to use for communication.
    ///
    /// The default is a link-local IPv6 multicast address.
    #[serde(default = "default_peer_addr")]
    pub peer: Ipv6Addr,

    /// The interval on which to retry messages that receive no response.
    #[serde(default = "default_retry_interval")]
    pub retry_interval: Duration,

    /// The number of retries for a message before failing.
    #[serde(default)]
    pub n_retries: Option<usize>,
}

// Return `true` if this is a link-local IPv6 address, i.e., in `fe80::/64`.
fn is_link_local(ip: Ipv6Addr) -> bool {
    ip.segments()[..4] == [0xfe80, 0, 0, 0]
}

// Yield the IPv6 address of the interface, if its name matches `name` and it
// has a link-local IPv6 address.
fn first_valid_address(name: &str, iface: nix::ifaddrs::InterfaceAddress) -> Option<Ipv6Addr> {
    if name == iface.interface_name {
        let ip6 = iface
            .address
            .and_then(|s| s.as_sockaddr_in6().map(|x| x.ip()))?;
        if is_link_local(ip6) {
            Some(ip6)
        } else {
            None
        }
    } else {
        None
    }
}

// Return true if the provide address is valid for the given interface.
fn is_valid_address(name: &str, addr: &Ipv6Addr) -> bool {
    let Ok(mut interfaces) = nix::ifaddrs::getifaddrs() else {
        return false;
    };
    interfaces
        .find_map(|iface| {
            if iface.interface_name == name {
                iface
                    .address
                    .and_then(|s| s.as_sockaddr_in6().map(|x| &x.ip() == addr))
            } else {
                None
            }
        })
        .unwrap_or(false)
}

/// Return the first IPv6 link-local address on an interface.
///
/// If no such interface or address exists, an `Err` is returned.
pub fn find_interface_link_local_addr(name: &str) -> Result<Ipv6Addr, Error> {
    let mut interfaces =
        nix::ifaddrs::getifaddrs().map_err(|_| Error::BadInterface(name.to_string()))?;
    interfaces
        .find_map(|iface| first_valid_address(name, iface))
        .ok_or_else(|| Error::BadInterface(name.to_string()))
}

/// A builder interface for generating controller configuration.
#[derive(Debug, Default)]
pub struct ConfigBuilder {
    interface: String,
    address: Option<Ipv6Addr>,
    port: Option<u16>,
    peer: Option<Ipv6Addr>,
    retry_interval: Option<Duration>,
    n_retries: Option<usize>,
}

impl ConfigBuilder {
    /// Create a new builder using a specific IP interface.
    pub fn new(interface: impl AsRef<str>) -> Self {
        Self {
            interface: String::from(interface.as_ref()),
            ..Default::default()
        }
    }

    /// Set the IPv6 address used for the controller.
    pub fn address(mut self, address: impl Into<Ipv6Addr>) -> Self {
        self.address = Some(address.into());
        self
    }

    /// Set the UDP port used for the controller.
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Set the address of the peer the controller communicates with.
    pub fn peer(mut self, peer: impl Into<Ipv6Addr>) -> Self {
        self.peer = Some(peer.into());
        self
    }

    /// Set the interval after which an outgoing request is retried, if no
    /// response is received.
    pub fn retry_interval(mut self, interval: Duration) -> Self {
        self.retry_interval = Some(interval);
        self
    }

    /// Set the total number of times a message is retried before failing.
    pub fn n_retries(mut self, retries: usize) -> Self {
        self.n_retries = Some(retries);
        self
    }

    /// Build a `Config` from `self`.
    pub fn build(self) -> Result<Config, Error> {
        let address = match self.address {
            None => find_interface_link_local_addr(&self.interface)?,
            Some(a) => {
                if is_valid_address(&self.interface, &a) {
                    a
                } else {
                    return Err(Error::BadInterface(self.interface));
                }
            }
        };
        Ok(Config {
            interface: self.interface,
            address,
            port: self.port.unwrap_or(PORT),
            peer: self.peer.unwrap_or_else(default_peer_addr),
            retry_interval: self.retry_interval.unwrap_or_else(default_retry_interval),
            n_retries: self.n_retries,
        })
    }
}

/// A type for controlling transceiver modules on a Sidecar.
#[derive(Debug)]
pub struct Controller {
    _config: Config,
    _iface: u32,
    _log: Logger,
    message_id: AtomicU64,

    // Channel onto which requests from the host to SP are sent.
    //
    // `io_task` owns the receiving end of this, and actually sends out the
    // messages to the SP.
    outgoing_request_tx: mpsc::Sender<OutstandingHostRequest>,

    // The task handling the details of message parsing and sending, including
    // serializing and sending outgoing messages; awaiting incoming responses;
    // deserializing and dispatching incoming SP requests; and sending those
    // outgoing responses back the SP. See `IoLoop` for details.
    io_task: JoinHandle<()>,
}

impl Drop for Controller {
    fn drop(&mut self) {
        self.io_task.abort();
    }
}

impl Controller {
    /// Create a new transceiver controller.
    pub async fn new(
        config: Config,
        log: Logger,
        request_tx: mpsc::Sender<SpRequest>,
    ) -> Result<Self, Error> {
        if let Err(e) = usdt::register_probes() {
            warn!(log, "failed to register DTrace probes"; "reason" => ?e);
        }

        let iface = if_nametoindex(config.interface.as_str())
            .map_err(|_| Error::BadInterface(config.interface.clone()))?;
        let local_addr = SocketAddrV6::new(config.address, config.port, 0, iface);
        let socket = UdpSocket::bind(local_addr).await?;
        debug!(
            log,
            "bound UDP socket";
            "interface" => &config.interface,
            "local_addr" => ?socket.local_addr(),
        );

        // Join the group for the multicast protocol address, so that we can
        // accept requests from the SP in the case it does not have our unicast
        // address.
        let multicast_addr = Ipv6Addr::from(ADDR);
        socket.join_multicast_v6(&multicast_addr, iface)?;
        socket.set_multicast_loop_v6(false)?;
        debug!(
            log,
            "joined IPv6 multicast group";
            "multicast_addr" => ?multicast_addr,
        );

        // Channel for communicating outgoing requests from this object to the
        // I/O loop. Note that the _responses_ from the I/O loop back to this
        // object are sent on a oneshot channel, which is itself placed on this
        // channel when sending the request.
        let (outgoing_request_tx, outgoing_request_rx) = mpsc::channel(NUM_OUTSTANDING_REQUESTS);

        // The multicast peer address for our protocol.
        //
        // We can't both `connect` the socket and still `send_to`, which means
        // we wouldn't be able to send outgoing packets without a unicast
        // adddress. Pass this address to the IO loop, so we can initiate
        // requests.
        let peer_addr = SocketAddrV6::new(config.peer, PORT, 0, iface);

        // The I/O task handles the actual network I/O, reading and writing UDP
        // packets in both directions, and dispatching requests from the SP.
        let io_log = log.new(slog::o!("task" => "io"));
        let io_loop = IoLoop::new(
            io_log,
            socket,
            peer_addr,
            config.n_retries,
            config.retry_interval,
            outgoing_request_rx,
            request_tx,
        );
        let io_task = tokio::spawn(async move {
            io_loop.run().await;
        });
        debug!(log, "spawned IO task");

        Ok(Self {
            _config: config,
            _iface: iface,
            _log: log,
            message_id: AtomicU64::new(0),
            outgoing_request_tx,
            io_task,
        })
    }

    // Return a header using the next available message ID.
    fn next_header(&self) -> Header {
        Header {
            version: message::version::CURRENT,
            message_id: self.message_id.fetch_add(1, Ordering::SeqCst),
        }
    }

    // Split the provided modules into a sequence of modules, each of the same
    // type.
    //
    // # Panics
    //
    // This panics if the transceivers and ID counts are different.
    fn split_modules_by_identifier(
        modules: ModuleId,
        ids: &[Identifier],
    ) -> BTreeMap<Identifier, ModuleId> {
        assert_eq!(modules.selected_transceiver_count(), ids.len());
        let fpga_id = modules.fpga_id;
        let mut out = BTreeMap::new();
        for (port, id) in modules.ports.to_indices().zip(ids) {
            out.entry(*id)
                .or_insert_with(|| ModuleId {
                    fpga_id,
                    ports: PortMask(0),
                })
                .ports
                .set(port)
                .unwrap();
        }
        out
    }

    /// Return the SFF-8024 identifier for a set of modules.
    pub async fn identifier(&self, modules: ModuleId) -> Result<Vec<Identifier>, Error> {
        let read = MemoryRead::new(sff8636::Page::Lower, 0, 1).unwrap();
        let per_module_data = self.read_impl(modules, read).await?;
        Ok(per_module_data
            .into_iter()
            .map(|v| Identifier::from(v[0]))
            .collect())
    }

    /// Return the vendor information of a set of modules.
    pub async fn vendor_info(&self, modules: ModuleId) -> Result<Vec<VendorInfo>, Error> {
        let ids = self.identifier(modules).await?;
        let modules_by_id = Self::split_modules_by_identifier(modules, &ids);
        let mut identity = BTreeMap::new();

        // Read data for each kind of module independently.
        for (id, modules) in modules_by_id.into_iter() {
            // Issue the reads for each chunk of data for this kind of module.
            let reads = Vendor::reads(id)?;
            let vendor_data = {
                let mut vendor_data = Vec::with_capacity(reads.len());
                for read in reads.into_iter() {
                    vendor_data.push(self.read(modules, read).await?);
                }
                vendor_data
            };

            // Parse the vendor data itself for each module.
            //
            // `vendor_data` is a Vec<Vec<Vec<u8>>> where they are, from outer
            // to inner:
            //
            // - Each read, defined by `Vendor::reads`.
            // - Each _module_ of the same kind.
            // - Bytes for that read and module.
            //
            // So the data for each module is at a single index of the second
            // array, and the full contents along the other two dimensions. (In
            // ndarray notation, something like `vendor_data[..][i][..]`.)
            for (i, port) in modules.ports.to_indices().enumerate() {
                let parse_data = vendor_data.iter().map(|read| read[i].as_slice());
                let vendor = Vendor::parse(id, parse_data)?;
                let ident = VendorInfo {
                    identifier: id,
                    vendor,
                };
                identity.insert(port, ident);
            }
        }

        // Sort by index, so that the returned `Vec<_>` maps to the return value
        // of `modules.ports.to_indices()`.
        Ok(identity.into_iter().map(|(_k, v)| v).collect())
    }

    /// Reset a set of transceiver modules.
    pub async fn reset(&self, modules: ModuleId) -> Result<(), Error> {
        let message = Message {
            header: self.next_header(),
            modules,
            body: MessageBody::HostRequest(HostRequest::Reset),
        };
        let request = HostRpcRequest {
            message,
            data: None,
        };
        let response = self.rpc(request).await?;
        match response.message.body {
            MessageBody::SpResponse(SpResponse::Ack) => Ok(()),
            MessageBody::SpResponse(SpResponse::Error(e)) => Err(Error::from(e)),
            other => Err(Error::UnexpectedMessage(other)),
        }
    }

    /// Set the power mode for a set of transceiver modules.
    pub async fn set_power_mode(&self, _modules: ModuleId, _mode: PowerMode) -> Result<(), Error> {
        todo!()
    }

    /// Enable the hot swap controller for a set of transceiver modules.
    pub async fn enable_power(&self, modules: ModuleId) -> Result<(), Error> {
        self.no_payload_request(modules, HostRequest::EnablePower)
            .await?;
        Ok(())
    }

    /// Disable the hot swap controller for a set of transceiver modules.
    pub async fn disable_power(&self, modules: ModuleId) -> Result<(), Error> {
        self.no_payload_request(modules, HostRequest::DisablePower)
            .await?;
        Ok(())
    }

    /// Assert reset for a set of transceiver modules.
    pub async fn assert_reset(&self, modules: ModuleId) -> Result<(), Error> {
        self.no_payload_request(modules, HostRequest::AssertReset)
            .await?;
        Ok(())
    }

    /// Deassert reset for a set of transceiver modules.
    pub async fn deassert_reset(&self, modules: ModuleId) -> Result<(), Error> {
        self.no_payload_request(modules, HostRequest::DeassertReset)
            .await?;
        Ok(())
    }

    /// Assert physical lpmode pin for a set of transceiver modules. Note: The
    /// effect this pin has on operation can change depending on if the software
    /// override of power control is set.
    pub async fn assert_lpmode(&self, modules: ModuleId) -> Result<(), Error> {
        self.no_payload_request(modules, HostRequest::AssertLpMode)
            .await?;
        Ok(())
    }

    /// Deassert physical lpmode pin for a set of transceiver modules. Note: The
    /// effect this pin has on operation can change depending on if the software
    /// override of power control is set.
    pub async fn deassert_lpmode(&self, modules: ModuleId) -> Result<(), Error> {
        self.no_payload_request(modules, HostRequest::DeassertLpMode)
            .await?;
        Ok(())
    }

    /// Helper to create a request where the body is configurable and there is
    /// no data payload needed.
    async fn no_payload_request(
        &self,
        modules: ModuleId,
        request: HostRequest,
    ) -> Result<(), Error> {
        let message = Message {
            header: self.next_header(),
            modules,
            body: MessageBody::HostRequest(request),
        };
        let request = HostRpcRequest {
            message,
            data: None,
        };
        let response = self.rpc(request).await?;
        match response.message.body {
            MessageBody::SpResponse(SpResponse::Ack) => Ok(()),
            MessageBody::SpResponse(SpResponse::Error(e)) => Err(Error::from(e)),
            other => Err(Error::UnexpectedMessage(other)),
        }
    }

    /// Report the status of a set of transceiver modules.
    pub async fn status(&self, modules: ModuleId) -> Result<Vec<Status>, Error> {
        let message = Message {
            header: self.next_header(),
            modules,
            body: MessageBody::HostRequest(HostRequest::Status),
        };
        let request = HostRpcRequest {
            message,
            data: None,
        };
        let response = self.rpc(request).await?;
        match response.message.body {
            MessageBody::SpResponse(SpResponse::Status) => Ok(response
                .data
                .expect("Length of data checked earlier")
                .into_iter()
                .map(|x| Status::from_bits(x).unwrap())
                .collect()),
            MessageBody::SpResponse(SpResponse::Error(e)) => Err(Error::from(e)),
            other => Err(Error::UnexpectedMessage(other)),
        }
    }

    /// Write the memory map of a set of transceiver modules.
    ///
    /// `write` contains a description of which memory region to write to,
    /// including the page, offset, and length. See [`MemoryWrite`] for details.
    ///
    /// `data` is a buffer to be written to each module. Note that it will be
    /// "broadcast" to all addressed modules! The length of `data` must match
    /// the length of the region specified in `write`.
    pub async fn write(
        &self,
        modules: ModuleId,
        write: MemoryWrite,
        data: &[u8],
    ) -> Result<(), Error> {
        let ids = self.identifier(modules).await?;
        verify_ids_for_page(write.page(), &ids)?;
        self.write_impl(modules, write, data).await
    }

    // Implementation of the write function, which does not check that the
    // memory pages address by `write` are valid for the addressed modules.
    async fn write_impl(
        &self,
        modules: ModuleId,
        write: MemoryWrite,
        data: &[u8],
    ) -> Result<(), Error> {
        if usize::from(write.len()) != data.len() {
            return Err(Error::InvalidWriteData);
        }
        let message = Message {
            header: self.next_header(),
            modules,
            body: MessageBody::HostRequest(HostRequest::Write(write)),
        };
        let request = HostRpcRequest {
            message,
            data: Some(data.to_vec()),
        };
        let response = self.rpc(request).await?;
        match response.message.body {
            MessageBody::SpResponse(SpResponse::Write(_)) => Ok(()),
            MessageBody::SpResponse(SpResponse::Error(e)) => Err(Error::from(e)),
            other => Err(Error::UnexpectedMessage(other)),
        }
    }

    /// Read the memory map of a set of transceiver modules.
    ///
    /// `read` contains a description of which memory region to read, including
    /// the page, offset, and length. See [`MemoryRead`] for details.
    ///
    /// Note that the _caller_ is responsible for verifying that the details of
    /// the read are valid, such as that the modules conform to the specified
    /// management interface, and that the page is supported.
    pub async fn read(&self, modules: ModuleId, read: MemoryRead) -> Result<Vec<Vec<u8>>, Error> {
        let ids = self.identifier(modules).await?;
        verify_ids_for_page(read.page(), &ids)?;
        self.read_impl(modules, read).await
    }

    // Implementation of the read function, which does not check that the memory
    // pages addressed by `read` are valid for the addressed modules.
    async fn read_impl(&self, modules: ModuleId, read: MemoryRead) -> Result<Vec<Vec<u8>>, Error> {
        let message = Message {
            header: self.next_header(),
            modules,
            body: MessageBody::HostRequest(HostRequest::Read(read)),
        };
        let request = HostRpcRequest {
            message,
            data: None,
        };
        let response = self.rpc(request).await?;
        let data = match response.message.body {
            MessageBody::SpResponse(SpResponse::Error(e)) => return Err(Error::from(e)),
            MessageBody::SpResponse(SpResponse::Read(_)) => {
                response.data.expect("Existence of data checked earlier")
            }
            other => return Err(Error::UnexpectedMessage(other)),
        };

        // We expect data to be a flattened vec of vecs, with the data from each
        // referenced transceiver. Split it into chunks sized by the number of
        // bytes we expected to read.
        let data = data
            .chunks_exact(usize::from(read.len()))
            .map(Vec::from)
            .collect::<Vec<_>>();
        assert_eq!(data.len(), modules.selected_transceiver_count());
        Ok(data)
    }

    /// Describe the memory model of a set of modules.
    pub async fn memory_model(&self, modules: ModuleId) -> Result<Vec<MemoryModel>, Error> {
        let ids = self.identifier(modules).await?;
        let modules_by_id = Self::split_modules_by_identifier(modules, &ids);
        let mut models = BTreeMap::new();

        // Read data for each _kind_ of module independently.
        for (id, modules) in modules_by_id.into_iter() {
            // Issue the reads for each chunk of data for this kind of module.
            let reads = MemoryModel::reads(id)?;
            let model_data = {
                let mut model_data = Vec::with_capacity(reads.len());
                for read in reads.into_iter() {
                    model_data.push(self.read(modules, read).await?);
                }
                model_data
            };

            // Parse the memory model for each module.
            for (i, port) in modules.ports.to_indices().enumerate() {
                let parse_data = model_data.iter().map(|read| read[i].as_slice());
                let model = MemoryModel::parse(id, parse_data)?;
                models.insert(port, model);
            }
        }

        // Sort by index, so that the returned `Vec<_>` maps to the return value
        // of `modules.ports.to_indices()`.
        Ok(models.into_iter().map(|(_k, v)| v).collect())
    }

    // Issue one RPC, possibly retrying, and await the response.
    async fn rpc(&self, request: HostRpcRequest) -> Result<SpRpcResponse, Error> {
        let (response_tx, response_rx) = oneshot::channel();
        let outstanding_request = OutstandingHostRequest {
            request,
            n_retries: 0,
            response_tx,
        };
        self.outgoing_request_tx
            .send(outstanding_request)
            .await
            .unwrap();
        response_rx
            .await
            .expect("failed to recv response on channel")
    }
}

fn verify_ids_for_page(page: &Page, ids: &[Identifier]) -> Result<(), Error> {
    let iface = page.management_interface();
    let cmp = match iface {
        ManagementInterface::Sff8636 => {
            |id| id == &Identifier::Qsfp28 || id == &Identifier::QsfpPlusSff8636
        }
        ManagementInterface::Cmis => {
            |id| id == &Identifier::QsfpDD || id == &Identifier::QsfpPlusCmis
        }
        ManagementInterface::Unknown(_) => unimplemented!(
            "Only SFF-8636 and CMIS management interfaces \
                are currently implemented"
        ),
    };
    if ids.iter().all(cmp) {
        Ok(())
    } else {
        Err(Error::InvalidInterfaceForModule(iface))
    }
}

// A POD type holding the data we need for the main I/O loop. See `IoLoop::run`
// for details.
#[derive(Debug)]
struct IoLoop {
    log: Logger,
    socket: UdpSocket,
    peer_addr: SocketAddrV6,
    n_retries: usize,
    resend: Interval,
    // Channel on which we receive outgoing requests from `Controller`. These
    // are pulled and sent over the UDP socket to the SP, possibly retrying.
    outgoing_request_rx: mpsc::Receiver<OutstandingHostRequest>,

    // The current outstanding request from `outgoing_request_tx`, if any.
    outstanding_request: Option<OutstandingHostRequest>,

    // The channel on which we dispatch incoming requests from the SP, to the
    // request handler. The items sent include a send-half for our
    // `outgoing_response_rx`.
    incoming_request_tx: mpsc::Sender<SpRequest>,

    // The channel on which we wait for outgoing responses from the request
    // handler. These are sent on the UDP socket to the SP.
    outgoing_response_rx: mpsc::Receiver<Result<Option<HostRpcResponse>, Error>>,

    // A sender for `outgoing_response_rx`.
    //
    // This is never used, but we need to maintain a send-half to
    // `outgoing_response_rx` so that receiving on it does not immediately
    // return errors.
    outgoing_response_tx: mpsc::Sender<Result<Option<HostRpcResponse>, Error>>,
}

impl IoLoop {
    #[allow(clippy::too_many_arguments)]
    fn new(
        log: Logger,
        socket: UdpSocket,
        peer_addr: SocketAddrV6,
        n_retries: Option<usize>,
        retry_interval: Duration,
        outgoing_request_rx: mpsc::Receiver<OutstandingHostRequest>,
        incoming_request_tx: mpsc::Sender<SpRequest>,
    ) -> Self {
        let (outgoing_response_tx, outgoing_response_rx) = mpsc::channel(NUM_OUTSTANDING_REQUESTS);
        Self {
            log,
            socket,
            peer_addr,
            n_retries: n_retries.unwrap_or(usize::MAX),
            resend: interval(retry_interval),
            outgoing_request_rx,
            outstanding_request: None,
            incoming_request_tx,
            outgoing_response_rx,
            outgoing_response_tx,
        }
    }

    // Send an outgoing response.
    async fn send_outgoing_response(&mut self, response: HostRpcResponse, tx_buf: &mut [u8]) {
        let data_start = hubpack::serialize(tx_buf, &response.message).unwrap();
        let msg_size = if let Some(data) = &response.data {
            let data_end = data_start + data.len();
            tx_buf[data_start..data_end].copy_from_slice(data);
            data_end
        } else {
            data_start
        };
        match self
            .socket
            .send_to(&tx_buf[..msg_size], &self.peer_addr)
            .await
        {
            Err(e) => {
                error!(
                    self.log,
                    "failed to send outgoing response";
                    "peer" => ?self.peer_addr,
                    "reason" => ?e,
                );
            }
            Ok(n_bytes) => {
                assert_eq!(n_bytes, msg_size);
                trace!(
                    self.log,
                    "sent outgoing response";
                    "peer" => ?self.peer_addr,
                    "message" => ?response.message,
                );
                probes::packet__sent!(|| {
                    let peer = IpAddr::V6(*self.peer_addr.ip());
                    (peer, n_bytes as u64, tx_buf.as_ptr())
                });
                probes::message__sent!(|| {
                    let peer = IpAddr::V6(*self.peer_addr.ip());
                    (peer, &response.message)
                });
            }
        }
    }

    // Send an outgoing request.
    //
    // Panics if there is no outstanding request.
    async fn send_outgoing_request(&mut self, tx_buf: &mut [u8]) {
        // Safety: Serialization can only fail in a few constrained
        // circumstances, such as a buffer overrun or unsupported types. None of
        // those apply here, so we just unwrap in that direction.
        let mut request = self.outstanding_request.as_mut().unwrap();
        let data_start = hubpack::serialize(tx_buf, &request.request.message).unwrap();
        let msg_size = if let Some(data) = &request.request.data {
            let data_end = data_start + data.len();
            tx_buf[data_start..data_end].copy_from_slice(data);
            data_end
        } else {
            data_start
        };
        match self
            .socket
            .send_to(&tx_buf[..msg_size], &self.peer_addr)
            .await
        {
            Err(e) => {
                error!(
                    self.log,
                    "failed to send outgoing request";
                    "peer" => ?self.peer_addr,
                    "reason" => ?e,
                );
            }
            Ok(n_bytes) => {
                assert_eq!(n_bytes, msg_size);
                trace!(
                    self.log,
                    "sent outgoing request";
                    "peer" => ?self.peer_addr,
                    "message" => ?request.request.message,
                );
                probes::packet__sent!(|| {
                    let peer = IpAddr::V6(*self.peer_addr.ip());
                    (peer, n_bytes as u64, tx_buf.as_ptr())
                });
                probes::message__sent!(|| {
                    let peer = IpAddr::V6(*self.peer_addr.ip());
                    (peer, &request.request.message)
                });
                self.resend.reset();
            }
        }
        // Increment the number of attempts, regardless of whether we could
        // successfully send the request or not. The error could be on "our"
        // side, e.g. an IP address or interface went away, but that should
        // still be considered an attempt. Otherwise, we may retry indefinitely.
        request.n_retries += 1;
    }

    async fn send_protocol_error(
        &self,
        peer: &SocketAddr,
        header: Header,
        modules: ModuleId,
        err: MessageError,
        tx_buf: &mut [u8],
    ) {
        let body = MessageBody::HostResponse(HostResponse::Error(err));
        let message = Message {
            header,
            modules,
            body,
        };
        let serialized_len = hubpack::serialize(tx_buf, &message).unwrap();
        match self.socket.send_to(&tx_buf[..serialized_len], peer).await {
            Err(e) => {
                error!(
                    self.log,
                    "failed to send protocol error";
                    "reason" => ?e,
                    "peer" => peer
                );
            }
            Ok(n_bytes) => {
                debug!(
                    self.log,
                    "sent protocol error";
                    "peer" => ?self.peer_addr,
                    "message" => ?message,
                );
                probes::packet__sent!(|| {
                    let peer = IpAddr::V6(*self.peer_addr.ip());
                    (peer, n_bytes as u64, tx_buf.as_ptr())
                });
                probes::message__sent!(|| {
                    let peer = IpAddr::V6(*self.peer_addr.ip());
                    (peer, &message)
                });
                assert_eq!(n_bytes, serialized_len);
            }
        }
    }

    // Main IO loop for communicating with the SP.
    //
    // This task is responsible for accepting messages from the host for delivery to
    // the SP (outgoing) and those from the SP to the host (incoming). The outgoing
    // messages are accepted from two channels:
    //
    // - `self.outgoing_request_rx` receives messages from the `Controller`
    // object itself, as part of the implementation of its public API.
    // - `self.outgoing_response_rx` receives messages from the
    // `request_handler` used to construct the `Controller`, and delivers the
    // host's desired responses to a SP request.
    //
    // These are serialized and sent over the contained UDP socket to the multicast
    // address defined in `transceiver_messages::ADDR`.
    //
    // This task also listens for incoming messages on the UDP socket from the SP.
    // These are deserialized and sanity checked. (Obvious failures result in an
    // error being sent back immediately.) Assuming they seem reasonable, then they
    // are dispatched as follows:
    //
    // - Requests from the SP are sent on `self.incoming_request_tx`. Responses
    // to those incoming requests are received back by this loop on a channel in
    // the items sent on the `self.incoming_request_tx` channel.
    //
    // - Responses to our own initiated requests are sent back on a `oneshot`
    // channel, that is sent in the data on `outgoing_request_tx`.
    async fn run(mut self) {
        let mut rx_buf = [0; MAX_PACKET_SIZE];
        let mut tx_buf = [0; MAX_PACKET_SIZE];

        loop {
            tokio::select! {
                // Poll for outgoing requests, but only if we don't already _have_
                // an outstanding request.
                maybe_request = self.outgoing_request_rx.recv(), if self.outstanding_request.is_none() => {

                    // We only get `None` if the sender is closed, meaning the task
                    // holding that side exited. Nothing else will come down this
                    // channel, and things are likely borked. Bail out.
                    let request = match maybe_request {
                        Some(r) => r,
                        None => {
                            debug!(self.log, "outgoing response channel closed, exiting");
                            return;
                        }
                    };
                    trace!(self.log, "received outgoing request"; "request" => ?request);

                    // Store the outstanding request, sanity-checking that we really
                    // didn't have a prior one.
                    let old = self.outstanding_request.replace(request);
                    assert!(
                        old.is_none(),
                        "dequeued a new request while one is already outstanding!",
                    );
                    self.send_outgoing_request(&mut tx_buf).await;
                }

                // If we _do_ have an outstanding request, we need to resend it
                // periodically until we get a response. Wait for up to the resend
                // interval of inactivity, and then possibly retry.
                _ = self.resend.tick(), if self.outstanding_request.is_some() => {
                    let n_retries = self.outstanding_request.as_ref().unwrap().n_retries;
                    if n_retries < self.n_retries {
                        debug!(self.log, "timed out without response, retrying");
                        self.send_outgoing_request(&mut tx_buf).await;
                    } else {
                        error!(
                            self.log,
                            "failed to send message within {n_retries} retries"
                        );
                        // Safety: This branch is only taken if the request is
                        // `Some(_)`.
                        let old = self.outstanding_request.take().unwrap();
                        old.response_tx.send(Err(Error::MaxRetries(n_retries))).unwrap();
                    }
                }

                // Poll for outgoing responses we need to send.
                maybe_response = self.outgoing_response_rx.recv() => {
                    let response = match maybe_response {
                        Some(r) => r,
                        None => {
                            debug!(self.log, "outgoing response channel closed, exiting");
                            return;
                        }
                    };
                    match response {
                        Ok(Some(r)) => {
                            trace!(
                                self.log,
                                "received outgoing response";
                                "message" => ?r.message,
                            );
                            self.send_outgoing_response(r, &mut tx_buf).await;
                        }
                        Ok(None) => {
                            trace!(
                                self.log,
                                "request handler explicitly dropped message"
                            );
                        }
                        Err(e) => {
                            error!(
                                self.log,
                                "request handler failed";
                                "error" => ?e
                            );
                        }
                    }
                }

                // Poll for incoming packets.
                res = self.socket.recv_from(&mut rx_buf) => {
                    let (n_bytes, peer) = match res {
                        Err(e) => {
                            error!(self.log, "I/O error receiving UDP packet: {e:?}");
                            continue;
                        }
                        Ok((n_bytes, peer)) => {
                            trace!(
                                self.log,
                                "packet received";
                                "n_bytes" => n_bytes,
                                "peer" => peer,
                            );
                            probes::packet__received!(|| {
                                (peer.ip(), n_bytes as u64, rx_buf.as_ptr())
                            });
                            (n_bytes, peer)
                        }
                    };

                    // Deserialize the message itself.
                    let (message, remainder): (Message, _) = match hubpack::deserialize(&rx_buf) {
                        Err(e) => {
                            // We've failed to deserialize the message. We'll
                            // not send any failure back to the peer, since we
                            // have no information about what kind of message
                            // this is. However, we'll deserialize the header
                            // (which should never fail) and emit a log message.
                            let (header, _): (Header, _) = hubpack::deserialize(&rx_buf).unwrap();
                            error!(
                                self.log,
                                "failed to deserialize message";
                                "reason" => ?e,
                                "peer" => peer,
                                "n_bytes" => n_bytes,
                                "header" => ?header,
                            );
                            probes::bad__message!(|| {
                                (peer.ip(), format!("deserialization failure: {e:?}"))
                            });
                            continue;
                        }
                        Ok((msg, remainder)) => (msg, remainder),
                    };
                    trace!(
                        self.log,
                        "message from peer";
                        "peer" => peer,
                        "message" => ?message
                    );
                    probes::message__received!(|| (peer.ip(), &message));

                    // Sanity check the protocol version.
                    if message.header.version != message::version::CURRENT {
                        // If the version does not match, we're choosing to drop
                        // the packet rather than reply with a version mismatch
                        // error. Without a matching version, we can't really
                        // trust the message kind we have deserialized, so won't
                        // be able to reliably send protocol errors.
                        debug!(
                            self.log,
                            "deserialized message with incorrect version";
                            "expected" => message::version::CURRENT,
                            "actual" => message.header.version,
                            "peer" => peer,
                        );
                        probes::bad__message!(|| {
                            (
                                peer.ip(),
                                format!(
                                    "incorrect version: expected {}, actual {}",
                                    message::version::CURRENT,
                                    message.header.version,
                                ),
                            )
                        });
                        continue;
                    }

                    // Sanity check that the message could possibly be meant for us.
                    //
                    // We never expect these message types to be sent to us.
                    if matches!(
                        message.body,
                        MessageBody::HostRequest(_) | MessageBody::HostResponse(_)
                    ) {
                        // We need to check the message ID to decide how to
                        // proceed.
                        //
                        // If we have an outstanding request, and this incoming
                        // message matches that ID, we need to fail this
                        // request. Otherwise we'll simply retry the message
                        // again, which will obviously fail in the same way.
                        //
                        // Note that we can always take out of the Option. If it
                        // is None, then we can replace it with None without
                        // worry. If it is Some(_), we want to replace it
                        // anyway when we fail this request.
                        let maybe_outstanding = self.outstanding_request.take();
                        if let Some(request) = maybe_outstanding {
                            if request.request.message.header.message_id ==
                                message.header.message_id {
                                debug!(
                                    self.log,
                                    "received incorrect message type, \
                                    but with message ID that matches our \
                                    outstanding message ID, failing the \
                                    request";
                                    "message" => ?message,
                                    "peer" => peer,
                                );
                                probes::bad__message!(|| {
                                    let msg = match message.body {
                                        MessageBody::HostRequest(_) => "HostRequest",
                                        MessageBody::HostResponse(_) => "HostResponse",
                                        _ => unreachable!(),
                                    };
                                    (
                                        peer.ip(),
                                        format!(
                                            "matching message ID, but wrong \
                                            message type: {msg}"
                                        )
                                    )
                                });
                                request.response_tx.send(
                                    Err(Error::Protocol(MessageError::ProtocolError))
                                ).unwrap();
                            }
                        } else {
                            // We don't have an outstanding request, so we try
                            // to inform the SP that this message wasn't
                            // supposed to be sent to us.
                            debug!(self.log, "wrong message type"; "peer" => peer);
                            probes::bad__message!(|| {
                                let msg = match message.body {
                                    MessageBody::HostRequest(_) => "HostRequest",
                                    MessageBody::HostResponse(_) => "HostResponse",
                                    _ => unreachable!(),
                                };
                                (peer.ip(), format!("wrong message type: {msg}"))
                            });
                            self.send_protocol_error(
                                &peer,
                                message.header,
                                message.modules,
                                MessageError::ProtocolError,
                                &mut tx_buf,
                            ).await;
                        }
                    }

                    // Check that we have data, if the message is supposed to
                    // contain it.
                    let data = if let Some(expected_len) = message.expected_data_len() {
                        if remainder.len() < expected_len {
                            error!(
                                self.log,
                                "message did not contain expected data";
                                "expected_len" => expected_len,
                                "actual_len" => remainder.len(),
                                "peer" => peer,
                            );
                            let err = MessageError::MissingData;
                            probes::bad__message!(|| (peer.ip(), format!("{:?}", err)));
                            self.send_protocol_error(
                                &peer,
                                message.header,
                                message.modules,
                                err,
                                &mut tx_buf,
                            ).await;
                            continue;
                        }
                        Some(remainder[..expected_len].to_vec())
                    } else {
                        None
                    };

                    // If this is a request, let's dispatch to the request handler
                    // channel.
                    if matches!(message.body, MessageBody::SpRequest(_)) {

                        // Construct a request and a send-half to
                        // `outgoing_response_rx` on which we'll receive the
                        // reply.
                        let request = SpRpcRequest { message, data };
                        let item = SpRequest {
                            request,
                            response_tx: self.outgoing_response_tx.clone(),
                        };
                        self.incoming_request_tx
                            .send(item)
                            .await
                            .expect("failed to dispatch incoming request on handler channel");
                        info!(
                            self.log,
                            "sent incoming SP request on handler channel"
                        );
                        continue;
                    }

                    // This is a response, possibly for our outstanding request.
                    //
                    // Note that we can't take the message now, since the
                    // response may not actually correspond to our outstanding
                    // request. We replace the message below if needed.
                    let maybe_response = if let Some(request) = &self.outstanding_request {
                        // Check if this is for our current outstanding request.
                        let outstanding_message_id = request
                            .request
                            .message
                            .header
                            .message_id;
                        if outstanding_message_id == message.header.message_id {
                            // We have a valid response! Return it for
                            // processing.
                            Some(SpRpcResponse { message, data })
                        } else {
                            probes::bad__message!(|| {
                                (
                                    peer.ip(),
                                    "response for request that is not outstanding"
                                )
                            });
                            debug!(
                                self.log,
                                "received response for message that is not outstanding";
                                "message" => ?message,
                                "outstanding_message_id" => outstanding_message_id,
                                "peer" => peer,
                            );
                            None
                        }
                    } else {
                        // We have no outstanding request.
                        //
                        // There are a lot of reasons this might be the case, such
                        // as a duplicate response from the SP for a previous
                        // request. It's not obvious what to do here, but for now,
                        // let's log and drop the message.
                        probes::bad__message!(|| {
                            (
                                peer.ip(),
                                "received response without an outstanding request",
                            )
                        });
                        debug!(
                            self.log,
                            "received response without an outstanding request";
                            "message" => ?message,
                            "peer" => peer,
                        );
                        None
                    };

                    // If we have a valid response, take out the outstanding
                    // message and forward the response on its channel.
                    if let Some(response) = maybe_response {
                        self
                            .outstanding_request
                            .take()
                            .expect("verified as Some(_) above")
                            .response_tx
                            .send(Ok(response))
                            .expect("failed to send response on channel");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::is_link_local;
    use super::sff8636;
    use super::verify_ids_for_page;
    use super::ConfigBuilder;
    use super::Identifier;
    use super::Page;
    use std::net::Ipv6Addr;

    #[test]
    fn test_verify_ids_for_page() {
        let page = Page::Sff8636(sff8636::Page::Lower);

        assert!(
            verify_ids_for_page(&page, &[Identifier::Qsfp28, Identifier::QsfpPlusSff8636]).is_ok()
        );
        assert!(
            verify_ids_for_page(&page, &[Identifier::QsfpDD, Identifier::QsfpPlusCmis]).is_err()
        );
    }

    #[test]
    fn test_config_builder() {
        assert!(ConfigBuilder::new("badif").build().is_err());
        assert!(ConfigBuilder::new("lo0").build().is_err());

        // Check if the system has a link-local, ensure we can create a config
        // for it.
        if let Some((ifname, address)) = nix::ifaddrs::getifaddrs()
            .expect("could not get IP interfaces")
            .find_map(|iface| {
                if let Some(addr) = iface.address {
                    if let Some(ipv6) = addr.as_sockaddr_in6() {
                        let ip = ipv6.ip();
                        if is_link_local(ip) {
                            return Some((iface.interface_name, ip));
                        }
                    }
                }
                None
            })
        {
            assert!(ConfigBuilder::new(&ifname).address(address).build().is_ok());
            assert!(ConfigBuilder::new(&ifname)
                .address(Ipv6Addr::UNSPECIFIED)
                .build()
                .is_err());
        }
    }
}
