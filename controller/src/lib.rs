// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

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
use tokio::time::sleep;
use tokio::time::Interval;
use transceiver_decode::Error as DecodeError;
use transceiver_decode::Identifier;
use transceiver_decode::MemoryModel;
use transceiver_decode::ParseFromModule;
use transceiver_decode::PowerControl;
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
pub use transceiver_messages::MacAddrs;
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

    #[error("Invalid power state transition")]
    InvalidPowerStateTransition,
}

/// An allowed power mode for the module.
#[derive(Clone, Copy, Debug, PartialEq, clap::ValueEnum)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Serialize, serde::Deserialize, schemars::JsonSchema)
)]
#[cfg_attr(any(feature = "api-traits", test), serde(rename_all = "snake_case"))]
pub enum PowerMode {
    /// A module is entirely powered off, using the EFuse.
    Off,

    /// Power is enabled to the module, but module remains in low-power mode.
    ///
    /// In this state, modules will not establish a link or transmit traffic,
    /// but they may be managed and queried for information through their memory
    /// maps.
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

// Durations related to reset, as mandated by SFF-8679, table 8-1.
const T_RESET: Duration = Duration::from_secs(2);
const T_RESET_INIT: Duration = Duration::from_micros(10);

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
    log: Logger,
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
            log,
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

    /// Return the MAC addresses allotted to a system by its FRUID data.
    pub async fn mac_addrs(&self) -> Result<MacAddrs, Error> {
        let request = HostRequest::MacAddrs;
        let message = Message {
            header: self.next_header(),
            modules: ModuleId::empty(0), // Irrelevant for this message.
            body: MessageBody::HostRequest(request),
        };
        let request = HostRpcRequest {
            message,
            data: None,
        };
        let response = self.rpc(request).await?;
        match response.message.body {
            MessageBody::SpResponse(SpResponse::MacAddrs(macs)) => Ok(macs),
            MessageBody::SpResponse(SpResponse::Error(e)) => Err(Error::from(e)),
            other => Err(Error::UnexpectedMessage(other)),
        }
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
        self.parse_modules_by_identifier::<Vendor>(modules)
            .await
            .map(|collection| {
                collection
                    .into_values()
                    .map(|(identifier, vendor)| VendorInfo { identifier, vendor })
                    .collect()
            })
    }

    /// Reset a set of transceiver modules.
    pub async fn reset(&self, modules: ModuleId) -> Result<(), Error> {
        // According to SFF-8679, the host is required to pulse `ResetL` for at
        // least `t_reset_init` to effect an actual reset of the module. Modules
        // are then afforded `t_reset` after the rising edge of the `ResetL`
        // pulse until they're required to become fully functional. See SFF-8679
        // Table 8-1, and section 5.3.2.
        self.assert_reset(modules).await?;
        sleep(T_RESET_INIT).await;
        self.deassert_reset(modules).await?;
        sleep(T_RESET).await;
        Ok(())
    }

    // Fetch the software power control state of a set of modules.
    async fn power_control(&self, modules: ModuleId) -> Result<Vec<PowerControl>, Error> {
        self.parse_modules_by_identifier::<PowerControl>(modules)
            .await
            .map(|collection| {
                collection
                    .into_values()
                    .map(|(_id, control)| control)
                    .collect()
            })
    }

    // Return the subset of `modules` where `f(status) == true`.
    fn filter_modules_with<F>(modules: ModuleId, status: &[Status], f: F) -> Result<ModuleId, Error>
    where
        F: Fn(Status) -> bool,
    {
        PortMask::from_index_iter(
            modules
                .ports
                .to_indices()
                .zip(status.into_iter())
                .filter_map(|(ix, st)| if f(*st) { Some(ix) } else { None }),
        )
        .map(|ports| ModuleId {
            fpga_id: modules.fpga_id,
            ports,
        })
        .map_err(Error::from)
    }

    /// Get the power mode of a set of transceiver modules.
    ///
    /// For each module, this returns the actual `PowerMode`, as well as whether
    /// the module has set software-override of power control. In the case where
    /// the module is in off, that can't be determined, and `None` is returned.
    pub async fn power_mode(
        &self,
        modules: ModuleId,
    ) -> Result<Vec<(PowerMode, Option<bool>)>, Error> {
        // Split the requested modules into those with power enabled via the
        // e-fuse, and those without. The latter are always reported as off.
        let status = self.status(modules).await?;
        let unpowered_modules = Self::filter_modules_with(modules, &status, |status| {
            !status.contains(Status::POWER_GOOD | Status::ENABLED)
        })?;
        let powered_modules = ModuleId {
            fpga_id: modules.fpga_id,
            ports: modules.ports.remove(&unpowered_modules.ports),
        };

        // Of the powered modules, those in reset must be also be considered
        // Off.
        //
        // Filter down the status of all modules to those that are powered.
        let powered_status: Vec<_> = status
            .iter()
            .enumerate()
            .filter(|(ix, _st)| {
                let index = u8::try_from(*ix).expect("Impossible index");
                powered_modules.contains(index)
            })
            .map(|(_ix, st)| st)
            .copied()
            .collect();
        let in_reset = Self::filter_modules_with(powered_modules, &powered_status, |status| {
            status.contains(Status::RESET)
        })?;

        // Let's collect the set of modules we already know the power mode for.
        // We'll add in the mode for those that are readable below, since we
        // only want to _issue_ the read request if we have 1 or more modules to
        // read.
        //
        // Note that we don't explicitly set the power mode of the unpowered
        // modules or those in reset. Those are off, which is the value we fill
        // this array with, so setting those is redundant.
        let mut out = vec![(PowerMode::Off, None); modules.selected_transceiver_count()];

        // We've whittled this down to the set of modules we can read from,
        // which means we can determine whether software-override of power
        // control is enabled.
        let readable_modules = ModuleId {
            fpga_id: modules.fpga_id,
            ports: powered_modules.ports.remove(&in_reset.ports),
        };
        let readable_status: Vec<_> = status
            .iter()
            .enumerate()
            .filter(|(ix, _st)| {
                let index = u8::try_from(*ix).expect("Impossible index");
                readable_modules.contains(index)
            })
            .map(|(_ix, st)| st)
            .copied()
            .collect();

        // If there are any such modules, read from them and write in their
        // power mode.
        if readable_modules.selected_transceiver_count() > 0 {
            let ctl = self.power_control(readable_modules).await?;
            let readable_power_mode =
                ctl.into_iter()
                    .zip(readable_status.into_iter())
                    .map(|(ctl, status)| {
                        match ctl {
                            // If software is in charge, report what it says.
                            PowerControl::OverrideLpModePin { low_power } => {
                                let mode = if low_power {
                                    PowerMode::Low
                                } else {
                                    PowerMode::High
                                };
                                (mode, Some(true))
                            }
                            // Hardware is in charge, so report the state of the
                            // `LPMode` pin itself.
                            PowerControl::UseLpModePin => {
                                let mode = if status.contains(Status::LOW_POWER_MODE) {
                                    PowerMode::Low
                                } else {
                                    PowerMode::High
                                };
                                (mode, Some(false))
                            }
                        }
                    });
            for (i, state) in readable_modules.ports.to_indices().zip(readable_power_mode) {
                out[usize::from(i)] = state;
            }
        }

        Ok(out)
    }

    /// Enable the hot swap controller for a set of transceiver modules.
    ///
    /// See the `set_power_mode` method for a higher-level interface to set the
    /// power to a specific mode.
    pub async fn enable_power(&self, modules: ModuleId) -> Result<(), Error> {
        self.no_payload_request(modules, HostRequest::EnablePower)
            .await?;
        Ok(())
    }

    /// Disable the hot swap controller for a set of transceiver modules.
    ///
    /// See the `set_power_mode` method for a higher-level interface to set the
    /// power to a specific mode.
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
    ///
    /// See the `set_power_mode` method for a higher-level interface to set the
    /// power to a specific mode.
    pub async fn assert_lpmode(&self, modules: ModuleId) -> Result<(), Error> {
        self.no_payload_request(modules, HostRequest::AssertLpMode)
            .await?;
        Ok(())
    }

    /// Deassert physical lpmode pin for a set of transceiver modules. Note: The
    /// effect this pin has on operation can change depending on if the software
    /// override of power control is set.
    ///
    /// See the `set_power_mode` method for a higher-level interface to set the
    /// power to a specific mode.
    pub async fn deassert_lpmode(&self, modules: ModuleId) -> Result<(), Error> {
        self.no_payload_request(modules, HostRequest::DeassertLpMode)
            .await?;
        Ok(())
    }

    // Helper to create a request where the body is configurable and there is
    // no data payload needed.
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

    /// Set the power mode for a set of transceiver modules.
    ///
    /// This method may be used regardless of whether a module uses hardware
    /// control or software override for controlling the power.
    pub async fn set_power_mode(&self, modules: ModuleId, mode: PowerMode) -> Result<(), Error> {
        // How we proceed largely depends on two things: whether we're turning
        // the power OFF entirely, and whether a module has set software
        // override of the `LPMode` pin.
        match mode {
            PowerMode::Off => {
                // We would technically like to assert `LPMode` here. However,
                // we can't do that without unintentionally back-powering the
                // modules themselves. For now we deassert `LPMode`, but see
                // https://github.com/oxidecomputer/hardware-qsfp-x32/issues/47
                // for the hardware issue and
                // https://rfd.shared.oxide.computer/rfd/0244#_fpga_module_sequencing
                // for a general discussion.
                self.deassert_lpmode(modules).await?;
                self.assert_reset(modules).await?;
                self.disable_power(modules).await
            }
            PowerMode::Low | PowerMode::High => {
                // Validate the power state transition.
                //
                // For now, we enforce that modules may not go directly to high
                // power, they have to go through low-power first.
                //
                // We can always set modules to low power, though, since that's
                // valid from both off and high-power, and a no-op if it's
                // already set.
                let current_power_state = self.power_mode(modules).await?;
                if matches!(mode, PowerMode::High)
                    && current_power_state
                        .iter()
                        .any(|(mode, _override)| mode == &PowerMode::Off)
                {
                    return Err(Error::InvalidPowerStateTransition);
                }

                // We need the status bits to determine if we also need to
                // twiddle `ResetL`.
                let status = self.status(modules).await?;

                // Check whether power is enabled / good, and / or reset
                // asserted for any of the requested modules. We need to manage
                // those pin states to control the power. Note that this is true
                // regardless of whether the module has software-override of
                // power control set. That's because we want the pins and the
                // memory map to reflect the same state, so that toggling the
                // software override doesn't change the power state of the
                // module, only which hardware signals it responds to.
                let need_power_enabled = Self::filter_modules_with(modules, &status, |st| {
                    !st.contains(Status::POWER_GOOD | Status::ENABLED)
                })?;

                // Check for any modules which need power applied, but which do
                // _not_ already have reset asserted. We're going to assert
                // reset on them now, but emit a warning.
                let need_reset_deasserted =
                    Self::filter_modules_with(modules, &status, |st| st.contains(Status::RESET))?;
                let need_power_but_not_reset = ModuleId {
                    fpga_id: modules.fpga_id,
                    ports: need_power_enabled
                        .ports
                        .remove(&need_reset_deasserted.ports),
                };
                if need_power_but_not_reset.selected_transceiver_count() > 0 {
                    warn!(
                        self.log,
                        "Found modules with power disabled, but reset deasserted. \
                        It will be asserted before enabling power";
                        "need_power_enabled" => ?need_power_enabled,
                        "need_reset_deasserted" => ?need_reset_deasserted,
                        "suspicious_modules" => ?need_power_but_not_reset,
                    );
                    self.assert_reset(need_power_but_not_reset).await?;

                    // Wait for SFF-8679 `t_reset_init`. It's a bit silly to
                    // wait 10us here, but we're trying to be careful.
                    sleep(T_RESET_INIT).await;
                }

                // Enable power for the required modules.
                if need_power_enabled.selected_transceiver_count() > 0 {
                    self.enable_power(need_power_enabled).await?;
                }

                // Set the hardware `LPMode` signal.
                //
                // We do this in between enabling power and deasserting reset
                // intentionally, in order to better handle the back-power issue
                // linked above.
                //
                // Note that this means we set the hardware signal now, and the
                // software signal later. The latter is because reset must be
                // deasserted to be able to write the memory maps. There are a
                // few cases to consider:
                //
                // - Off -> Low
                // - Low -> High or High -> Low
                //
                // If a module is in the first case, then it sees:
                //
                // - enable_power
                // - assert_lpmode
                // - deassert_reset
                // - wait 2s
                // - set_software_power_mode
                //
                // That's fine, and the best we can do, since the module may not
                // respond to the write until we wait.
                //
                // For modules in the second case, they'll see:
                //
                // - assert_lpmode or deassert_lpmode
                // - set_software_power_mode
                //
                // Note that there may be a wait of up to 2s in between the last
                // steps, because other modules may have required twiddling
                // reset. That does lead to a window in which the hardware
                // signal and memory map bit can be out of sync. No
                // functionality here really relies on it, but it is
                // unfortunate.
                if matches!(mode, PowerMode::Low) {
                    self.assert_lpmode(modules).await?;
                } else {
                    self.deassert_lpmode(modules).await?;
                }

                // Deassert reset for the required modules.
                //
                // Note that we are explicitly ensuring above that all modules
                // which need reset deasserted also need power enabled. (This
                // cannot apply to modules in high-power mode.) So we can use
                // the `need_power_enabled` modules for both operations.
                if need_power_enabled.selected_transceiver_count() > 0 {
                    self.deassert_reset(need_power_enabled).await?;

                    // The SFF-8769 specifies that modules may take up to 2
                    // seconds after asserting ResetL before they are ready for
                    // reads. This is `t_reset`.
                    sleep(T_RESET).await;
                }

                // Set the bits indicating the new power mode in the memory map.
                //
                // See note above for why this is here.
                self.set_software_power_mode(modules, &current_power_state, mode)
                    .await
            }
        }
    }

    // Set the power mode assuming software control. _NO CHECKING_ is done as to
    // whether that is the case.
    //
    // # Panics
    //
    // Panics if `mode` is not `PowerMode::{Low,High}` since `PowerMode::Off`
    // isn't relevant to this interface.
    async fn set_software_power_mode(
        &self,
        modules: ModuleId,
        current_power_state: &[(PowerMode, Option<bool>)],
        mode: PowerMode,
    ) -> Result<(), Error> {
        assert!(matches!(mode, PowerMode::Low | PowerMode::High));

        // Split the software controlled modules by their identifiers, since we
        // need to write to different regions of the memory map in that case.
        let identifiers = self.identifier(modules).await?;
        let split = Self::split_modules_by_identifier(modules, &identifiers);
        for (ident, modules) in split.into_iter() {
            // Splitting by identifier is not enough, as it is for other cases.
            // We also need to avoid changing the software override bit, so
            // we'll further split this set of modules into those _with_ and
            // _without_ software override.
            let (with_override, without_override): (Vec<_>, Vec<_>) = modules
                .ports
                .to_indices()
                .partition(|ix| matches!(current_power_state[usize::from(*ix)].1, Some(true)));

            let with_override = ModuleId {
                fpga_id: modules.fpga_id,
                ports: PortMask::from_index_iter(with_override.into_iter())?,
            };
            let without_override = ModuleId {
                fpga_id: modules.fpga_id,
                ports: PortMask::from_index_iter(without_override.into_iter())?,
            };

            for (with_override, modules) in [(true, with_override), (false, without_override)] {
                // TODO-completeness: Consider adding this to the
                // `ParseFromModule` trait, since that encodes these locations
                // for _reads_, but not writes. We could require the implementor
                // to specify these locations themselves in the trait, and the
                // _provide_ a function that converts them to reads / writes.
                let (write, word) = match ident {
                    Identifier::QsfpPlusSff8636 | Identifier::Qsfp28 => {
                        let write = MemoryWrite::new(sff8636::Page::Lower, 93, 1)?;
                        // Byte 93.
                        //
                        // Bit 0: Set software override.
                        //
                        // Bit 1: Set to LPMode.
                        //
                        // TODO-correctness: We're technically clobbering whether
                        // the other, higher power classes are enabled. If we're
                        // setting into LPMode, that's fine. It seems like this only
                        // matters if we're setting into high-power mode, when we
                        // were already there, _and_ something had enabled those
                        // higher power classes. These bits are also optional, so
                        // we're deferring this for now.
                        let override_bit = if with_override { 0b01 } else { 0b00 };
                        let mode_bit = if matches!(mode, PowerMode::Low) {
                            0b10
                        } else {
                            0b00
                        };
                        (write, mode_bit | override_bit)
                    }
                    Identifier::QsfpPlusCmis | Identifier::QsfpDD => {
                        let write = MemoryWrite::new(sff8636::Page::Lower, 26, 1)?;
                        // Byte 26.
                        //
                        // Bit 6: 1 if the module should evaluate the hardware pin.
                        //
                        // Bit 4: Request low power mode.
                        //
                        // TODO-correctness: We're technically clobbering bit 5,
                        // which selects the squelch method. We should really be
                        // reading, OR'ing that bit, and writing back.
                        let override_bit = if with_override {
                            0b0000_0000
                        } else {
                            0b0100_0000
                        };
                        let mode_bit = if matches!(mode, PowerMode::Low) {
                            0b0001_0000
                        } else {
                            0b0000_0000
                        };
                        (write, mode_bit | override_bit)
                    }
                    id => return Err(Error::from(DecodeError::UnsupportedIdentifier(id))),
                };

                // Issue the write.
                self.write_impl(modules, write, &[word]).await?;
            }
        }

        Ok(())
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
        self.parse_modules_by_identifier::<MemoryModel>(modules)
            .await
            .map(|collection| collection.into_values().map(|(_id, model)| model).collect())
    }

    // Parse a decodable piece of data from each module.
    //
    // This uses the `ParseFromModule` trait to decode the memory map for each
    // _kind_ of module in `modules` depending on their identifier. That is, it
    // issues one message for all modules of the same kind.
    //
    // Data is returned as a map from module index (u8) to pairs of (Identifier,
    // P). This allows users to collect data into collections based on the index
    // or Identifier.
    async fn parse_modules_by_identifier<P: ParseFromModule>(
        &self,
        modules: ModuleId,
    ) -> Result<BTreeMap<u8, (Identifier, P)>, Error> {
        let ids = self.identifier(modules).await?;
        let modules_by_id = Self::split_modules_by_identifier(modules, &ids);
        let mut data_by_module = BTreeMap::new();

        // Read data for each _kind_ of module independently.
        for (id, modules) in modules_by_id.into_iter() {
            // Issue the reads for each chunk of data for this kind of module.
            let reads = P::reads(id)?;
            let data = {
                let mut data = Vec::with_capacity(reads.len());
                for read in reads.into_iter() {
                    data.push(self.read(modules, read).await?);
                }
                data
            };

            // Parse the data for each module.
            for (i, port) in modules.ports.to_indices().enumerate() {
                let parse_data = data.iter().map(|read| read[i].as_slice());
                let parsed = P::parse(id, parse_data)?;
                data_by_module.insert(port, (id, parsed));
            }
        }
        Ok(data_by_module)
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

                    // Check the version in the response.
                    //
                    // Beginning at version `MIN` (V5), we committed to
                    // backwards compatibility. In particular, any existing
                    // messages must still be decodable by software running a
                    // later version of the protocol.
                    //
                    // In this case we're processing a response to our own
                    // request. If we _get_ a response at all, it means that the
                    // peer is running at least `MIN`. There are actually no
                    // other checks that need to be performed, which would
                    // prevent us from decoding the message.
                    //
                    // Suppose the peer is running between `MIN` and `CURRENT`.
                    // Then we can clearly process their response, because the
                    // version is one that we've committed to compatibility
                    // with. This could be a version-mismatch error message,
                    // because the _peer_ may not be able to handle the message.
                    //
                    // If the version is _newer_ than `CURRENT`, we can still
                    // process it. That's because all of our messages can be
                    // decoded and processed by the peer, who has also committed
                    // to this compatibility.
                    if message.header.version < message::version::MIN {
                        debug!(
                            self.log,
                            "deserialized message with incompatible version";
                            "current" => message::version::CURRENT,
                            "min" => message::version::MIN,
                            "message_version" => message.header.version,
                            "peer" => peer,
                        );
                        probes::bad__message!(|| {
                            (
                                peer.ip(),
                                format!(
                                    "incompatible version: \
                                    current {}, min {}, message_version {}",
                                    message::version::CURRENT,
                                    message::version::MIN,
                                    message.header.version,
                                ),
                            )
                        });

                        // In this case, we're never going to be able to process
                        // a response from the peer. If this is a response to
                        // our outstanding message; send an error message on its
                        // response channel; and throw it away. If this is a
                        // message from the peer, just do nothing, since they
                        // won't be able to handle our response anyway.
                        if let Some(request) = self.outstanding_request.take() {
                            request.response_tx.send(
                                Err(Error::Protocol(MessageError::VersionMismatch {
                                    expected: message::version::CURRENT,
                                    actual: message.header.version
                                }))
                            ).unwrap();
                        }
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
    use super::message;
    use super::mpsc;
    use super::oneshot;
    use super::sff8636;
    use super::verify_ids_for_page;
    use super::ConfigBuilder;
    use super::Duration;
    use super::Error;
    use super::Header;
    use super::HostRequest;
    use super::HostRpcRequest;
    use super::Identifier;
    use super::IoLoop;
    use super::Logger;
    use super::Message;
    use super::MessageBody;
    use super::MessageError;
    use super::ModuleId;
    use super::OutstandingHostRequest;
    use super::Page;
    use super::PowerMode;
    use super::SocketAddr;
    use super::SocketAddrV6;
    use super::SpResponse;
    use super::SpRpcResponse;
    use super::UdpSocket;
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

    #[test]
    fn test_deserialize_power_mode() {
        assert_eq!(PowerMode::Off, serde_json::from_str("\"off\"").unwrap());
        assert_eq!(PowerMode::Low, serde_json::from_str("\"low\"").unwrap());
        assert_eq!(PowerMode::High, serde_json::from_str("\"high\"").unwrap());
    }

    #[test]
    fn test_serialize_power_mode() {
        assert_eq!(serde_json::to_string(&PowerMode::Off).unwrap(), "\"off\"");
        assert_eq!(serde_json::to_string(&PowerMode::Low).unwrap(), "\"low\"");
        assert_eq!(serde_json::to_string(&PowerMode::High).unwrap(), "\"high\"");
    }

    // Sanity checks for the handling of "responses" from the SP when their
    // version does not match our own. In particular, we simulate:
    //
    // - An SP running before the minimum committed version. This should
    // actually never generate a response, but we test the logic anyway. We
    // expect that this causes us to return a version-mismatch error.
    //
    // - An SP running between committed and our own version, exclusive. We
    // should still handle this response correctly.
    #[tokio::test]
    async fn test_version_mismatch_handling() {
        // In this test, the SP sends us an extremely old version.
        //
        // They should never do that, because of the implementations that we've
        // already put in the field. But if they do, this exercises our code in
        // the IO loop which detects that and injects a version mismatch error
        // into the response channel.
        let response = test_version_mismatch_impl(message::version::V1).await;
        assert!(matches!(
            response,
            Err(Error::Protocol(MessageError::VersionMismatch { .. }))
        ));

        // In this test, the SP sends us something below our version, but that's
        // been committed. We should handle this correctly, and not fail to
        // deserialize anything. I.e., both peers are respecting the protocol.
        let response = test_version_mismatch_impl(message::version::MIN).await;
        assert!(matches!(
            response,
            Ok(SpRpcResponse {
                message: Message {
                    header: Header {
                        version: message::version::MIN,
                        ..
                    },
                    body: MessageBody::SpResponse(SpResponse::Ack),
                    ..
                },
                ..
            })
        ));

        // In this test, the SP is beyond our own version. Assuming they're
        // respecting the protocol, they should be able to handle our message
        // (which is part of the committed protocol), and send us a decodable
        // response.
        let the_future = message::version::CURRENT + 1;
        let response = test_version_mismatch_impl(the_future).await;
        assert!(matches!(
            response,
            Ok(SpRpcResponse {
                message: Message {
                    header: Header {
                        version: _the_future,
                        ..
                    },
                    body: MessageBody::SpResponse(SpResponse::Ack),
                    ..
                },
                ..
            })
        ));
    }

    async fn test_version_mismatch_impl(sp_version: u8) -> Result<SpRpcResponse, Error> {
        let io_log = Logger::root(slog::Discard, slog::o!());
        let sp_address = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0);
        let sp_socket = UdpSocket::bind(sp_address).await.unwrap();
        let SocketAddr::V6(sp_address) = sp_socket.local_addr().unwrap() else {
            panic!("Should be V6 socket address");
        };
        let (outgoing_request_tx, outgoing_request_rx) = mpsc::channel(1);
        let (request_tx, _request_rx) = mpsc::channel(1);

        let host_address = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0);
        let socket = UdpSocket::bind(host_address).await.unwrap();
        let SocketAddr::V6(host_address) = socket.local_addr().unwrap() else {
            panic!("Should be V6 socket address");
        };
        let io_loop = IoLoop::new(
            io_log,
            socket,
            sp_address,
            Some(3),
            Duration::from_secs(1),
            outgoing_request_rx,
            request_tx,
        );
        let _io_task = tokio::spawn(async move {
            io_loop.run().await;
        });

        // Spawn a task to emulate the SP.
        let sp_task = tokio::spawn(async move {
            let mut buf = [0; 2048];
            let n_bytes = tokio::time::timeout(Duration::from_secs(1), sp_socket.recv(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert!(n_bytes > 0);

            // Send back an absurd version.
            let message = Message {
                header: Header {
                    version: sp_version,
                    message_id: 0,
                },
                modules: ModuleId::all_transceivers(0),
                body: MessageBody::SpResponse(SpResponse::Ack),
            };
            let n_bytes = hubpack::serialize(&mut buf, &message).unwrap();
            assert_eq!(
                sp_socket
                    .send_to(&buf[..n_bytes], host_address)
                    .await
                    .unwrap(),
                n_bytes
            );
        });

        // Send a single message, something where an ACK is all that's required.
        let (response_tx, response_rx) = oneshot::channel();
        let message = Message {
            header: Header {
                version: message::version::CURRENT,
                message_id: 0,
            },
            modules: ModuleId::all_transceivers(0),
            body: MessageBody::HostRequest(HostRequest::DisablePower),
        };
        let request = HostRpcRequest {
            message,
            data: None,
        };
        let req = OutstandingHostRequest {
            request,
            n_retries: 0,
            response_tx,
        };
        outgoing_request_tx.send(req).await.unwrap();
        let response = response_rx.await.unwrap();
        assert!(sp_task.await.is_ok());
        response
    }
}
