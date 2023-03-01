// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Configuration of the transceiver controller.

use crate::Error;
use std::net::Ipv6Addr;
use std::time::Duration;
use transceiver_messages::ADDR;
use transceiver_messages::PORT;

/// Return the default retry interval for resending messages.
pub const fn default_retry_interval() -> Duration {
    Duration::from_secs(1)
}

/// Return the default address of the peer.
pub fn default_peer_addr() -> Ipv6Addr {
    Ipv6Addr::from(ADDR)
}

/// Return the default port on which we should _listen_ for messages.
pub const fn default_port() -> u16 {
    PORT
}

/// Configuration for a [`crate::Controller`].
///
/// The [`ConfigBuilder`] can be used to construct this with defaults that work
/// for a production Oxide rack environment.
#[derive(Clone, Debug)]
pub struct Config {
    /// The address on which to listen for messages.
    pub address: Ipv6Addr,

    /// The source UDP port.
    ///
    /// This _must_ be [`default_port`] in order to receive unsolicited
    /// messages, but may be anything else if one only cares about responses to
    /// outgoing requests.
    pub port: u16,

    /// The name of the interface on which to listen.
    pub interface: String,

    /// The IPv6 address to use for communication.
    ///
    /// The default is a link-local IPv6 multicast address.
    pub peer: Ipv6Addr,

    /// The destination UDP port.
    ///
    /// This should be [`default_port`] to communicate with the SP, but other
    /// values may be useful for testing.
    pub peer_port: u16,

    /// The interval on which to retry messages that receive no response.
    pub retry_interval: Duration,

    /// The number of retries for a message before failing.
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
    peer_port: Option<u16>,
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

    /// Set the destination UDP port used for the controller.
    pub fn peer_port(mut self, port: u16) -> Self {
        self.peer_port = Some(port);
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
            port: self.port.unwrap_or_else(default_port),
            peer: self.peer.unwrap_or_else(default_peer_addr),
            peer_port: self.peer_port.unwrap_or_else(default_port),
            retry_interval: self.retry_interval.unwrap_or_else(default_retry_interval),
            n_retries: self.n_retries,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::is_link_local;
    use super::ConfigBuilder;
    use std::net::Ipv6Addr;

    #[test]
    fn test_config_builder() {
        assert!(ConfigBuilder::new("badif").build().is_err());
        assert!(ConfigBuilder::new("lo0").build().is_err());
        assert!(ConfigBuilder::new("lo0")
            .address(Ipv6Addr::LOCALHOST)
            .build()
            .is_ok());

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
