// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A host-side control interface to the SP for managing Sidecar transceivers.

use tokio::net::UdpSocket;

/// A type for controlling transceiver modules on a Sidecar.
#[derive(Debug)]
pub struct Controller;
