// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Implementation of the main controller logic.

use crate::config::*;
use crate::ioloop::IoLoop;
use crate::messages::*;
use crate::results::*;
use crate::Error;
use crate::PowerMode;
use crate::PowerState;
use crate::TransceiverError;
use crate::NUM_OUTSTANDING_REQUESTS;
use hubpack::SerializedSize;
use itertools::Itertools;
use nix::net::if_::if_nametoindex;
use slog::debug;
use slog::warn;
use slog::Logger;
use std::collections::BTreeMap;
use std::net::SocketAddrV6;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use transceiver_decode::Error as DecodeError;
use transceiver_decode::Identifier;
use transceiver_decode::MemoryModel;
use transceiver_decode::Monitors;
use transceiver_decode::ParseFromModule;
use transceiver_decode::PowerControl;
use transceiver_decode::VendorInfo;
use transceiver_messages::filter_module_data;
use transceiver_messages::keep_module_data;
pub use transceiver_messages::mac::MacAddrs;
use transceiver_messages::merge_module_data;
use transceiver_messages::message;
use transceiver_messages::message::Header;
use transceiver_messages::message::HostRequest;
pub use transceiver_messages::message::HwError;
pub use transceiver_messages::message::LedState;
use transceiver_messages::message::MacAddrResponse;
use transceiver_messages::message::Message;
use transceiver_messages::message::MessageBody;
use transceiver_messages::message::MessageKind;
pub use transceiver_messages::message::ProtocolError;
use transceiver_messages::message::SpResponse;
pub use transceiver_messages::message::Status;
pub use transceiver_messages::mgmt;
use transceiver_messages::mgmt::sff8636;
use transceiver_messages::mgmt::ManagementInterface;
use transceiver_messages::mgmt::MemoryRead;
use transceiver_messages::mgmt::MemoryWrite;
use transceiver_messages::mgmt::Page;
use transceiver_messages::remove_module_data;
pub use transceiver_messages::InvalidPort;
pub use transceiver_messages::ModuleId;
use transceiver_messages::MAX_PAYLOAD_SIZE;

// Durations related to reset, as mandated by SFF-8679, table 8-1.
const T_RESET: Duration = Duration::from_secs(2);
const T_RESET_INIT: Duration = Duration::from_micros(10);

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
    ///
    /// A controller must be constructed with a [`Config`], which describes how
    /// to talk to the peer SP over the network as well as parameters for things
    /// like message retries.
    ///
    /// The other important argument is `request_tx`. The [`Controller`] is
    /// meant to handle spontaneous requests from the SP, not only responses to
    /// our own requests. As SP requests are received, they're forward to this
    /// channel. Users can do whatever they need there, and send back responses
    /// on the [`SpRequest`]'s oneshot `response_tx` channel. If the handler
    /// wishes to drop a message entirely, `Ok(None)` can be sent on the
    /// channel. Otherwise, a [`HostRpcResponse`] should be sent.
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
        let multicast_addr = default_peer_addr();
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
        let peer_addr = SocketAddrV6::new(config.peer, config.peer_port, 0, iface);

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
    fn next_header(&self, message_kind: MessageKind) -> Header {
        Header::new(self.message_id.fetch_add(1, Ordering::SeqCst), message_kind)
    }

    // Split the provided modules into a sequence of modules, each of the same
    // type.
    //
    // # Panics
    //
    // This panics if the transceivers and ID counts are different.
    fn split_modules_by_identifier(
        modules: &ModuleId,
        ids: &[Identifier],
    ) -> BTreeMap<Identifier, ModuleId> {
        assert_eq!(modules.selected_transceiver_count(), ids.len());
        let mut out = BTreeMap::new();
        for (port, id) in modules.to_indices().zip(ids) {
            out.entry(*id)
                .or_insert_with(ModuleId::empty)
                .set(port)
                .unwrap();
        }
        out
    }

    /// Return the LED state of a set of modules.
    pub async fn leds(&self, modules: ModuleId) -> Result<LedStateResult, Error> {
        let message = Message::from(HostRequest::LedState(modules));
        let request = HostRpcRequest {
            header: self.next_header(MessageKind::HostRequest),
            message,
            data: None,
        };
        let response = self.rpc(request).await?;
        match response.message.body {
            MessageBody::SpResponse(
                st @ SpResponse::LedState {
                    modules,
                    failed_modules,
                },
            ) => {
                let data = response.data.expect("Existence of data checked earlier");
                let (data, error_data) = data.split_at(st.expected_data_len().unwrap());
                let state = data
                    .chunks(LedState::MAX_SIZE)
                    .map(|chunk| hubpack::deserialize(chunk).unwrap().0)
                    .collect();
                let failures = Self::deserialize_hw_errors(failed_modules, error_data)?;
                Ok(LedStateResult {
                    modules,
                    data: state,
                    failures,
                })
            }
            other => Err(Error::UnexpectedMessage(other)),
        }
    }

    /// Set the LED state of a set of modules.
    pub async fn set_leds(&self, modules: ModuleId, state: LedState) -> Result<AckResult, Error> {
        self.no_payload_request(HostRequest::SetLedState { modules, state })
            .await
    }

    /// Return the MAC addresses allotted to a system by its FRUID data.
    pub async fn mac_addrs(&self) -> Result<MacAddrs, Error> {
        let message = Message::from(HostRequest::MacAddrs);
        let request = HostRpcRequest {
            header: self.next_header(MessageKind::HostRequest),
            message,
            data: None,
        };
        let response = self.rpc(request).await?;
        match response.message.body {
            MessageBody::SpResponse(SpResponse::MacAddrs(MacAddrResponse::Ok(macs))) => Ok(macs),
            MessageBody::SpResponse(SpResponse::MacAddrs(MacAddrResponse::Error(e))) => {
                Err(Error::Mac(e))
            }
            other => Err(Error::UnexpectedMessage(other)),
        }
    }

    /// Return the SFF-8024 identifier for a set of modules.
    pub async fn identifier(&self, modules: ModuleId) -> Result<IdentifierResult, Error> {
        let read = MemoryRead::new(sff8636::Page::Lower, 0, 1).unwrap();
        self.read_impl(modules, read)
            .await
            .map(|read_result| IdentifierResult {
                modules: read_result.modules,
                data: read_result
                    .data
                    .into_iter()
                    .map(|v| Identifier::from(v[0]))
                    .collect(),
                failures: read_result.failures,
            })
    }

    /// Return the vendor information of a set of modules.
    pub async fn vendor_info(&self, modules: ModuleId) -> Result<VendorInfoResult, Error> {
        self.parse_modules_by_identifier::<VendorInfo>(modules)
            .await
    }

    /// Reset a set of transceiver modules.
    pub async fn reset(&self, modules: ModuleId) -> Result<AckResult, Error> {
        // According to SFF-8679, the host is required to pulse `ResetL` for at
        // least `t_reset_init` to effect an actual reset of the module. Modules
        // are then afforded `t_reset` after the rising edge of the `ResetL`
        // pulse until they're required to become fully functional. See SFF-8679
        // Table 8-1, and section 5.3.2.
        let AckResult {
            modules, failures, ..
        } = self.assert_reset(modules).await?;
        sleep(T_RESET_INIT).await;
        let AckResult {
            modules,
            failures: new_failures,
            ..
        } = self.deassert_reset(modules).await?;
        sleep(T_RESET).await;
        Ok(AckResult::new(modules, failures.merge(&new_failures)))
    }

    // Fetch the software power control state of a set of modules.
    async fn power_control(&self, modules: ModuleId) -> Result<PowerControlResult, Error> {
        self.parse_modules_by_identifier::<PowerControl>(modules)
            .await
    }

    // Helper to parse out hardware errors for a set of modules from trailing
    // data.
    //
    // `data` should point to the start of the errors. Use `expected_data_len()`
    // and / or `expected_error_data_len()` as needed to get here, from the
    // actual response data.
    fn deserialize_hw_errors(
        failed_modules: ModuleId,
        data: &[u8],
    ) -> Result<FailedModules, Error> {
        message::deserialize_hw_errors(failed_modules, data)
            .map_err(Error::from)
            .map(|hw_errors| {
                let errors = hw_errors
                    .into_iter()
                    .zip(failed_modules.to_indices())
                    .map(|(source, module_index)| TransceiverError::Hardware {
                        module_index,
                        source,
                    })
                    .collect();
                FailedModules {
                    modules: failed_modules,
                    errors,
                }
            })
    }

    /// Get the power mode of a set of transceiver modules.
    ///
    /// For each module, this returns the actual `PowerState`, as well as whether
    /// the module has set software-override of power control. In the case where
    /// the module is in off, that can't be determined, and `None` is returned.
    pub async fn power(&self, modules: ModuleId) -> Result<PowerModeResult, Error> {
        // Fetch the status bits for all the modules.
        //
        // We're going to split these up in a few different ways. We'll
        // immediately fail anything we can't get the status bits for (and
        // possibly add more to this set as we go).
        let status_result = self.status(modules).await?;

        // Split the requested modules into those with power enabled via the
        // EFuse, and those without. The latter are always reported as off.
        let (powered_modules, powered_status) = filter_module_data(
            status_result.modules,
            status_result.status().iter(),
            |_, st| st.contains(Status::POWER_GOOD | Status::ENABLED),
        );
        let unpowered_modules = status_result.modules.remove(&powered_modules);

        // Of the powered modules, those in reset must be also be considered
        // Off.
        let (in_reset, _) =
            filter_module_data(powered_modules, powered_status.iter(), |_, status| {
                status.contains(Status::RESET)
            });

        // At this point, we have the set of `unpowered_modules` and `in_reset`.
        // These will always be reported as off. To determine the real power
        // state, we also need to determine whether modules are configured for
        // software-override, which requires reading their memory maps. We'll
        // filter the set of `powered_modules` to those which we expect to be
        // readable, which are those that are _not_ in reset.
        //
        // In the case that the modules don't use software override, we need to
        // report the status bits themselves as the power state. So filter down
        // the full set of status bits to those that are readable (powered and
        // not in reset).
        let (readable_modules, readable_status) =
            remove_module_data(powered_modules, powered_status.iter(), in_reset);

        // At this point, we have a set of modules we _know_ to be off, the
        // union of `unpowered_modules` and `in_reset`. If we have any modules
        // that we expect to be readable, actually read the power control
        // information and return their `PowerMode`.
        let result = match readable_modules.selected_transceiver_count() {
            0 => PowerModeResult::default(),
            _ => {
                let control = self.power_control(readable_modules).await?;

                // Further filter the status to those that we successfully read
                // from, again so we can index correctly.
                let (_, readable_status) = filter_module_data(
                    readable_modules,
                    readable_status.iter(),
                    |index, _status| control.modules.contains(index),
                );

                // Construct the `PowerMode` for each module we read from, based
                // on software-control and possibly the status bits.
                let mode = control
                    .power_control()
                    .iter()
                    .zip(readable_status.into_iter())
                    .map(|(control, status)| {
                        match control {
                            // If software is in charge, report what it says.
                            PowerControl::OverrideLpModePin { low_power } => {
                                let state = if *low_power {
                                    PowerState::Low
                                } else {
                                    PowerState::High
                                };
                                PowerMode {
                                    state,
                                    software_override: Some(true),
                                }
                            }
                            // Hardware is in charge, so report the state of the
                            // `LPMode` pin itself.
                            PowerControl::UseLpModePin => {
                                let state = if status.contains(Status::LOW_POWER_MODE) {
                                    PowerState::Low
                                } else {
                                    PowerState::High
                                };
                                PowerMode {
                                    state,
                                    software_override: Some(false),
                                }
                            }
                        }
                    })
                    .collect();

                PowerModeResult {
                    modules: control.modules,
                    data: mode,
                    failures: control.failures,
                }
            }
        };

        // We need to add the failures we've already encountered, when first
        // fetching the status.
        let all_failures = result.failures.merge(&status_result.failures);

        // We also need to _insert_ the modules that we know are already off,
        // i.e., those that are unpowered at the EFuse, or in reset.
        //
        // We can do this with a merge-like operation, by iterating over the
        // known-off modules and actual determined modes, and pushing the one
        // with the lower index onto the result arrays.
        let known_off = unpowered_modules.merge(&in_reset);
        let (all_modules, all_modes) = merge_module_data(
            known_off,
            std::iter::repeat(&PowerMode::default()),
            result.modules,
            result.power_modes().iter(),
        );
        Ok(PowerModeResult {
            modules: all_modules,
            data: all_modes,
            failures: all_failures,
        })
    }

    /// Set the power state for a set of transceiver modules.
    ///
    /// This method may be used regardless of whether a module uses hardware
    /// control or software override for controlling the power.
    pub async fn set_power(
        &self,
        modules: ModuleId,
        state: PowerState,
    ) -> Result<AckResult, Error> {
        // How we proceed largely depends on two things: whether we're turning
        // the power OFF entirely, and whether a module has set software
        // override of the `LPMode` pin.
        match state {
            PowerState::Off => {
                // We would technically like to assert `LPMode` here. However,
                // we can't do that without unintentionally back-powering the
                // modules themselves. For now we deassert `LPMode`, but see
                // https://github.com/oxidecomputer/hardware-qsfp-x32/issues/47
                // for the hardware issue and
                // https://rfd.shared.oxide.computer/rfd/0244#_fpga_module_sequencing
                // for a general discussion.
                let AckResult {
                    modules,
                    mut failures,
                    ..
                } = self.deassert_lpmode(modules).await?;
                let AckResult {
                    modules,
                    failures: new_failures,
                    ..
                } = self.assert_reset(modules).await?;
                failures.merge_into(&new_failures);

                let result = self.disable_power(modules).await?;
                failures.merge_into(&result.failures);
                Ok(AckResult { failures, ..result })
            }
            PowerState::Low | PowerState::High => {
                // Validate the power state transition.
                //
                // For now, we enforce that modules may not go directly to high
                // power, they have to go through low-power first.
                //
                // We can always set modules to low power, though, since that's
                // valid from both off and high-power, and a no-op if it's
                // already set.
                //
                // NOTE: `modules` is always the current set we've succesfully
                // operated on thus far. `failures` is always the set of
                // failures we've seen thus far. New failures are merged in at
                // each point.
                let PowerModeResult {
                    modules,
                    data: power_modes,
                    mut failures,
                } = self.power(modules).await?;
                let start_modules = modules; // See end of this function.
                if matches!(state, PowerState::High)
                    && power_modes.iter().any(|mode| mode.state == PowerState::Off)
                {
                    return Err(Error::InvalidPowerStateTransition);
                }

                // We need the status bits to determine if we also need to
                // twiddle `ResetL`.
                //
                // Destructure the response so we can merge in the new failures
                // seen at this point.
                let StatusResult {
                    modules,
                    data: status,
                    failures: new_failures,
                } = self.status(modules).await?;
                failures.merge_into(&new_failures);

                // Check whether power is enabled / good, and / or reset
                // asserted for any of the requested modules. We need to manage
                // those pin states to control the power. Note that this is true
                // regardless of whether the module has software-override of
                // power control set. That's because we want the pins and the
                // memory map to reflect the same state, so that toggling the
                // software override doesn't change the power state of the
                // module, only which hardware signals it responds to.
                let (need_power_enabled, _) =
                    filter_module_data(modules, status.iter(), |_, st| {
                        !st.contains(Status::POWER_GOOD | Status::ENABLED)
                            || st.contains(Status::RESET)
                    });

                // Check for any modules which need power applied, but which do
                // _not_ already have reset asserted. We're going to assert
                // reset on them now, but emit a warning.
                let (need_reset_deasserted, _) =
                    filter_module_data(modules, status.iter(), |_, st| st.contains(Status::RESET));
                let need_power_but_not_reset = need_power_enabled.remove(&need_reset_deasserted);
                let modules = if need_power_but_not_reset.selected_transceiver_count() > 0 {
                    warn!(
                        self.log,
                        "Found modules with power disabled, but reset deasserted. \
                        It will be asserted before enabling power";
                        "need_power_enabled" => ?need_power_enabled,
                        "need_reset_deasserted" => ?need_reset_deasserted,
                        "suspicious_modules" => ?need_power_but_not_reset,
                    );
                    let AckResult {
                        modules,
                        failures: new_failures,
                        ..
                    } = self.assert_reset(need_power_but_not_reset).await?;
                    failures.merge_into(&new_failures);

                    // Wait for SFF-8679 `t_reset_init`. It's a bit silly to
                    // wait 10us here, but we're trying to be careful.
                    sleep(T_RESET_INIT).await;

                    modules
                } else {
                    modules
                };

                // Enable power for the required modules.
                let modules = if need_power_enabled.selected_transceiver_count() > 0 {
                    let AckResult {
                        modules,
                        failures: new_failures,
                        ..
                    } = self.enable_power(need_power_enabled).await?;
                    failures.merge_into(&new_failures);
                    modules
                } else {
                    modules
                };

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
                // - set_software_power_state
                //
                // That's fine, and the best we can do, since the module may not
                // respond to the write until we wait.
                //
                // For modules in the second case, they'll see:
                //
                // - assert_lpmode or deassert_lpmode
                // - set_software_power_state
                //
                // Note that there may be a wait of up to 2s in between the last
                // steps, because other modules may have required twiddling
                // reset. That does lead to a window in which the hardware
                // signal and memory map bit can be out of sync. No
                // functionality here really relies on it, but it is
                // unfortunate.
                let AckResult {
                    modules,
                    failures: new_failures,
                    ..
                } = if matches!(state, PowerState::Low) {
                    self.assert_lpmode(modules).await?
                } else {
                    self.deassert_lpmode(modules).await?
                };
                failures.merge_into(&new_failures);

                // Deassert reset for the required modules.
                //
                // Note that we are explicitly ensuring above that all modules
                // which need reset deasserted also need power enabled. (This
                // cannot apply to modules in high-power state.) So we can use
                // the `need_power_enabled` modules for both operations.
                let modules = if need_power_enabled.selected_transceiver_count() > 0 {
                    let AckResult {
                        modules,
                        failures: new_failures,
                        ..
                    } = self.deassert_reset(need_power_enabled).await?;
                    failures.merge_into(&new_failures);

                    // The SFF-8769 specifies that modules may take up to 2
                    // seconds after asserting ResetL before they are ready for
                    // reads. This is `t_reset`.
                    sleep(T_RESET).await;

                    modules
                } else {
                    modules
                };

                // Set the bits indicating the new power state in the memory map.
                //
                // See note above for why this is here.
                //
                // We'll send in the current power state result, by starting
                // with the power states we received in the first call to
                // `self.power()`, and keeping only those we've successfully
                // operated on up to this point.
                let (_, power_modes) = keep_module_data(start_modules, power_modes.iter(), modules);
                let power_result = PowerModeResult {
                    modules,
                    data: power_modes,
                    failures,
                };
                self.set_software_power_state(power_result, state).await
            }
        }
    }

    // Set the power state assuming software control. _NO CHECKING_ is done as to
    // whether that is the case.
    //
    // # Panics
    //
    // Panics if `state` is not `PowerState::{Low,High}` since `PowerState::Off`
    // isn't relevant to this interface.
    async fn set_software_power_state(
        &self,
        power_result: PowerModeResult,
        state: PowerState,
    ) -> Result<AckResult, Error> {
        assert!(matches!(state, PowerState::Low | PowerState::High));

        // This method is a bit tricky. We issue a sequence of operations, each
        // of which may fail on a subset of the transceivers. At each operation,
        // we possibly filter down the accessed modules to those we've accessed
        // successfully thus far. We also add any failures we've encountered to
        // the running union of the failed modules.
        //
        // `success_modules` and `power_mode` always go together. There are
        // several places where we filter things down, but we should always see
        // these to appear together in those operations.
        //
        // `failures` always contains the union of all the failures.
        //
        // So as we do fallible operations, we'll remove stuff from both
        // `success_modules` and `power_mode`, and add stuff to `failures`.
        let PowerModeResult {
            modules: success_modules,
            data: power_mode,
            mut failures,
        } = power_result;

        // Split the software controlled modules by their identifiers, since we
        // need to write to different regions of the memory map in that case.
        let ident_result = self.identifier(success_modules).await?;
        let split =
            Self::split_modules_by_identifier(&ident_result.modules, ident_result.identifiers());

        // Filter down the successful modules and associated power modes, and
        // add in the latest failures.
        //
        // Note that we're making `succes_modules` and `power_mode` mutable here
        // intentionally. We need to possibly update these values inside the
        // loops below.
        let (mut success_modules, mut power_mode) =
            keep_module_data(success_modules, power_mode.iter(), ident_result.modules);
        failures.merge_into(&ident_result.failures);

        for (ident, modules) in split.into_iter() {
            // Splitting by identifier is not enough, as it is for other cases.
            // We also need to avoid changing the software override bit, so
            // we'll further split this set of modules into those _with_ and
            // _without_ software override. We'll write the same value
            // associated with either of those to the correct bit, when we also
            // change the power state itself.
            //
            // Note that we're filtering on `success_modules` and `power_mode`,
            // since those are always in sync.
            let (with_override, _) =
                filter_module_data(success_modules, power_mode.iter(), |id, mode| {
                    modules.contains(id) && matches!(mode.software_override, Some(true))
                });
            let (without_override, _) =
                filter_module_data(modules, power_mode.iter(), |id, mode| {
                    modules.contains(id) && !matches!(mode.software_override, Some(true))
                });

            for (with_override, modules) in [(true, with_override), (false, without_override)] {
                // TODO-completeness: Consider adding this to the
                // `ParseFromModule` trait, since that encodes these locations
                // for _reads_, but not writes. We could require the implementor
                // to specify these locations themselves in the trait, and then
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
                        // matters if we're setting into high-power state, when we
                        // were already there, _and_ something had enabled those
                        // higher power classes. These bits are also optional, so
                        // we're deferring this for now.
                        let override_bit = if with_override { 0b01 } else { 0b00 };
                        let state_bit = if matches!(state, PowerState::Low) {
                            0b10
                        } else {
                            0b00
                        };
                        (write, state_bit | override_bit)
                    }
                    Identifier::QsfpPlusCmis | Identifier::QsfpDD => {
                        let write = MemoryWrite::new(sff8636::Page::Lower, 26, 1)?;
                        // Byte 26.
                        //
                        // Bit 6: 1 if the module should evaluate the hardware pin.
                        //
                        // Bit 4: Request low power state.
                        //
                        // TODO-correctness: We're technically clobbering bit 5,
                        // which selects the squelch method. We should really be
                        // reading, OR'ing that bit, and writing back.
                        let override_bit = if with_override {
                            0b0000_0000
                        } else {
                            0b0100_0000
                        };
                        let state_bit = if matches!(state, PowerState::Low) {
                            0b0001_0000
                        } else {
                            0b0000_0000
                        };
                        (write, state_bit | override_bit)
                    }
                    id => return Err(Error::from(DecodeError::UnsupportedIdentifier(id))),
                };

                // Issue the write.
                let write_result = self.write_impl(modules, write, &[word]).await?;

                // Update the set of successful / failed modules.
                let (new_modules, new_power_mode) =
                    remove_module_data(modules, power_mode.iter(), write_result.failures.modules);
                success_modules = new_modules;
                power_mode = new_power_mode;
                failures.merge_into(&write_result.failures);
            }
        }
        Ok(AckResult::new(success_modules, failures))
    }

    /// Enable the hot swap controller for a set of transceiver modules.
    ///
    /// See the `set_power` method for a higher-level interface to set the power
    /// to a specific state.
    pub async fn enable_power(&self, modules: ModuleId) -> Result<AckResult, Error> {
        self.no_payload_request(HostRequest::EnablePower(modules))
            .await
    }

    /// Disable the hot swap controller for a set of transceiver modules.
    ///
    /// See the `set_power` method for a higher-level interface to set the power
    /// to a specific state.
    pub async fn disable_power(&self, modules: ModuleId) -> Result<AckResult, Error> {
        self.no_payload_request(HostRequest::DisablePower(modules))
            .await
    }

    /// Assert reset for a set of transceiver modules.
    pub async fn assert_reset(&self, modules: ModuleId) -> Result<AckResult, Error> {
        self.no_payload_request(HostRequest::AssertReset(modules))
            .await
    }

    /// Deassert reset for a set of transceiver modules.
    pub async fn deassert_reset(&self, modules: ModuleId) -> Result<AckResult, Error> {
        self.no_payload_request(HostRequest::DeassertReset(modules))
            .await
    }

    /// Assert physical lpmode pin for a set of transceiver modules. Note: The
    /// effect this pin has on operation can change depending on if the software
    /// override of power control is set.
    ///
    /// See the `set_power` method for a higher-level interface to set the power
    /// to a specific state.
    pub async fn assert_lpmode(&self, modules: ModuleId) -> Result<AckResult, Error> {
        self.no_payload_request(HostRequest::AssertLpMode(modules))
            .await
    }

    /// Deassert physical lpmode pin for a set of transceiver modules. Note: The
    /// effect this pin has on operation can change depending on if the software
    /// override of power control is set.
    ///
    /// See the `set_power` method for a higher-level interface to set the power
    /// to a specific state.
    pub async fn deassert_lpmode(&self, modules: ModuleId) -> Result<AckResult, Error> {
        self.no_payload_request(HostRequest::DeassertLpMode(modules))
            .await
    }

    /// Clear the hot swap controller fault for a set of transceiver modules.
    /// Note: If the fault was induced by a hardware failure it may be only
    /// briefly cleared before being asserted again.
    pub async fn clear_power_fault(&self, modules: ModuleId) -> Result<AckResult, Error> {
        self.no_payload_request(HostRequest::ClearPowerFault(modules))
            .await
    }

    // Helper to create a request where the body is configurable and there is
    // no data payload needed in either the request or response.
    async fn no_payload_request(&self, request: HostRequest) -> Result<AckResult, Error> {
        let message = Message::from(request);
        let request = HostRpcRequest {
            header: self.next_header(message.kind()),
            message,
            data: None,
        };
        let response = self.rpc(request).await?;
        match response.message.body {
            MessageBody::SpResponse(SpResponse::Ack {
                modules: success_modules,
                failed_modules,
            }) => {
                let data = response.data.expect("Existence ensured above");
                let failures = Self::deserialize_hw_errors(failed_modules, &data)?;
                Ok(AckResult::new(success_modules, failures))
            }
            other => Err(Error::UnexpectedMessage(other)),
        }
    }

    /// Report the status of a set of transceiver modules.
    pub async fn status(&self, modules: ModuleId) -> Result<StatusResult, Error> {
        let message = Message::from(HostRequest::Status(modules));
        let request = HostRpcRequest {
            header: self.next_header(MessageKind::HostRequest),
            message,
            data: None,
        };
        let response = self.rpc(request).await?;
        match response.message.body {
            MessageBody::SpResponse(
                st @ SpResponse::Status {
                    modules,
                    failed_modules,
                },
            ) => {
                let data = response.data.expect("Existence of data checked earlier");
                let (data, error_data) = data.split_at(st.expected_data_len().unwrap());
                let status = data
                    .iter()
                    .copied()
                    .map(|x| Status::from_bits(x).unwrap())
                    .collect();
                let failures = Self::deserialize_hw_errors(failed_modules, error_data)?;
                Ok(StatusResult {
                    modules,
                    data: status,
                    failures,
                })
            }
            other => Err(Error::UnexpectedMessage(other)),
        }
    }

    /// Report the status of a set of transceiver modules.
    pub async fn extended_status(&self, modules: ModuleId) -> Result<ExtendedStatusResult, Error> {
        let message = Message::from(HostRequest::ExtendedStatus(modules));
        let request = HostRpcRequest {
            header: self.next_header(MessageKind::HostRequest),
            message,
            data: None,
        };
        let response = self.rpc(request).await?;
        match response.message.body {
            MessageBody::SpResponse(
                st @ SpResponse::ExtendedStatus {
                    modules,
                    failed_modules,
                },
            ) => {
                let data = response.data.expect("Existence of data checked earlier");
                let (data, error_data) = data.split_at(st.expected_data_len().unwrap());
                let status = data
                    .chunks_exact(4)
                    .map(|x| hubpack::deserialize(x).unwrap().0)
                    .collect();
                let failures = Self::deserialize_hw_errors(failed_modules, error_data)?;
                Ok(ExtendedStatusResult {
                    modules,
                    data: status,
                    failures,
                })
            }
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
    ) -> Result<AckResult, Error> {
        let ident_result = self.identifier(modules).await?;
        verify_ids_for_page(
            write.page(),
            &ident_result.modules,
            ident_result.identifiers(),
        )?;
        let write_result = self.write_impl(ident_result.modules, write, data).await?;
        let merged_failures = ident_result.failures.merge(&write_result.failures);
        Ok(AckResult::new(write_result.modules, merged_failures))
    }

    // Implementation of the write function, which does not check that the
    // memory pages address by `write` are valid for the addressed modules.
    async fn write_impl(
        &self,
        modules: ModuleId,
        write: MemoryWrite,
        data: &[u8],
    ) -> Result<AckResult, Error> {
        if usize::from(write.len()) != data.len() {
            return Err(Error::InvalidWriteData {
                expected: write.len().into(),
                actual: data.len(),
            });
        }
        let request = HostRequest::Write { modules, write };
        let message = Message::from(request);
        let request = HostRpcRequest {
            header: self.next_header(message.kind()),
            message,
            data: Some(data.to_vec()),
        };
        let response = self.rpc(request).await?;
        match response.message.body {
            MessageBody::SpResponse(SpResponse::Write {
                modules: success_modules,
                failed_modules,
                ..
            }) => {
                let data = response.data.expect("Data ensured above");
                let failures = Self::deserialize_hw_errors(failed_modules, &data)?;
                Ok(AckResult::new(success_modules, failures))
            }
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
    pub async fn read(&self, modules: ModuleId, read: MemoryRead) -> Result<ReadResult, Error> {
        if modules.selected_transceiver_count() == 0 || read.len() == 0 {
            return Ok(ReadResult::success(modules, vec![]).unwrap());
        }
        let result = self.identifier(modules).await?;
        verify_ids_for_page(read.page(), &result.modules, result.identifiers())?;
        let read_result = self.read_impl(result.modules, read).await?;
        let merged_failures = result.failures.merge(&read_result.failures);
        Ok(ReadResult {
            failures: merged_failures,
            ..read_result
        })
    }

    // Implementation of the read function, which does not check that the memory
    // pages addressed by `read` are valid for the addressed modules.
    async fn read_impl(&self, modules: ModuleId, read: MemoryRead) -> Result<ReadResult, Error> {
        if modules.selected_transceiver_count() == 0 || read.len() == 0 {
            return Ok(ReadResult::success(modules, vec![]).unwrap());
        }
        // It's possible for consumers to request more data than will fit in a
        // single protocol message. We'll split that up here, rather than
        // requiring the consumer to worry about it.
        let mut split_modules = split_large_reads(&modules, &read).into_iter();
        let first_modules = split_modules
            .next()
            .expect("Checked we have at least one module just above");
        let mut response = self.read_impl_one_message(first_modules, read).await?;
        for next_modules in split_modules {
            let next_response = self.read_impl_one_message(next_modules, read).await?;
            response = response.merge(&next_response).unwrap();
        }
        Ok(response)
    }

    // The core implementation of the read method, which requires that all data
    // fits within a single protocol message.
    //
    // # Panics
    //
    // This will panic if the read does not fit in one message.
    async fn read_impl_one_message(
        &self,
        modules: ModuleId,
        read: MemoryRead,
    ) -> Result<ReadResult, Error> {
        assert!(fits_in_one_message(&modules, &read));
        let request = HostRpcRequest {
            header: self.next_header(MessageKind::HostRequest),
            message: Message::from(HostRequest::Read { modules, read }),
            data: None,
        };
        let response = self.rpc(request).await?;
        match response.message.body {
            MessageBody::SpResponse(
                rd @ SpResponse::Read {
                    modules,
                    failed_modules,
                    ..
                },
            ) => {
                let (read_data, error_data) = response
                    .data
                    .as_ref()
                    .expect("Checked earlier")
                    .split_at(rd.expected_data_len().expect("Expected some data length"));

                // We expect data to be a flattened vec of vecs, with the data
                // from each referenced transceiver. Split it into chunks sized
                // by the number of bytes we expected to read.
                let data = read_data
                    .chunks_exact(usize::from(read.len()))
                    .map(Vec::from)
                    .collect::<Vec<_>>();
                assert_eq!(data.len(), modules.selected_transceiver_count());
                let failures = Self::deserialize_hw_errors(failed_modules, error_data)?;
                Ok(ReadResult {
                    modules,
                    data,
                    failures,
                })
            }
            other => Err(Error::UnexpectedMessage(other)),
        }
    }

    /// Describe the memory model of a set of modules.
    pub async fn memory_model(&self, modules: ModuleId) -> Result<MemoryModelResult, Error> {
        self.parse_modules_by_identifier::<MemoryModel>(modules)
            .await
    }

    /// Return the monitoring information of a set of modules.
    pub async fn monitors(&self, modules: ModuleId) -> Result<MonitorResult, Error> {
        self.parse_modules_by_identifier::<Monitors>(modules).await
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
    async fn parse_modules_by_identifier<P: ParseFromModule + core::fmt::Debug>(
        &self,
        modules: ModuleId,
    ) -> Result<ModuleResult<P>, Error> {
        // Create the returned result.
        //
        // As we issue reads and parse the data, we'll update this. Each module
        // we successfully read from and parse will have the result appended to
        // `data`.
        //
        // Each module that we fail to _read_ from will have its error
        // appended to `failures`; the corresponding module will be removed from
        // `modules` and added to `failures`.
        //
        // Note that if we fail to _parse_ the data, we return an `Error` from
        // this method entirely. That's not great, since we could succeed to
        // parse some module's data and fail another.
        let ident_result = self.identifier(modules).await?;
        let mut data_by_index = BTreeMap::new();
        let mut result = ModuleResult {
            modules: ident_result.modules,
            data: Vec::with_capacity(ident_result.modules.selected_transceiver_count()),
            failures: ident_result.failures.clone(),
        };
        let modules_by_id =
            Self::split_modules_by_identifier(&ident_result.modules, ident_result.identifiers());

        // Read data for each _kind_ of module independently.
        for (id, modules) in modules_by_id.into_iter() {
            // Issue the reads for each chunk of data for this kind of module.
            //
            // `read_results` contains the reads from _all modules_ of this
            // kind. In each element, we have a `Vec<Vec<u8>>`, where each inner
            // byte array is for one _module_. Thought of as a multidimensional
            // array, the raw data is indexed by:
            //
            // - Read `i` for the type `P`
            // - Module `j`
            // - Byte `k`
            //
            // These can technically fail, but we'll issue all the reads for all
            // the chunks, and then handle failures below.
            let reads = P::reads(id).map_err(TransceiverError::from)?;
            let read_results = {
                let mut results = Vec::with_capacity(reads.len());
                for read in reads.into_iter() {
                    results.push(self.read_impl(modules, read).await?);
                }
                results
            };

            // Parse the data for each module.
            //
            // Continuing with the multidimensional array analogy here, we're
            // transposing the 0th and 1st dimensions, reads and modules. We
            // want to access all data for module `j`, across all reads `i` and
            // all bytes `k`.
            'module: for module in modules.to_indices() {
                // Construct the data to parse.
                //
                // Specifically, we want to parse the data chunks for this
                // module when we know all of the reads are valid. So let's
                // filter down to those where all reads succeeded, by searching
                // for this module in any of the failures.
                for read_result in read_results.iter() {
                    if let Some(err) = read_result.nth_err(module) {
                        // Remove from the set of successful modules.
                        result
                            .modules
                            .clear(module)
                            .expect("Module indices previously verified");
                        // Add to the final set of errors.
                        result
                            .failures
                            .modules
                            .set(module)
                            .expect("Module indices previously verified");
                        result.failures.errors.push(*err);
                        // Skip to the next module entirely.
                        continue 'module;
                    }
                }

                // At this point, we know we've successfully read all the chunks
                // for this module. Collect them for parsing.
                let parse_data = read_results.iter().map(|read_result| {
                    read_result
                        .nth(module)
                        .expect("Only fully-read modules should be here")
                        .as_slice()
                });

                // Parse all the data from the module.
                //
                // This may also fail, in which case we'll add the module into
                // the failed set as well. Note that we store all data in a map
                // by index, so that we can be sure to keep it sorted
                // appropriately at the end of the entire operation.
                match P::parse(id, parse_data) {
                    Ok(parsed) => {
                        data_by_index.insert(module, parsed);
                    }
                    Err(e) => {
                        result
                            .modules
                            .clear(module)
                            .expect("Module indices previously verified");
                        result
                            .failures
                            .modules
                            .set(module)
                            .expect("Module indices previously verified");
                        result.failures.errors.push(TransceiverError::from(e));
                    }
                }
            }
        }
        // Collect the data into the output array, which maintains the sort
        // order by module index.
        result.data.extend(data_by_index.into_values());
        Ok(result)
    }

    // Issue one RPC, possibly retrying, and await the response.
    async fn rpc(&self, request: HostRpcRequest) -> Result<SpRpcResponse, Error> {
        let (response_tx, response_rx) = oneshot::channel();
        let outstanding_request = OutstandingHostRequest {
            request,
            n_retries: 0,
            n_error_messages: 0,
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

// Split a read which may be too large to fit in one protocol message into an
// iterator over modules. Each item contains at least one module, and few enough
// the the issued read is guaranteed to fit in a single response message.
//
// Note that this just splits the _modules_ into groups, it never modifies the
// `read` argument. The `MemoryRead` type ensures that the read is always able
// to fit in a single message by construction.
fn split_large_reads<'a>(modules: &'a ModuleId, read: &'a MemoryRead) -> Vec<ModuleId> {
    let n_modules_per_request = MAX_PAYLOAD_SIZE / usize::from(read.len());
    modules
        .to_indices()
        .chunks(n_modules_per_request)
        .into_iter()
        .map(|chunk| ModuleId::from_index_iter(chunk).unwrap())
        .collect()
}

// Return `true` if the provided read information will fit in one protocol
// message.
fn fits_in_one_message(modules: &ModuleId, read: &MemoryRead) -> bool {
    let n_bytes = modules.selected_transceiver_count() * usize::from(read.len());
    n_bytes <= MAX_PAYLOAD_SIZE
}

fn verify_ids_for_page(
    page: &Page,
    modules: &ModuleId,
    ids: &[Identifier],
) -> Result<(), TransceiverError> {
    let interface = page.management_interface();
    let mut items = modules.to_indices().zip(ids.iter());
    let to_err = |module_index, identifier| {
        Err(TransceiverError::InvalidInterfaceForModule {
            module_index,
            identifier,
            interface,
        })
    };
    match interface {
        ManagementInterface::Sff8636 => {
            match items.find(|(_index, &ident)| {
                !(ident == Identifier::Qsfp28 || ident == Identifier::QsfpPlusSff8636)
            }) {
                None => Ok(()),
                Some((ix, ident)) => to_err(ix, *ident),
            }
        }
        ManagementInterface::Cmis => {
            match items.find(|(_index, &ident)| {
                !(ident == Identifier::QsfpDD || ident == Identifier::QsfpPlusCmis)
            }) {
                None => Ok(()),
                Some((ix, ident)) => to_err(ix, *ident),
            }
        }
        ManagementInterface::Unknown(_) => unimplemented!(
            "Only SFF-8636 and CMIS management interfaces \
                are currently implemented"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::fits_in_one_message;
    use super::split_large_reads;
    use super::verify_ids_for_page;
    use super::Identifier;
    use super::ModuleId;
    use super::Page;
    use super::PowerState;
    use crate::config::ConfigBuilder;
    use crate::messages::SpRequest;
    use crate::results::AckResult;
    use crate::results::FailedModules;
    use crate::results::IdentifierResult;
    use crate::results::MemoryModelResult;
    use crate::results::PowerModeResult;
    use crate::test_utils;
    use crate::Controller;
    use crate::Error;
    use crate::PowerMode;
    use crate::TransceiverError;
    use crate::NUM_OUTSTANDING_REQUESTS;
    use hubpack::SerializedSize;
    use serde::Serialize;
    use std::net::Ipv6Addr;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;
    use tokio::sync::oneshot;
    use transceiver_decode::MemoryModel;
    use transceiver_decode::ParseFromModule;
    use transceiver_decode::PowerControl;
    use transceiver_messages::mac::BadMacAddrRange;
    use transceiver_messages::mac::BadMacAddrReason;
    use transceiver_messages::mac::MacAddrs;
    use transceiver_messages::message::Header;
    use transceiver_messages::message::HostRequest;
    use transceiver_messages::message::HwError;
    use transceiver_messages::message::MacAddrResponse;
    use transceiver_messages::message::Message;
    use transceiver_messages::message::MessageBody;
    use transceiver_messages::message::SpResponse;
    use transceiver_messages::message::Status;
    use transceiver_messages::mgmt::cmis;
    use transceiver_messages::mgmt::sff8636;
    use transceiver_messages::mgmt::MemoryRead;
    use transceiver_messages::MAX_PACKET_SIZE;
    use transceiver_messages::MAX_PAYLOAD_SIZE;

    #[test]
    fn test_verify_ids_for_page() {
        let page = Page::Sff8636(sff8636::Page::Lower);
        let modules = ModuleId(0b11);
        assert!(verify_ids_for_page(
            &page,
            &modules,
            &[Identifier::Qsfp28, Identifier::QsfpPlusSff8636]
        )
        .is_ok());
        assert!(verify_ids_for_page(
            &page,
            &modules,
            &[Identifier::QsfpDD, Identifier::QsfpPlusCmis]
        )
        .is_err());
    }

    #[test]
    fn test_deserialize_power_state() {
        assert_eq!(PowerState::Off, serde_json::from_str("\"off\"").unwrap());
        assert_eq!(PowerState::Low, serde_json::from_str("\"low\"").unwrap());
        assert_eq!(PowerState::High, serde_json::from_str("\"high\"").unwrap());
    }

    #[test]
    fn test_serialize_power_state() {
        assert_eq!(serde_json::to_string(&PowerState::Off).unwrap(), "\"off\"");
        assert_eq!(serde_json::to_string(&PowerState::Low).unwrap(), "\"low\"");
        assert_eq!(
            serde_json::to_string(&PowerState::High).unwrap(),
            "\"high\""
        );
    }

    #[derive(Debug)]
    struct MockSp {
        // Socket on which we receive host requests / send responses
        socket: UdpSocket,

        // The message bodies we expect the host to send us. We assert that
        // these are received in exactly this order. Note that we can't really
        // test the headers, since the `Controller` generates those internally.
        //
        // We may want to move these to integration tests, since that's really
        // what they are, testing the actual interface.
        expected_requests: Vec<Message>,

        // The sequence of response messages we want to send back. These should
        // match up exactly with the `expected_requests`. The second tuple
        // element is the possible trailing data to write into the message.
        responses: Vec<(Message, Option<Vec<u8>>)>,

        // Channel we use to signal that we died.
        ded: Option<oneshot::Sender<Result<(), String>>>,
    }

    impl Drop for MockSp {
        fn drop(&mut self) {
            self.notify(Err(String::from("dropped")));
        }
    }

    impl MockSp {
        fn notify(&mut self, what: Result<(), String>) {
            if let Some(sender) = self.ded.take() {
                let _ = sender.send(what);
            }
        }

        async fn run(mut self) {
            let mut rx_buf = [0u8; MAX_PACKET_SIZE];
            let mut tx_buf = [0u8; MAX_PACKET_SIZE];
            for (i, (expected_request, (response, maybe_data))) in self
                .expected_requests
                .iter()
                .zip(self.responses.iter())
                .enumerate()
            {
                // Need a clean slate.
                rx_buf.fill(0);
                tx_buf.fill(0);

                // Take a request, and assert it matches.
                let (_n_bytes, peer) = match self.socket.recv_from(&mut rx_buf).await {
                    Ok(x) => x,
                    Err(e) => {
                        self.notify(Err(format!("recv failed: {e:?}")));
                        return;
                    }
                };
                let (header, remainder) = match hubpack::deserialize::<Header>(&rx_buf) {
                    Ok(x) => x,
                    Err(e) => {
                        self.notify(Err(format!("header deserialization failed: {e:?}")));
                        return;
                    }
                };
                let (message, _remainder) = match hubpack::deserialize::<Message>(&remainder) {
                    Ok(x) => x,
                    Err(e) => {
                        self.notify(Err(format!("message deserialization failed: {e:?}")));
                        return;
                    }
                };
                if &message != expected_request {
                    self.notify(Err(format!(
                        "received request {i} does not match expected, \
                        expected = {expected_request:?}, actual = \
                        {message:?}",
                    )));
                    return;
                }

                // Send the response we were told to send.
                let header = Header::new(header.message_id, response.kind());
                let mut n_written = match hubpack::serialize(&mut tx_buf, &header) {
                    Ok(n) => n,
                    Err(e) => {
                        self.notify(Err(format!("header serialization failed: {e:?}")));
                        return;
                    }
                };
                n_written += match hubpack::serialize(&mut tx_buf[n_written..], &response) {
                    Ok(n) => n,
                    Err(e) => {
                        self.notify(Err(format!("response serialization failed: {e:?}")));
                        return;
                    }
                };

                // Send the trailing data, if any.
                if let Some(data) = &maybe_data {
                    tx_buf[n_written..][..data.len()].copy_from_slice(&data);
                    n_written += data.len();
                }
                self.socket
                    .send_to(&tx_buf[..n_written], peer)
                    .await
                    .unwrap();
            }

            // Notify of successful completion of our loop, so the tests pass.
            self.notify(Ok(()));
        }
    }

    // The interface we assume for testing.
    //
    // This will only work on illumos systems.
    const IFACE: &str = "lo0";

    fn request_channels() -> (mpsc::Sender<SpRequest>, mpsc::Receiver<SpRequest>) {
        mpsc::channel(NUM_OUTSTANDING_REQUESTS)
    }

    // Return a Controller and UDP socket for the mock SP.
    async fn peer_setup() -> (Controller, UdpSocket) {
        let sp_socket = test_utils::localhost_socket().await;
        let SocketAddr::V6(peer) = sp_socket.local_addr().unwrap() else {
            panic!("Must be Ipv6");
        };
        let config = ConfigBuilder::new(IFACE)
            .address(Ipv6Addr::LOCALHOST)
            .port(0)
            .peer(*peer.ip())
            .peer_port(peer.port())
            .build()
            .unwrap();
        let log = test_utils::test_logger();
        let (request_tx, _request_rx) = request_channels();
        (
            Controller::new(config, log, request_tx).await.unwrap(),
            sp_socket,
        )
    }

    #[tokio::test]
    async fn test_macs() {
        let (controller, socket) = peer_setup().await;
        let expected_requests =
            vec![Message::new(MessageBody::HostRequest(HostRequest::MacAddrs)); 2];
        let mac = [0xa8, 0x40, 0x25, 0xff, 0xff, 0xfe];
        let macs = MacAddrs::new(mac, 1, 1).unwrap();
        let bad = BadMacAddrRange {
            base_mac: mac,
            count: 100,
            stride: 100,
            reason: BadMacAddrReason::SpansMultipleOuis,
        };
        let responses = vec![
            (
                Message::new(MessageBody::SpResponse(SpResponse::MacAddrs(
                    MacAddrResponse::Ok(macs),
                ))),
                None,
            ),
            (
                Message::new(MessageBody::SpResponse(SpResponse::MacAddrs(
                    MacAddrResponse::Error(bad),
                ))),
                None,
            ),
        ];
        let (ded, mut ded_rx) = oneshot::channel();
        let sp = MockSp {
            socket,
            expected_requests,
            responses,
            ded: Some(ded),
        };
        let _sp_task = tokio::spawn(sp.run());

        tokio::select! {
            e = &mut ded_rx => panic!("MockSp panicked: {e:?}"),
            response = controller.mac_addrs() => {
                assert_eq!(response.unwrap(), macs);
            }
        }
        tokio::select! {
            note = &mut ded_rx => {
                note.unwrap().expect("MockSp panicked");
            }
            response = controller.mac_addrs() => {
                let Err(Error::Mac(e)) = &response else {
                    panic!("Expected bad MAC error, found {response:?}");
                };
                assert_eq!(e, &bad);
            }
        }
    }

    fn serialize_vec<T: SerializedSize + Serialize>(items: &[T]) -> Vec<u8> {
        let size = items.len() * T::MAX_SIZE;
        let mut out = vec![0; size];
        let mut buf = &mut out[..];
        for item in items.iter() {
            let n = hubpack::serialize(&mut buf, item).unwrap();
            buf = &mut buf[n..];
        }
        out
    }

    #[tokio::test]
    async fn test_identifier() {
        let (controller, socket) = peer_setup().await;

        let read = MemoryRead::new(sff8636::Page::Lower, 0, 1).unwrap();
        let modules = ModuleId(0b11);
        let ident = vec![Identifier::QsfpPlusSff8636, Identifier::QsfpPlusCmis];
        let failed_modules = ModuleId(0b01);
        let errors = vec![HwError::FpgaError];
        let received_errors = vec![TransceiverError::Hardware {
            module_index: 0,
            source: errors[0].clone(),
        }];
        let expected_requests = vec![
            Message::new(MessageBody::HostRequest(HostRequest::Read {
                modules,
                read,
            }));
            2
        ];

        let success_data = ident.iter().map(|id| u8::from(*id)).collect();
        let error_data = [vec![u8::from(ident[0])], serialize_vec(&errors)].concat();
        let responses = vec![
            (
                Message::new(MessageBody::SpResponse(SpResponse::Read {
                    modules,
                    failed_modules: ModuleId::empty(),
                    read,
                })),
                Some(success_data),
            ),
            (
                Message::new(MessageBody::SpResponse(SpResponse::Read {
                    modules: modules.remove(&failed_modules),
                    failed_modules,
                    read,
                })),
                Some(error_data),
            ),
        ];
        let (ded, mut ded_rx) = oneshot::channel();
        let sp = MockSp {
            socket,
            expected_requests,
            responses,
            ded: Some(ded),
        };
        let _sp_task = tokio::spawn(sp.run());

        // We want to _either_ panic if the SP did, or get the result from the
        // `Controller::identifier` call.
        tokio::select! {
            e = &mut ded_rx => panic!("MockSp panicked: {e:?}"),
            response = controller.identifier(modules) => {
                assert_eq!(
                    response.unwrap(), IdentifierResult {
                        modules: modules,
                        data: ident.clone(),
                        failures: FailedModules::success(),
                    });
            }
        }

        let response = tokio::spawn(async move { controller.identifier(modules).await });
        let _ = ded_rx.await.unwrap().expect("MockSp panicked");
        assert_eq!(
            response.await.unwrap().unwrap(),
            IdentifierResult {
                modules: modules.remove(&failed_modules),
                data: ident[..1].to_vec(),
                failures: FailedModules {
                    modules: failed_modules,
                    errors: received_errors,
                },
            }
        );
    }

    #[tokio::test]
    async fn test_assert_lp_mode() {
        simple_ack_op(HostRequest::AssertLpMode).await;
    }

    #[tokio::test]
    async fn test_deassert_lp_mode() {
        simple_ack_op(HostRequest::DeassertLpMode).await;
    }

    #[tokio::test]
    async fn test_enable_power() {
        simple_ack_op(HostRequest::EnablePower).await;
    }

    #[tokio::test]
    async fn test_disable_power() {
        simple_ack_op(HostRequest::DisablePower).await;
    }

    #[tokio::test]
    async fn test_assert_reset() {
        simple_ack_op(HostRequest::AssertReset).await;
    }

    #[tokio::test]
    async fn test_deassert_reset() {
        simple_ack_op(HostRequest::DeassertReset).await;
    }

    #[tokio::test]
    async fn test_clear_power_fault() {
        simple_ack_op(HostRequest::ClearPowerFault).await;
    }

    // Helper function to run a bunch of tests, which generally just send some
    // simple host request and await an ACK. E.g., assert reset and disable
    // power are fundamentally the same, with a slightly different method and
    // message.
    async fn simple_ack_op(req: impl Fn(ModuleId) -> HostRequest) {
        let (controller, socket) = peer_setup().await;
        let controller = Arc::new(controller);

        // The modules which succeed on the first call, and fail on the second.
        let modules = ModuleId(0b11);
        let failed_modules = ModuleId(0b01);

        // The actual error is not realistic, but any HwError will do.
        let errors = vec![HwError::FpgaError];
        let received_errors = vec![TransceiverError::Hardware {
            module_index: 0,
            source: errors[0].clone(),
        }];
        let request = req(modules);
        let expected_requests = vec![Message::new(MessageBody::HostRequest(request)); 2];

        let error_data = serialize_vec(&errors);
        let responses = vec![
            (
                Message::new(MessageBody::SpResponse(SpResponse::Ack {
                    modules,
                    failed_modules: ModuleId::empty(),
                })),
                None,
            ),
            (
                Message::new(MessageBody::SpResponse(SpResponse::Ack {
                    modules: modules.remove(&failed_modules),
                    failed_modules,
                })),
                Some(error_data),
            ),
        ];
        let (ded, mut ded_rx) = oneshot::channel();
        let sp = MockSp {
            socket,
            expected_requests,
            responses,
            ded: Some(ded),
        };
        let _sp_task = tokio::spawn(sp.run());

        // We want to _either_ panic if the SP did, or get the result from the
        // actual method we ran. Spawn the actual method on a separate task so
        // it can run in parallel.
        let ctl = controller.clone();
        let task = match request {
            HostRequest::AssertReset(_) => {
                tokio::spawn(async move { ctl.assert_reset(modules).await })
            }
            HostRequest::DeassertReset(_) => {
                tokio::spawn(async move { ctl.deassert_reset(modules).await })
            }
            HostRequest::EnablePower(_) => {
                tokio::spawn(async move { ctl.enable_power(modules).await })
            }
            HostRequest::DisablePower(_) => {
                tokio::spawn(async move { ctl.disable_power(modules).await })
            }
            HostRequest::AssertLpMode(_) => {
                tokio::spawn(async move { ctl.assert_lpmode(modules).await })
            }
            HostRequest::DeassertLpMode(_) => {
                tokio::spawn(async move { ctl.deassert_lpmode(modules).await })
            }
            HostRequest::ClearPowerFault(_) => {
                tokio::spawn(async move { ctl.clear_power_fault(modules).await })
            }
            _ => unimplemented!(),
        };
        let response = tokio::select! {
            e = &mut ded_rx => panic!("MockSp panicked: {e:?}"),
            response = task => response.unwrap().unwrap(),
        };
        assert_eq!(
            response,
            AckResult {
                modules: modules,
                data: vec![(); 2],
                failures: FailedModules::success(),
            }
        );

        // Same thing, spawn a task to run the actual controller method.
        let task = match request {
            HostRequest::AssertReset(_) => {
                tokio::spawn(async move { controller.assert_reset(modules).await })
            }
            HostRequest::DeassertReset(_) => {
                tokio::spawn(async move { controller.deassert_reset(modules).await })
            }
            HostRequest::EnablePower(_) => {
                tokio::spawn(async move { controller.enable_power(modules).await })
            }
            HostRequest::DisablePower(_) => {
                tokio::spawn(async move { controller.disable_power(modules).await })
            }
            HostRequest::AssertLpMode(_) => {
                tokio::spawn(async move { controller.assert_lpmode(modules).await })
            }
            HostRequest::DeassertLpMode(_) => {
                tokio::spawn(async move { controller.deassert_lpmode(modules).await })
            }
            HostRequest::ClearPowerFault(_) => {
                tokio::spawn(async move { controller.clear_power_fault(modules).await })
            }
            _ => unimplemented!(),
        };
        let _ = ded_rx.await.unwrap().expect("MockSp panicked");
        assert_eq!(
            task.await.unwrap().unwrap(),
            AckResult {
                modules: modules.remove(&failed_modules),
                data: vec![(); 1],
                failures: FailedModules {
                    modules: failed_modules,
                    errors: received_errors,
                },
            }
        );
    }

    // Test fetching the power mode of a set of transceiver modules.
    //
    // `Controller::power_mode` combines a few different pieces, to determine a
    // higher-level "power mode" for a module:
    //
    // - The actual power supply to the module, via the EFuse.
    // - The ResetL signal
    // - Reading the LPMode signal
    // - Reading the memory map, to determine software control.
    //
    // The first three are retrieved from the status bits. The latter is
    // retrieved from the memory map, only for modules that have power and are
    // not in reset (i.e., are readable).
    //
    // This test tries to capture all of those possibilities, with a bunch of
    // modules.
    //
    // - One with no hardware power
    // - One with hardware power, but in reset
    // - One with hardware power and _not_ software override, in hardware
    // low-power.
    // - One with hardware power and _with_ software override, in software
    // low-power.
    // - One with hardware power and _not_ software override, in hardware
    // high-power mode
    // - One with hardware power and _with_ software override, in software
    // high-power mode
    //
    // These should be reported as two modules in `PowerState::Off`, two in
    // `PowerState::Low`, and two in `PowerState::High`. Of the last four, we
    // should alternate between hardware and software control.
    #[tokio::test]
    async fn test_power_mode_no_failures() {
        let (controller, socket) = peer_setup().await;

        // We'll read six modules, and here test without any failures.
        let modules = ModuleId(0b0011_1111);

        // The first two modules, one each of SFF and CMIS, are unpowered and in
        // reset respectively. Those will always be reported as off, so we'll
        // never try to read from them.
        let readable_modules = ModuleId(0b0011_1100);
        let readable_sff_modules = ModuleId(0b0000_1100);
        let readable_cmis_modules = ModuleId(0b0011_0000);

        // The expected status for _all_ modules
        let expected_status = vec![
            Status::empty(),
            Status::POWER_GOOD | Status::ENABLED | Status::LOW_POWER_MODE | Status::RESET,
            Status::POWER_GOOD | Status::ENABLED | Status::LOW_POWER_MODE,
            Status::POWER_GOOD | Status::ENABLED | Status::LOW_POWER_MODE,
            Status::POWER_GOOD | Status::ENABLED,
            Status::POWER_GOOD | Status::ENABLED,
        ];

        // The expected power modes, i.e., the final output of the actual
        // `Controller::power` call.
        let expected_power_mode = vec![
            PowerMode {
                state: PowerState::Off,
                software_override: None,
            },
            PowerMode {
                state: PowerState::Off,
                software_override: None,
            },
            PowerMode {
                state: PowerState::Low,
                software_override: Some(false),
            },
            PowerMode {
                state: PowerState::Low,
                software_override: Some(true),
            },
            PowerMode {
                state: PowerState::High,
                software_override: Some(false),
            },
            PowerMode {
                state: PowerState::High,
                software_override: Some(true),
            },
        ];

        // When reading the memory map, of the last four modules, the
        // identifiers will first be accessed. We'll pretend there are two of
        // each supported kind.
        let expected_identifiers = vec![
            Identifier::QsfpPlusSff8636,
            Identifier::QsfpPlusSff8636,
            Identifier::QsfpPlusCmis,
            Identifier::QsfpPlusCmis,
        ];

        // The method first accesses the status, then reads the memory map for
        // the last four modules. Each of those accesses a single byte in the
        // memory map, defined by the `PowerModel::reads()` method for the
        // corresponding identifier.
        //
        // We know there's just one read required to access the power control
        // data. Also note that we issue only _two_ read requests for the last 4
        // modules -- that's because `parse_modules_by_identifier()` splits the
        // modules by ID, and there are two kinds of IDs (SFF and CMIS).
        let power_control_reads = [Identifier::QsfpPlusSff8636, Identifier::QsfpPlusCmis]
            .into_iter()
            .map(|id| PowerControl::reads(id).unwrap()[0])
            .collect::<Vec<_>>();
        let read_modules = vec![readable_sff_modules, readable_cmis_modules];

        // Create the expected host -> SP requests.
        //
        // This will hit the status for all the modules, and then should filter
        // that down to the last four modules for a read. Because there are two
        // _kinds_ of modules, those will be read separately. That makes two
        // reads, each for two modules.
        let identifier_read = MemoryRead::new(sff8636::Page::Lower, 0, 1).unwrap();
        let mut expected_requests = vec![
            Message::new(MessageBody::HostRequest(HostRequest::Status(modules))),
            Message::new(MessageBody::HostRequest(HostRequest::Read {
                modules: readable_modules,
                read: identifier_read,
            })),
        ];
        expected_requests.extend(power_control_reads.iter().zip(read_modules.iter()).map(
            |(read, modules)| {
                Message::new(MessageBody::HostRequest(HostRequest::Read {
                    modules: *modules,
                    read: *read,
                }))
            },
        ));

        // The successful data for each request will consist of:
        //
        // - The status bits for all modules
        // - The identifiers for all modules
        // - The PowerControl for each of the four modules actually read from.
        //
        // For the SFF modules, that is one octet with:
        // - bit 0 clear -> use the hardware signal
        // - bit 0 set -> use bit 1
        // - bit 1 set -> force low-power mode
        //
        // For the CMIS modules, that is one octet with:
        // - bit 6 set -> evaluate LPMode signal (hardware control)
        // - bit 6 clear -> use bit 4
        // - bit 4 set -> force low-power mode.
        //
        // Note that we set the bit forcing to LPMode for all reads. That should
        // not matter, but it is how our software is expected to operate.
        let status_data = serialize_vec(&expected_status);
        let identifier_data = expected_identifiers
            .iter()
            .map(|id| u8::from(*id))
            .collect::<Vec<_>>();
        let read_data = vec![
            // SFF-8636, low-power hardware control
            vec![0b10],
            // SFF-8636, low-power software control
            vec![0b11],
            // CMIS, high-power hardware control
            vec![0b100_0000],
            // CMIS, high-power software control
            vec![0b000_0000],
        ];

        // Construct the expected responses to each host request.
        //
        // - Status
        // - Identifier read on all modules
        // - PowerControl read on 2 SFF-8636 modules
        // - PowerControl read on 2 CMIS modules
        //
        // None of these fail.
        let responses = vec![
            (
                Message::new(MessageBody::SpResponse(SpResponse::Status {
                    modules,
                    failed_modules: ModuleId::empty(),
                })),
                Some(status_data),
            ),
            (
                Message::new(MessageBody::SpResponse(SpResponse::Read {
                    modules: readable_modules,
                    failed_modules: ModuleId::empty(),
                    read: identifier_read,
                })),
                Some(identifier_data),
            ),
            (
                Message::new(MessageBody::SpResponse(SpResponse::Read {
                    modules: readable_sff_modules,
                    failed_modules: ModuleId::empty(),
                    read: power_control_reads[0],
                })),
                Some(read_data[..2].concat()),
            ),
            (
                Message::new(MessageBody::SpResponse(SpResponse::Read {
                    modules: readable_cmis_modules,
                    failed_modules: ModuleId::empty(),
                    read: power_control_reads[1],
                })),
                Some(read_data[2..].concat()),
            ),
        ];

        let (ded, ded_rx) = oneshot::channel();
        let sp = MockSp {
            socket,
            expected_requests,
            responses,
            ded: Some(ded),
        };
        let _sp_task = tokio::spawn(sp.run());

        // Spawn a task to run the actual controller request.
        let task = tokio::spawn(async move { controller.power(modules).await });
        ded_rx.await.unwrap().expect("MockSp panicked");
        let response = task.await.unwrap().unwrap();
        assert_eq!(
            response,
            PowerModeResult {
                modules: modules,
                data: expected_power_mode,
                failures: FailedModules::success(),
            }
        );
    }

    // This tests how we winnow down requests to read the power mode from a set
    // of modules.
    //
    // The method looks at both hardware signals and possibly the memory map in
    // a few ways. We'll inject requests at each stage, and ensure that we
    // filter things down appropriately (and add the right errors) along the
    // way.
    #[tokio::test]
    async fn test_power_mode_with_failures() {
        let (controller, socket) = peer_setup().await;

        // There are 3 real places we can fail
        //
        // - Reading the status bits
        // - Reading the identifier, once we've confirmed a module is powered.
        // - Reading the memory map bits pertaining to software override.
        //
        // We'll start with four modules, and inject a failure on three of them
        // at each stage. At the end, we should be left with the single module
        // and three failures.
        let modules = ModuleId(0b1111);

        // Modules that fail the first request to fetch the status.
        let failed_status_modules = ModuleId(0b001);

        // Modules that we then issue the first request to read the identifier
        // for, internally to the `power_control` method.
        let read_ident_modules = modules.remove(&failed_status_modules);

        // Modules that we fail to fetch the identifier for, in the
        // `power_control` method.
        let failed_ident_modules = ModuleId(0b010);

        // Modules we then read the power control bytes from.
        let read_modules = read_ident_modules.remove(&failed_ident_modules);

        // Modules we fail to read the status control bytes from.
        let failed_read_modules = ModuleId(0b100);

        // The modules we expect to succeed with at the end of the day.
        let success_modules = read_modules.remove(&failed_read_modules);

        // The modules we expect to have failed at the end of the day.
        let all_failures = modules.remove(&success_modules);

        // We expect to fetch the status for all but the first module.
        let expected_status = vec![
            Status::POWER_GOOD | Status::ENABLED | Status::LOW_POWER_MODE,
            Status::POWER_GOOD | Status::ENABLED | Status::LOW_POWER_MODE,
            Status::POWER_GOOD | Status::ENABLED | Status::LOW_POWER_MODE,
        ];
        let expected_status_data = serialize_vec(&expected_status);

        // The error expected for that first module.
        let expected_status_err = vec![TransceiverError::Hardware {
            module_index: 0,
            source: HwError::FpgaError,
        }];
        let expected_status_err_data = serialize_vec(&[HwError::FpgaError]);

        // We expect to read the identifier for the latter 2 modules.
        let expected_idents = vec![Identifier::QsfpPlusSff8636; 2];
        let expected_ident_data = expected_idents
            .iter()
            .copied()
            .map(u8::from)
            .collect::<Vec<_>>();

        // The expected error for the third module.
        let expected_ident_err = vec![TransceiverError::Hardware {
            module_index: 1,
            source: HwError::FpgaError,
        }];
        let expected_ident_err_data = serialize_vec(&[HwError::FpgaError]);

        // We expect to read only the last module, returning the power mode
        // below.
        let expected_power_mode = vec![PowerMode {
            state: PowerState::Low,
            software_override: Some(false),
        }];
        let expected_power_data = vec![
            // SFF-8636, low-power hardware control
            vec![0b10],
        ];

        // The expected error for the second module.
        let expected_power_err = vec![TransceiverError::Hardware {
            module_index: 2,
            source: HwError::FpgaError,
        }];
        let expected_power_err_data = serialize_vec(&[HwError::FpgaError]);

        // Bundle all the requests.
        let identifier_read = MemoryRead::new(sff8636::Page::Lower, 0, 1).unwrap();
        let power_control_read = PowerControl::reads(Identifier::QsfpPlusSff8636).unwrap()[0];
        let expected_requests = vec![
            // Fetch the status
            Message::new(MessageBody::HostRequest(HostRequest::Status(modules))),
            // Fetch the identifier
            Message::new(MessageBody::HostRequest(HostRequest::Read {
                modules: read_ident_modules,
                read: identifier_read,
            })),
            // Fetch the actual power control bytes.
            Message::new(MessageBody::HostRequest(HostRequest::Read {
                modules: read_modules,
                read: power_control_read,
            })),
        ];

        // Build the responses we expect.
        let responses = vec![
            // We've asked for all modules, but we get back only those that we
            // can read the identifier for.
            (
                Message::new(MessageBody::SpResponse(SpResponse::Status {
                    modules: read_ident_modules,
                    failed_modules: failed_status_modules,
                })),
                Some([expected_status_data, expected_status_err_data].concat()),
            ),
            // We've asked for `read_ident_modules`, but one failed, so we get
            // back only those that we can actually read from.
            (
                Message::new(MessageBody::SpResponse(SpResponse::Read {
                    modules: read_modules,
                    failed_modules: failed_ident_modules,
                    read: identifier_read,
                })),
                Some([expected_ident_data.clone(), expected_ident_err_data].concat()),
            ),
            // We've asked for `read_modules`, but one failed, so we get back
            // only those that we can actually read from. This captures the
            // first internal read of the identifier in `power_control`, which
            // we fail on that first module. So the modules here are the same as
            // below.
            (
                Message::new(MessageBody::SpResponse(SpResponse::Read {
                    modules: success_modules,
                    failed_modules: failed_read_modules,
                    read: identifier_read,
                })),
                Some([expected_power_data[0].clone(), expected_power_err_data].concat()),
            ),
        ];

        let (ded, ded_rx) = oneshot::channel();
        let sp = MockSp {
            socket,
            expected_requests,
            responses,
            ded: Some(ded),
        };
        let _sp_task = tokio::spawn(sp.run());

        // Spawn a task to run the actual controller request.
        let task = tokio::spawn(async move { controller.power(modules).await });
        ded_rx.await.unwrap().expect("MockSp panicked");
        let response = task.await.unwrap().unwrap();
        assert_eq!(
            response,
            PowerModeResult {
                modules: success_modules,
                data: expected_power_mode,
                failures: FailedModules {
                    modules: all_failures,
                    errors: vec![
                        expected_status_err[0].clone(),
                        expected_ident_err[0].clone(),
                        expected_power_err[0].clone()
                    ],
                }
            }
        );
    }

    // Test setting the power mode to off, which is pretty straightfoward.
    //
    // This tries to turn off power to four modules. The first three fail at
    // each of the three requests made internally in `set_power` in this case.
    // The last one succeeds.
    #[tokio::test]
    async fn test_set_power_mode_off() {
        let (controller, socket) = peer_setup().await;

        // Build up the set of modules we start with, and the failures we hit
        // along the. Also construct the errors each request.
        let modules = ModuleId(0b1111);
        let failed_lp_mode_modules = ModuleId(0b0001);
        let failed_lp_mode_err = &[HwError::FpgaError];
        let assert_reset_modules = modules.remove(&failed_lp_mode_modules);
        let failed_reset_modules = ModuleId(0b0010);
        let failed_reset_err = &[HwError::FpgaError];
        let disable_power_modules = assert_reset_modules.remove(&failed_reset_modules);
        let failed_disable_power_modules = ModuleId(0b0100);
        let failed_disable_power_err = &[HwError::FpgaError];
        let success = disable_power_modules.remove(&failed_disable_power_modules);

        let expected_requests = vec![
            Message::new(MessageBody::HostRequest(HostRequest::DeassertLpMode(
                modules,
            ))),
            Message::new(MessageBody::HostRequest(HostRequest::AssertReset(
                assert_reset_modules,
            ))),
            Message::new(MessageBody::HostRequest(HostRequest::DisablePower(
                disable_power_modules,
            ))),
        ];
        let responses = vec![
            (
                Message::new(MessageBody::SpResponse(SpResponse::Ack {
                    modules: assert_reset_modules,
                    failed_modules: failed_lp_mode_modules,
                })),
                Some(serialize_vec(failed_lp_mode_err)),
            ),
            (
                Message::new(MessageBody::SpResponse(SpResponse::Ack {
                    modules: disable_power_modules,
                    failed_modules: failed_reset_modules,
                })),
                Some(serialize_vec(failed_reset_err)),
            ),
            (
                Message::new(MessageBody::SpResponse(SpResponse::Ack {
                    modules: success,
                    failed_modules: failed_disable_power_modules,
                })),
                Some(serialize_vec(failed_disable_power_err)),
            ),
        ];

        let (ded, ded_rx) = oneshot::channel();
        let sp = MockSp {
            socket,
            expected_requests,
            responses,
            ded: Some(ded),
        };
        let _sp_task = tokio::spawn(sp.run());

        let task =
            tokio::spawn(async move { controller.set_power(modules, PowerState::Off).await });
        ded_rx.await.unwrap().expect("MockSp panicked");
        let response = task.await.unwrap().unwrap();
        assert_eq!(
            response,
            AckResult {
                modules: success,
                data: vec![()],
                failures: FailedModules {
                    modules: modules.remove(&success),
                    errors: vec![
                        TransceiverError::Hardware {
                            module_index: 0,
                            source: failed_lp_mode_err[0],
                        },
                        TransceiverError::Hardware {
                            module_index: 1,
                            source: failed_reset_err[0],
                        },
                        TransceiverError::Hardware {
                            module_index: 2,
                            source: failed_disable_power_err[0],
                        },
                    ],
                }
            }
        );
    }

    // Helper type for `test_memory_model()`, including the raw data we expect
    // to read from a few modules, and the `MemoryModel`s we should parse them
    // into.
    #[derive(Debug)]
    struct MemoryModelTestData {
        sff_model: MemoryModel,
        sff_raw: Vec<Vec<u8>>,
        cmis_model: MemoryModel,
        cmis_raw: Vec<Vec<u8>>,
    }

    // Return the data used to run `test_memory_model`.
    //
    // This generates the expected `MemoryModel`s for two modules, one SFF-8636
    // and one CMIS. It encodes these into the byte arrays we expect to read
    // back from such modules' memory maps, i.e, the data we use to parse out
    // the actual model information.
    //
    // The SFF module will be advertised as flat.
    // The CMIS module will suppport the required unbanked pages (0x00, 0x01,
    // 0x02), the required banked pages (0x10, 0x11), and one additional banked
    // page (0x03).
    //
    // See `decode::MemoryModel::parse` for details.
    //
    // NOTE: This isn't intended to be a test of the `MemoryModel` type, but we
    // unfortunately have to get up in its grill to make this test realistic. It
    // might be better to add an `encode` function to the `ParseFromModule`
    // trait, which is the inverse of `parse`.
    fn memory_model_data() -> MemoryModelTestData {
        // Create the MemoryModel for the CMIS module.
        let mut cmis_pages: Vec<_> = [0x00, 0x01, 0x02]
            .into_iter()
            .map(|page| Page::from(cmis::UpperPage::new_unbanked(page).unwrap()))
            .collect();
        let max_bank = 1;
        for page in [0x10, 0x11] {
            cmis_pages.push(cmis::UpperPage::new_banked(page, max_bank).unwrap().into());
        }
        cmis_pages.push(cmis::UpperPage::new_unbanked(0x03).unwrap().into());
        cmis_pages.sort(); // Sorted when read.

        // Encode the SFF module's flat memory model into the expected raw data.
        let sff_raw = vec![
            vec![1 << 2], // Bit 2 set indicates a flat model
            vec![0],      // Not read in this case, but should have the right size.
        ];

        // Encode the CMIS raw data.
        let cmis_raw = vec![
            // Bit 7 set indicates flat, so leave it all clear.
            vec![0],
            // Other advertised pages, bit 3 means page 0x03, bits 0:1 indicate
            // the maximum bank, which is 1 for us.
            vec![1 << 2 | 0b01],
        ];

        MemoryModelTestData {
            sff_model: MemoryModel::Flat,
            sff_raw,
            cmis_model: MemoryModel::Paged(cmis_pages),
            cmis_raw,
        }
    }

    // Controller::memory_model is a good example of the methods calling
    // `parse_modules_by_identifier`. Internally, this method does a few things:
    //
    // - Read the SFF-8636 identifer for all the requested modules
    // - Split them into groups based on that ID
    // - Issue reads to each group for the requested data, since those can all
    // be read the same way.
    // - Parse out the data from each module in each group, again, since those
    // can all be parsed the same way.
    //
    // The definition of the required reads and how to parse the data come from
    // the `ParseFromModule` trait.
    //
    // We're testing this specific `Controller` method because it's simple, and
    // several methods simply delegate to the `parse_modules_by_identifier`
    // method. These all issue at least two read requests (one per kind of
    // module), and sometimes more, if the data is split up in several places of
    // the modules' memory maps.
    #[tokio::test]
    async fn test_memory_model() {
        let (controller, socket) = peer_setup().await;

        // We'll test two modules, one of each kind, to ensure we're exercising
        // the splitting and merging logic.
        let sff_reads = MemoryModel::reads(Identifier::QsfpPlusSff8636).unwrap();
        let cmis_reads = MemoryModel::reads(Identifier::QsfpPlusCmis).unwrap();
        let sff_module = ModuleId(0b01);
        let cmis_module = ModuleId(0b10);
        let modules = ModuleId(0b11);
        let failed_modules = cmis_module;
        let errors = vec![HwError::FpgaError];
        let received_errors = vec![TransceiverError::Hardware {
            module_index: cmis_module.to_indices().next().unwrap(),
            source: errors[0].clone(),
        }];

        // We expect a few different requests:
        //
        // - Read the identifier of all modules. This is used to split the
        // modules by ID.
        // - Issue the SFF-8636 read(s).
        // - Issue the CMIS read(s).
        //
        // The latter two both currently issue multiple requests (2).
        let ident_read = MemoryRead::new(sff8636::Page::Lower, 0, 1).unwrap();
        let mut expected_requests =
            vec![Message::new(MessageBody::HostRequest(HostRequest::Read {
                modules,
                read: ident_read,
            }))];
        expected_requests.extend(sff_reads.iter().map(|read| {
            Message::new(MessageBody::HostRequest(HostRequest::Read {
                modules: sff_module,
                read: *read,
            }))
        }));
        expected_requests.extend(cmis_reads.iter().map(|read| {
            Message::new(MessageBody::HostRequest(HostRequest::Read {
                modules: cmis_module,
                read: *read,
            }))
        }));

        // That's all for _one_ call to `Controller::memory_model`. We'll issue
        // _two_ so that we can test the error-handling in the second one.
        expected_requests.extend(expected_requests.clone());

        // The successful data should be the actual, parsed `MemoryModel`s. This
        // type also contains the expected raw data we've read back, which
        // should be in the responses from the MockSp.
        let test_data = memory_model_data();

        // We'll fail the CMIS module on the second call, This is the error we
        // expect. Note that we're going to fail it on the read of the memory
        // model data, not the identifier.
        let error_data = serialize_vec(&errors);

        // We need the identifiers as well, since the first read is for that, to
        // know how to read the remainder of the memory maps.
        let ident = vec![Identifier::QsfpPlusSff8636, Identifier::QsfpPlusCmis];
        let ident_read_data = ident.iter().map(|id| u8::from(*id)).collect();

        // Collect all the expected responses. There should be the same number
        // as for the requests themselves.
        let first_call_responses = vec![
            // We first expect a read for the identifiers, for both modules.
            (
                Message::new(MessageBody::SpResponse(SpResponse::Read {
                    modules,
                    failed_modules: ModuleId::empty(),
                    read: ident_read,
                })),
                Some(ident_read_data),
            ),
            // Then we expect two reads for the SFF module, since there are two
            // separate reads returned from `MemoryModel::reads()`.
            (
                Message::new(MessageBody::SpResponse(SpResponse::Read {
                    modules: sff_module,
                    failed_modules: ModuleId::empty(),
                    read: sff_reads[0],
                })),
                Some(test_data.sff_raw[0].clone()),
            ),
            (
                Message::new(MessageBody::SpResponse(SpResponse::Read {
                    modules: sff_module,
                    failed_modules: ModuleId::empty(),
                    read: sff_reads[1],
                })),
                Some(test_data.sff_raw[1].clone()),
            ),
            // Then we expect two reads for the CMIS module, since there are two
            // separate reads returned from `MemoryModel::reads()`.
            (
                Message::new(MessageBody::SpResponse(SpResponse::Read {
                    modules: cmis_module,
                    failed_modules: ModuleId::empty(),
                    read: cmis_reads[0],
                })),
                Some(test_data.cmis_raw[0].clone()),
            ),
            (
                Message::new(MessageBody::SpResponse(SpResponse::Read {
                    modules: cmis_module,
                    failed_modules: ModuleId::empty(),
                    read: cmis_reads[1],
                })),
                Some(test_data.cmis_raw[1].clone()),
            ),
        ];

        // For the second call, we'll have _almost_ the same thing as the first.
        // However, we're going to fail the very last read, the second CMIS
        // read. This is arbitrary.
        let mut second_call_responses = first_call_responses.clone();
        let new_last = (
            Message::new(MessageBody::SpResponse(SpResponse::Read {
                modules: ModuleId::empty(),
                failed_modules: cmis_module,
                read: cmis_reads[1],
            })),
            Some(error_data.clone()),
        );
        let last = second_call_responses.last_mut().unwrap();
        *last = new_last.clone();
        let responses = [first_call_responses, second_call_responses].concat();

        let (ded, mut ded_rx) = oneshot::channel();
        let sp = MockSp {
            socket,
            expected_requests,
            responses,
            ded: Some(ded),
        };
        let _sp_task = tokio::spawn(sp.run());

        // We want to _either_ panic if the SP did, or get the result from the
        // `Controller::memory_model` call.
        tokio::select! {
            e = &mut ded_rx => panic!("MockSp panicked: {e:?}"),
            response = controller.memory_model(modules) => {
                assert_eq!(
                    response.unwrap(), MemoryModelResult {
                        modules: modules,
                        data: vec![test_data.sff_model.clone(), test_data.cmis_model.clone()],
                        failures: FailedModules::success(),
                    });
            }
        }

        let response = tokio::spawn(async move { controller.memory_model(modules).await });
        let _ = ded_rx.await.unwrap().expect("MockSp panicked");
        assert_eq!(
            response.await.unwrap().unwrap(),
            MemoryModelResult {
                modules: sff_module,
                data: vec![test_data.sff_model.clone()],
                failures: FailedModules {
                    modules: failed_modules,
                    errors: received_errors,
                }
            }
        );
    }

    // Regression test for
    // https://github.com/oxidecomputer/transceiver-control/issues/79, ensuring
    // that we collect everything into the right order, even if we read out of
    // order.
    //
    // In this test, we'll just read the power_control information for 2
    // modules, but a CMIS _and then an SFF-8636_ module. That is the opposite
    // order in which we actually issue the reads, and so we can check that the
    // ordering by index is preserved, despite the reads occurring in a
    // different order.
    #[tokio::test]
    async fn test_parse_modules_by_identifier_out_of_order() {
        let (controller, socket) = peer_setup().await;

        // We'll read two modules, and here test without any failures.
        let modules = ModuleId(0b11);

        // The _lower index_ is a CMIS module, the higher an SFF-8636.
        let cmis_module = ModuleId(0b01);
        let sff_module = ModuleId(0b10);

        // The expected status for _all_ modules. The CMIS module will be
        // considered in low power mode, with software override. The SFF will be
        // in high-power, using the LPMode pin.
        let expected_status = vec![
            Status::POWER_GOOD | Status::ENABLED | Status::LOW_POWER_MODE,
            Status::POWER_GOOD | Status::ENABLED,
        ];

        // The expected power modes, i.e., the final output of the actual
        // `Controller::power` call.
        let expected_power_mode = vec![
            PowerMode {
                state: PowerState::Low,
                software_override: Some(true),
            },
            PowerMode {
                state: PowerState::High,
                software_override: Some(false),
            },
        ];

        // The reads first access the identifiers, so that the maps can be read
        // correctly.
        let expected_identifiers = vec![Identifier::QsfpPlusCmis, Identifier::QsfpPlusSff8636];

        // The method first accesses the status, then reads the memory map for
        // the last four modules. Each of those accesses a single byte in the
        // memory map, defined by the `PowerModel::reads()` method for the
        // corresponding identifier.
        //
        // We know there's just one read required to access the power control
        // data. Also note that we issue only _two_ read requests for the last 4
        // modules -- that's because `parse_modules_by_identifier()` splits the
        // modules by ID, and there are two kinds of IDs (SFF and CMIS).
        //
        // > IMPORTANT: The expected reads are actually _out of order_ compared
        // to the modules themselves. That is, the lower-indexed module is CMIS,
        // but we read from the SFF module first. That's just because we split
        // the reads by ID, and the sort order of the `Identifier` enum has
        // SFF-8636 prior to CMIS. So the expected reads are SFF first, then
        // CMIS, even though we expect the data at the end to be for CMIS first
        // then SFF, which is the order of `expected_power_mode`.
        let power_control_reads = [Identifier::QsfpPlusSff8636, Identifier::QsfpPlusCmis]
            .into_iter()
            .map(|id| PowerControl::reads(id).unwrap()[0])
            .collect::<Vec<_>>();
        let read_modules = vec![sff_module, cmis_module];

        // Create the expected host -> SP requests.
        //
        // This will first read the identifier, and then issue two additional
        // reads, one for each kind of module.
        let identifier_read = MemoryRead::new(sff8636::Page::Lower, 0, 1).unwrap();
        let mut expected_requests = vec![
            Message::new(MessageBody::HostRequest(HostRequest::Status(modules))),
            Message::new(MessageBody::HostRequest(HostRequest::Read {
                modules,
                read: identifier_read,
            })),
        ];
        expected_requests.extend(power_control_reads.iter().zip(read_modules.iter()).map(
            |(read, modules)| {
                Message::new(MessageBody::HostRequest(HostRequest::Read {
                    modules: *modules,
                    read: *read,
                }))
            },
        ));

        // The successful data for each request will consist of:
        //
        // - The status bits for all modules
        // - The identifiers for all modules
        // - The PowerControl for all modules.
        //
        // For the SFF module, that is one octet with:
        // - bit 0 clear -> use LPMode signal (hardware control)
        // - bit 1 clear -> High-power mode (Note that this would be ignored by
        // the module, but is how our software is expected to operate.
        //
        // For the CMIS modules, that is one octet with:
        // - bit 6 clear -> ignore LPMode signal (software control)
        // - bit 6 clear -> use bit 4
        // - bit 4 set -> force low-power mode.
        let status_data = serialize_vec(&expected_status);
        let identifier_data = expected_identifiers
            .iter()
            .map(|id| u8::from(*id))
            .collect::<Vec<_>>();
        let read_data = vec![
            // SFF-8636, high-power, hardware control
            vec![0b00],
            // CMIS, low-power, software control
            vec![0b0001_0000],
        ];

        // Construct the expected responses to each host request.
        //
        // - Status
        // - Identifier read on all modules
        // - PowerControl read on 2 CMIS module
        // - PowerControl read on 1 SFF-8636 module
        //
        // None of these fail.
        let responses = vec![
            (
                Message::new(MessageBody::SpResponse(SpResponse::Status {
                    modules,
                    failed_modules: ModuleId::empty(),
                })),
                Some(status_data),
            ),
            (
                Message::new(MessageBody::SpResponse(SpResponse::Read {
                    modules,
                    failed_modules: ModuleId::empty(),
                    read: identifier_read,
                })),
                Some(identifier_data),
            ),
            (
                Message::new(MessageBody::SpResponse(SpResponse::Read {
                    modules: sff_module,
                    failed_modules: ModuleId::empty(),
                    read: power_control_reads[0],
                })),
                Some(read_data[..1].concat()),
            ),
            (
                Message::new(MessageBody::SpResponse(SpResponse::Read {
                    modules: cmis_module,
                    failed_modules: ModuleId::empty(),
                    read: power_control_reads[1],
                })),
                Some(read_data[1..].concat()),
            ),
        ];

        let (ded, ded_rx) = oneshot::channel();
        let sp = MockSp {
            socket,
            expected_requests,
            responses,
            ded: Some(ded),
        };
        let _sp_task = tokio::spawn(sp.run());

        // Spawn a task to run the actual controller request.
        let task = tokio::spawn(async move { controller.power(modules).await });
        ded_rx.await.unwrap().expect("MockSp panicked");
        let response = task.await.unwrap().unwrap();
        assert_eq!(
            response,
            PowerModeResult {
                modules: modules,
                data: expected_power_mode,
                failures: FailedModules::success(),
            }
        );
    }

    #[test]
    fn test_fits_in_one_message() {
        let modules = ModuleId::single(0).unwrap();
        let read = MemoryRead::new(sff8636::Page::Lower, 0, 128).unwrap();
        assert!(fits_in_one_message(&modules, &read));
        let modules = ModuleId::all();
        assert!(!fits_in_one_message(&modules, &read));
    }

    #[test]
    fn test_split_large_reads() {
        let modules = ModuleId::single(0).unwrap();
        let read = MemoryRead::new(sff8636::Page::Lower, 0, 128).unwrap();
        let new_modules = split_large_reads(&modules, &read);
        assert_eq!(new_modules, vec![modules]);

        let one_too_many = u8::try_from(MAX_PAYLOAD_SIZE / 128 + 1).unwrap();
        let modules = ModuleId::from_index_iter(0..one_too_many).unwrap();
        let new_modules = split_large_reads(&modules, &read);
        assert_eq!(new_modules.len(), 2);
        assert_eq!(new_modules[0].merge(&new_modules[1]), modules);
        assert_eq!(new_modules[0], modules.remove(&new_modules[1]));
        assert_eq!(new_modules[1], modules.remove(&new_modules[0]));
        assert_eq!(
            modules.selected_transceiver_count(),
            new_modules
                .iter()
                .map(ModuleId::selected_transceiver_count)
                .sum::<usize>(),
        );

        let exactly_two = u8::try_from(2 * MAX_PAYLOAD_SIZE / 128).unwrap();
        let modules = ModuleId::from_index_iter(0..exactly_two).unwrap();
        let new_modules = split_large_reads(&modules, &read);
        assert_eq!(new_modules.len(), 2);
        assert_eq!(
            new_modules[0].selected_transceiver_count(),
            new_modules[1].selected_transceiver_count()
        );
        assert_eq!(new_modules[0].merge(&new_modules[1]), modules);
        assert_eq!(new_modules[0], modules.remove(&new_modules[1]));
        assert_eq!(new_modules[1], modules.remove(&new_modules[0]));
        assert_eq!(
            modules.selected_transceiver_count(),
            new_modules
                .iter()
                .map(ModuleId::selected_transceiver_count)
                .sum::<usize>(),
        );
        assert_eq!(new_modules.len(), 2);
    }
}
