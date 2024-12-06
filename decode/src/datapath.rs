// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Decode module datapath state.

use crate::utils::extract_bit;
use crate::Error;
use crate::ExtendedSpecificationComplianceCode;
use crate::HostElectricalInterfaceId;
use crate::Identifier;
use crate::MediaInterfaceId;
use crate::MediaType;
use crate::ParseFromModule;
use std::collections::BTreeMap;
use std::fmt;
use transceiver_messages::mgmt::cmis;
use transceiver_messages::mgmt::sff8636;
use transceiver_messages::mgmt::MemoryRead;

/// Information about a transceiver's datapath.
///
/// This includes state related to the low-level eletrical and optical path
/// through which bits flow. This includes flags like loss-of-signal /
/// loss-of-lock; transmitter enablement state; and equalization parameters.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)
)]
#[cfg_attr(any(feature = "api-traits", test), serde(rename_all = "snake_case"))]
pub enum Datapath {
    /// A number of datapaths in a CMIS module.
    ///
    /// CMIS modules may have a large number of supported configurations of
    /// their various lanes, each called an "application". These are described
    /// by the `ApplicationDescriptor` type, which mirrors CMIS 5.0 table 8-18.
    /// Each descriptor is identified by an "Application Selector Code", which
    /// is just its index in the section of the memory map describing them.
    ///
    /// Each lane can be used in zero or more applications, however, it may
    /// exist in at most one application at a time. These active applications,
    /// of which there may be more than one, are keyed by their codes in the
    /// contained mapping.
    Cmis {
        /// The type of free-side connector
        connector: ConnectorType,
        /// A bit mask with a 1 in bit `i` if the `i`th lane is supported.
        supported_lanes: u8,
        /// Mapping from "application selector" ID to its datapath information.
        ///
        /// The datapath inclues the lanes used; host electrical interface;
        /// media interface; and a lot more about the state of the path.
        datapaths: BTreeMap<u8, CmisDatapath>,
    },
    /// Datapath state about each lane in an SFF-8636 module.
    Sff8636 {
        connector: ConnectorType,
        specification: SffComplianceCode,
        lanes: [Sff8636Datapath; 4],
    },
}

/// The type of a media-side connector.
///
/// These values come from SFF-8024 Rev 4.10 Table 4-3
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)
)]
#[cfg_attr(any(feature = "api-traits", test), serde(rename_all = "snake_case"))]
pub enum ConnectorType {
    Unknown,
    SubscriberConnector,
    LucentConnector,
    Mpo1x12,
    Mpo2x16,
    Rj45,
    Mpo2x12,
    Mpo1x16,
    Other(u8),
    Reserved(u8),
    VendorSpecific(u8),
}

impl From<u8> for ConnectorType {
    fn from(value: u8) -> Self {
        use ConnectorType::*;
        match value {
            0x00 => Unknown,
            0x01 => SubscriberConnector,
            0x07 => LucentConnector,
            0x0c => Mpo1x12,
            0x0d => Mpo2x16,
            0x22 => Rj45,
            0x27 => Mpo2x12,
            0x28 => Mpo1x16,
            0x0e..=0x1f | 0x29..=0x7f => Reserved(value),
            0x80..=0xff => VendorSpecific(value),
            x => Other(x),
        }
    }
}

impl fmt::Display for ConnectorType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ConnectorType::Unknown => write!(f, "Unknown"),
            ConnectorType::SubscriberConnector => write!(f, "Subscriber Connector"),
            ConnectorType::LucentConnector => write!(f, "Lucent Connector (LC)"),
            ConnectorType::Mpo1x12 => write!(f, "MPO 1x12"),
            ConnectorType::Mpo2x16 => write!(f, "MPO 2x16"),
            ConnectorType::Rj45 => write!(f, "RJ-45"),
            ConnectorType::Mpo2x12 => write!(f, "MPO-2x12"),
            ConnectorType::Mpo1x16 => write!(f, "MPO-1x16"),
            ConnectorType::Other(x) => write!(f, "Other ({x:02x})"),
            ConnectorType::Reserved(x) => write!(f, "Reserved ({x:02x})"),
            ConnectorType::VendorSpecific(x) => write!(f, "Vendor-specific ({x:02x})"),
        }
    }
}

/// The compliance code for an SFF-8636 module.
///
/// These values record a specification compliance code, from SFF-8636 Table
/// 6-17, or an extended specification compliance code, from SFF-8024 Table 4-4.
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)
)]
#[cfg_attr(any(feature = "api-traits", test), serde(rename_all = "snake_case"))]
pub enum SffComplianceCode {
    Extended(ExtendedSpecificationComplianceCode),
    Ethernet(u8),
}

impl fmt::Display for SffComplianceCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Extended(ext) => write!(f, "{}", ext),
            Self::Ethernet(x) => match x {
                0b0000_0001 => write!(f, "40G Active Cable"),
                0b0000_0010 => write!(f, "40GBASE-LR4"),
                0b0000_0100 => write!(f, "40GBASE-SR4"),
                0b0000_1000 => write!(f, "40GBASE-CR4"),
                0b0001_0000 => write!(f, "10GBASE-SR"),
                0b0010_0000 => write!(f, "10GBASE-LR"),
                0b0100_0000 => write!(f, "10GBASE-LRM"),
                _ => unreachable!(),
            },
        }
    }
}

impl SffComplianceCode {
    /// Decode specification compliance, from the core specification and
    /// possibly the extended specification compliance byte.
    pub fn new(specification: u8, extended_specification: u8) -> Self {
        if specification == 0x80 {
            Self::Extended(ExtendedSpecificationComplianceCode::from(
                extended_specification,
            ))
        } else {
            Self::Ethernet(specification)
        }
    }
}

impl ParseFromModule for Datapath {
    fn reads(id: Identifier) -> Result<Vec<MemoryRead>, Error> {
        match id {
            Identifier::QsfpPlusSff8636 | Identifier::Qsfp28 => {
                let tx_enable = MemoryRead::new(sff8636::Page::Lower, 86, 1)?;
                let los = MemoryRead::new(sff8636::Page::Lower, 3, 3)?;
                let cdr = MemoryRead::new(sff8636::Page::Lower, 98, 1)?;
                let compliance =
                    MemoryRead::new(sff8636::Page::Upper(sff8636::UpperPage::new(0)?), 130, 2)?;
                let extended_compliance =
                    MemoryRead::new(sff8636::Page::Upper(sff8636::UpperPage::new(0)?), 192, 1)?;
                Ok(vec![tx_enable, los, cdr, compliance, extended_compliance])
            }
            Identifier::QsfpPlusCmis | Identifier::QsfpDD => {
                // As with most module data, CMIS is _far_ more complicated than
                // SFF-8636. Lanes can be assigned to different datapaths,
                // though only one at a time, and modules can have a large
                // number of different datapaths. Each is described by an
                // `ApplicationDescriptor`, which defines the host / media
                // interfaces; lane assignments; and number of lanes.
                //
                // We'll start by reading the connector type, which is the same
                // for all lanes, and the list of supported lanes. These fit in
                // one read.
                let connector_type = MemoryRead::new(
                    cmis::Page::Upper(cmis::UpperPage::new_unbanked(0x00)?),
                    203,
                    7,
                )?;

                // Read the configuration for each lane. Table 8-83.
                //
                // For each lane, this gives indices for the datapath that uses
                // that lane, if any. The bits of each byte are intepreted as:
                //
                // The upper 4 bits give the the index of the Application that
                // this lane is part of. E.g., if this is `0b0001`, then this is
                // part of the application with index 1. If this is all zero,
                // the lane is unused.
                //
                // The next 3 bits give the index of the first lane in the
                // datapath that contains this lane.
                //
                // The last bit is 1 if the SI settings for the lane can be
                // controlled by the host, or 0 if the application defines them
                // entirely.
                //
                // The lane is "active" if the index is _not_ all zeros, i.e.,
                // this lane is in use in _some_ application.
                let lane_config = MemoryRead::new(
                    cmis::Page::Upper(cmis::UpperPage::new_banked(0x11, 0)?),
                    206,
                    8,
                )?;

                // Read the media type. CMIS Table 8-17.
                let media_type = MemoryRead::new(cmis::Page::Lower, 85, 1)?;

                // Read the assignments of media lanes to applications. Table
                // 8-51.
                //
                // Note that we _first_ read the media assignments, which are
                // bit-masks that are a 1 when the corresponding lane is used in
                // the application. We read these first because they're required
                // to understand how to decode the application descriptors,
                // which we read next.
                let media_assignments = MemoryRead::new(
                    cmis::Page::Upper(cmis::UpperPage::new_unbanked(0x01)?),
                    176,
                    8,
                )?;

                // Read the application descriptors. Table 8-19.
                //
                // An application descriptor describes everything about an
                // "application", which is the set of lanes and their metadata
                // that goes into a single datapath. These values include:
                //
                // - Host interface ID
                // - Media interface ID
                // - Host lane count
                // - Media lane count
                // - Host lane assignment options
                //
                // There is always at least one application descriptor, and the
                // end of the list is indicated by a Host interface ID of 0xFF.
                let descriptors = (86..118)
                    .step_by(8)
                    .map(|start| MemoryRead::new(cmis::Page::Lower, start, 8))
                    .collect::<Result<Vec<_>, _>>()?;

                // Read the support for various lane-specific controls. Table
                // 8-44.
                let control_support = MemoryRead::new(
                    cmis::Page::Upper(cmis::UpperPage::new_unbanked(0x01)?),
                    155,
                    4,
                )?;

                // Next, read the lane-specific control bits, indicating how the
                // host can manipulate each lane, such as disabling the
                // transmitter.
                //
                // Table 8-61.
                let controls0 = MemoryRead::new(
                    cmis::Page::Upper(cmis::UpperPage::new_banked(0x10, 0)?),
                    129,
                    4,
                )?;
                let controls1 = MemoryRead::new(
                    cmis::Page::Upper(cmis::UpperPage::new_banked(0x10, 0)?),
                    134,
                    6,
                )?;

                // Read datapath state for each datapath. Table 8-73.
                let datapath_state = MemoryRead::new(
                    cmis::Page::Upper(cmis::UpperPage::new_banked(0x11, 0)?),
                    128,
                    4,
                )?;

                // Read the lane-specific output status bits. Table 8-75.
                let lane_status = MemoryRead::new(
                    cmis::Page::Upper(cmis::UpperPage::new_banked(0x11, 0)?),
                    132,
                    2,
                )?;

                // And finally the lane-specific flags. Table 8-77.
                let tx_lane_flags = MemoryRead::new(
                    cmis::Page::Upper(cmis::UpperPage::new_banked(0x11, 0)?),
                    135,
                    4,
                )?;
                // Table 8-78.
                let rx_lane_flags = MemoryRead::new(
                    cmis::Page::Upper(cmis::UpperPage::new_banked(0x11, 0)?),
                    147,
                    2,
                )?;

                let mut reads = Vec::with_capacity(15);
                reads.push(connector_type);
                reads.push(lane_config);
                reads.push(media_type);
                reads.push(media_assignments);
                reads.extend(descriptors);
                reads.push(control_support);
                reads.push(controls0);
                reads.push(controls1);
                reads.push(datapath_state);
                reads.push(lane_status);
                reads.push(tx_lane_flags);
                reads.push(rx_lane_flags);
                Ok(reads)
            }
            _ => Err(Error::UnsupportedIdentifier(id)),
        }
    }

    fn parse<'a>(id: Identifier, mut reads: impl Iterator<Item = &'a [u8]>) -> Result<Self, Error> {
        match id {
            Identifier::QsfpPlusSff8636 | Identifier::Qsfp28 => {
                let tx_enable = reads.next().unwrap();
                assert_eq!(tx_enable.len(), 1);
                let los = reads.next().unwrap();
                assert_eq!(los.len(), 3);
                let cdr = reads.next().unwrap();
                assert_eq!(cdr.len(), 1);
                let compliance = reads.next().unwrap();
                assert_eq!(compliance.len(), 2);
                let extended_compliance = reads.next().unwrap();
                assert_eq!(extended_compliance.len(), 1);

                // Extract connector type.
                let connector = ConnectorType::from(compliance[0]);

                // Extract specification compliance code.
                let specification = SffComplianceCode::new(compliance[1], extended_compliance[0]);

                // Extract data for all four lanes.
                //
                // It's not currently obvious how to extract the _real_ number
                // of lanes. In contrast to CMIS, this isn't explicitly
                // described by the memory map. We could extract it from the
                // host-electrical ID, but that doesn't constrain it enough,
                // since some IDs support multiple lane configurations.
                let lanes = (0..4)
                    .map(|lane| {
                        // Byte 86 bits 0..3 are Tx _disabled_.
                        let tx_enabled = !extract_bit(tx_enable[0], lane)?;

                        // The LOS / LOL bits are not inverted: 1 means there is
                        // such as state. Some of these are shifted by 4, since the
                        // lower 4 bits are for the Rx side of things.
                        let tx_lane = lane + 4;
                        let tx_los = extract_bit(los[0], tx_lane)?;
                        let tx_adaptive_eq_fault = extract_bit(los[1], tx_lane)?;
                        let tx_fault = extract_bit(los[1], lane)?;
                        let tx_lol = extract_bit(los[2], tx_lane)?;

                        // Rx side state is in the lower 4 bits.
                        let rx_los = extract_bit(los[0], lane)?;
                        let rx_lol = extract_bit(los[2], lane)?;

                        // Extract CDR bits.
                        let tx_cdr_enabled = extract_bit(cdr[0], tx_lane)?;
                        let rx_cdr_enabled = extract_bit(cdr[0], lane)?;

                        Ok(Sff8636Datapath {
                            tx_enabled,
                            tx_los,
                            rx_los,
                            tx_adaptive_eq_fault,
                            tx_fault,
                            tx_lol,
                            rx_lol,
                            tx_cdr_enabled,
                            rx_cdr_enabled,
                        })
                    })
                    .collect::<Result<Vec<_>, Error>>()?
                    .try_into()
                    .unwrap();
                Ok(Datapath::Sff8636 {
                    connector,
                    specification,
                    lanes,
                })
            }
            Identifier::QsfpPlusCmis | Identifier::QsfpDD => {
                // First, read the connector type and which lanes are
                // _unsupported_.
                let connector_type = reads.next().expect("No connector type read");
                assert_eq!(connector_type.len(), 7);
                let connector = ConnectorType::from(connector_type[0]);

                // See CMIS 5.0 Table 8-31.
                //
                // Each bit is 1 when the lane is _unsupported_. We invert that
                // to be sane.
                let supported_lanes = !connector_type[6];

                // We next read the lane configuration, which tells us which
                // application (if any) each lane is assigned to. These are the
                // lanes _in use_, and the set of all applications in use is the
                // union of those any lane is assigned to.
                let lane_config = reads.next().expect("No datapath lane configuration read");
                assert_eq!(lane_config.len(), 8);
                let lane_configs: Vec<_> =
                    lane_config.iter().map(LaneDatapathConfig::from).collect();

                // Decode media type.
                let media_type = MediaType::from(reads.next().expect("No media type read")[0]);

                // Extract the media assignment options.
                let media_assignments =
                    reads.next().expect("Missing media assignment options read");

                // Parse out the applications themselves.
                //
                // These are the _supported_ applications. The active ones are
                // defined by the application selectors that the lanes are
                // assigned to, in each entry of `lane_configs` above.
                //
                // Pull out all 8 descriptors. These are 4 bytes each, which
                // we've packed into 4 reads of 2 descriptors.
                let mut supported_applications = Vec::with_capacity(8);
                let mut descriptors = Vec::with_capacity(8);
                for read in 0..4 {
                    let descriptor = reads
                        .next()
                        .unwrap_or_else(|| panic!("Missing application descriptor read {read}"));
                    descriptors.extend(descriptor.chunks_exact(4));
                }
                for (i, descriptor) in descriptors.into_iter().enumerate() {
                    // Fetch the assignment of each lane for this application
                    // ID.
                    let assignment = media_assignments[i];
                    let app = ApplicationDescriptor::from_bytes(
                        media_type,
                        descriptor.try_into().unwrap(),
                        assignment,
                    )
                    .unwrap();

                    // If this is the end of list, break out, otherwise push
                    // this descriptor and continue.
                    if app.host_id == HostElectricalInterfaceId::EndOfList {
                        break;
                    }
                    supported_applications.push(app);
                }

                // Pull out the set of _active_ applications, using the lane
                // configurations.
                //
                // We're creating a mapping from the application selector ID
                // (AppSel), to a tuple of (application descriptor, array of
                // lanes). This is so that later, we can pull out the status
                // bits of each lane and assign it to the right datapath.
                let mut active_applications: BTreeMap<u8, (ApplicationDescriptor, Vec<u8>)> =
                    BTreeMap::new();
                for (lane, lane_config) in lane_configs.into_iter().enumerate() {
                    if lane_config.is_assigned() {
                        let app_sel = lane_config.app_select_code;
                        let app = supported_applications
                            .get(usize::from(app_sel - 1))
                            .expect("Up to 8 applications are currently supported");
                        active_applications
                            .entry(app_sel)
                            .or_insert_with(|| (*app, vec![]))
                            .1
                            .push(lane.try_into().unwrap());
                    }
                }

                fn supported_bit_is_set(
                    support: u8,
                    bit: u8,
                    control: u8,
                    lane: u8,
                ) -> Option<bool> {
                    if let Ok(true) = extract_bit(support, bit) {
                        extract_bit(control, lane).ok()
                    } else {
                        None
                    }
                }

                // For each active application, let's access the status bits of
                // the lanes that it's composed of.
                let support = reads.next().expect("Missing control support read");
                let controls0 = reads.next().expect("Missing controls0 read");
                let controls1 = reads.next().expect("Missing controls1 read");
                let datapath_state = reads.next().expect("Missing datapath state read");
                let lane_status = reads.next().expect("Missing lane-specific status read");
                let tx_lane_flags = reads.next().expect("Missing Tx lane flags read");
                let rx_lane_flags = reads.next().expect("Missing Rx lane flags read");
                let mut datapaths = BTreeMap::new();
                for (app_sel, (app, lanes)) in active_applications.into_iter() {
                    for lane in lanes.into_iter() {
                        // Most of these controls and flags are advertised in a
                        // support word. Extract the bit itself as a boolean, if
                        // it is supported, or None if not.
                        //
                        // See CMIS 5.0 section 8.4.7 for the bit definitions of
                        // the support bits. See table 8-61 for the control
                        // bits.
                        let tx_input_polarity =
                            supported_bit_is_set(support[0], 0, controls0[0], lane).map(|x| {
                                if x {
                                    Polarity::Flipped
                                } else {
                                    Polarity::Normal
                                }
                            });
                        let tx_output_enabled =
                            supported_bit_is_set(support[0], 1, controls0[1], lane).map(|x| !x);
                        let tx_auto_squelch_disable =
                            supported_bit_is_set(support[0], 2, controls0[2], lane);
                        let tx_force_squelch =
                            supported_bit_is_set(support[0], 3, controls0[3], lane);
                        let rx_output_polarity =
                            supported_bit_is_set(support[1], 0, controls1[3], lane).map(|x| {
                                if x {
                                    Polarity::Flipped
                                } else {
                                    Polarity::Normal
                                }
                            });
                        let rx_output_enabled =
                            supported_bit_is_set(support[1], 1, controls1[4], lane).map(|x| !x);
                        let rx_auto_squelch_disable =
                            supported_bit_is_set(support[1], 2, controls1[5], lane);

                        // The output status bits are required by the spec.
                        let rx_output_status = if lane_status[0] & (1 << lane) != 0 {
                            OutputStatus::Valid
                        } else {
                            OutputStatus::Invalid
                        };
                        let tx_output_status = if lane_status[1] & (1 << lane) != 0 {
                            OutputStatus::Valid
                        } else {
                            OutputStatus::Invalid
                        };

                        let tx_failure =
                            supported_bit_is_set(support[2], 0, tx_lane_flags[0], lane);
                        let tx_los = supported_bit_is_set(support[2], 1, tx_lane_flags[1], lane);
                        let tx_lol = supported_bit_is_set(support[2], 2, tx_lane_flags[2], lane);
                        let tx_adaptive_eq_fail =
                            supported_bit_is_set(support[2], 3, tx_lane_flags[3], lane);
                        let rx_los = supported_bit_is_set(support[3], 1, rx_lane_flags[0], lane);

                        // The datapath state is stored in a nibble within the
                        // bytes read in `datapath_state`. The lower-order
                        // nibble (bits 0-3) are the first of these two lanes,
                        // the higher-order nibble (bits 4-7) are the second /
                        // larger of the two lanes.
                        //
                        // See CMIS table 8-73 for details.
                        let index = usize::from(lane / 2);
                        let shift = if lane % 2 == 1 { 0 } else { 4 };
                        let nibble = (datapath_state[index] & (0x0f << shift)) >> shift;
                        let state = CmisDatapathState::try_from(nibble)?;
                        let rx_lol = supported_bit_is_set(support[3], 2, rx_lane_flags[1], lane);

                        let st = LaneStatus {
                            state,
                            tx_input_polarity,
                            tx_output_enabled,
                            tx_auto_squelch_disable,
                            tx_force_squelch,
                            rx_output_polarity,
                            rx_output_enabled,
                            rx_auto_squelch_disable,
                            rx_output_status,
                            tx_output_status,
                            tx_failure,
                            tx_los,
                            tx_lol,
                            tx_adaptive_eq_fail,
                            rx_los,
                            rx_lol,
                        };

                        // Add this lane, either to a new application keyed by
                        // its AppSel code, or an existing.
                        datapaths
                            .entry(app_sel)
                            .or_insert_with(|| CmisDatapath {
                                application: app,
                                lane_status: BTreeMap::new(),
                            })
                            .lane_status
                            .insert(1 + lane, st);
                    }
                }
                Ok(Datapath::Cmis {
                    datapaths,
                    connector,
                    supported_lanes,
                })
            }
            _ => Err(Error::UnsupportedIdentifier(id)),
        }
    }
}

/// The datapath of an SFF-8636 module.
///
/// This describes the state of a single lane in an SFF module. It includes
/// information about input and output signals, faults, and controls.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)
)]
pub struct Sff8636Datapath {
    /// Software control of output transmitter.
    pub tx_enabled: bool,

    /// Host-side loss of signal flag.
    ///
    /// This is true if there is no detected electrical signal from the
    /// host-side serdes.
    pub tx_los: bool,

    /// Media-side loss of signal flag.
    ///
    /// This is true if there is no detected input signal from the media-side
    /// (usually optical).
    pub rx_los: bool,

    /// Flag indicating a fault in adaptive transmit equalization.
    pub tx_adaptive_eq_fault: bool,

    /// Flag indicating a fault in the transmitter and/or laser.
    pub tx_fault: bool,

    /// Host-side loss of lock flag.
    ///
    /// This is true if the module is not able to extract a clock signal from
    /// the host-side electrical signal.
    pub tx_lol: bool,

    /// Media-side loss of lock flag.
    ///
    /// This is true if the module is not able to extract a clock signal from
    /// the media-side signal (usually optical).
    pub rx_lol: bool,

    /// Host-side transmit Clock and Data Recovery (CDR) enable status.
    ///
    /// CDR is the process by which the module enages an internal retimer
    /// function, through which the module attempts to recovery a clock signal
    /// directly from the input bitstream.
    pub tx_cdr_enabled: bool,

    /// Media-side transmit Clock and Data Recovery (CDR) enable status.
    ///
    /// CDR is the process by which the module enages an internal retimer
    /// function, through which the module attempts to recovery a clock signal
    /// directly from the input bitstream.
    pub rx_cdr_enabled: bool,
}

/// A datapath in a CMIS module.
///
/// In contrast to SFF-8636, CMIS makes first-class the concept of a datpath: a
/// set of lanes and all the associated machinery involved in the transfer of
/// data. This includes:
///
/// - The "application descriptor" which is the host and media interfaces, and
///   the lanes on each side used to transfer data;
/// - The state of the datapath in a well-defined finite state machine (see CMIS
///   5.0 section 6.3.3);
/// - The flags indicating how the datapath components are operating, such as
///   receiving an input Rx signal or whether the transmitter is disabled.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)
)]
pub struct CmisDatapath {
    /// The application descriptor for this datapath.
    pub application: ApplicationDescriptor,

    /// The status bits for each lane in the datapath.
    pub lane_status: BTreeMap<u8, LaneStatus>,
}

/// The status of a single CMIS lane.
///
/// If any particular control or status value is unsupported by a module, it is
/// `None`.
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)
)]
pub struct LaneStatus {
    /// The datapath state of this lane.
    ///
    /// See CMIS 5.0 section 8.9.1 for details.
    pub state: CmisDatapathState,

    /// The Tx input polarity.
    ///
    /// This indicates a host-side control that flips the polarity of the
    /// host-side input signal.
    pub tx_input_polarity: Option<Polarity>,

    /// Whether the Tx output is enabled.
    pub tx_output_enabled: Option<bool>,

    /// Whether the host-side has disabled the Tx auto-squelch.
    ///
    /// The module can implement automatic squelching of the Tx output, if the
    /// host-side input signal isn't valid. This indicates whether the host has
    /// disabled such a setting.
    pub tx_auto_squelch_disable: Option<bool>,

    /// Whether the host-side has force-squelched the Tx output.
    ///
    /// This indicates that the host can _force_ squelching the output if the
    /// signal is not valid.
    pub tx_force_squelch: Option<bool>,

    /// The Rx output polarity.
    ///
    /// This indicates a host-side control that flips the polarity of the
    /// host-side output signal.
    pub rx_output_polarity: Option<Polarity>,

    /// Whether the Rx output is enabled.
    ///
    /// The host may control this to disable the electrical output from the
    /// module to the host.
    pub rx_output_enabled: Option<bool>,

    /// Whether the host-side has disabled the Rx auto-squelch.
    ///
    /// The module can implement automatic squelching of the Rx output, if the
    /// media-side input signal isn't valid. This indicates whether the host has
    /// disabled such a setting.
    pub rx_auto_squelch_disable: Option<bool>,

    /// Status of host-side Rx output.
    ///
    /// This indicates whether the Rx output is sending a valid signal to the
    /// host. Note that this is `Invalid` if the output is either muted (such as
    /// squelched) or explicitly disabled.
    pub rx_output_status: OutputStatus,

    /// Status of media-side Tx output.
    ///
    /// This indicates whether the Rx output is sending a valid signal to the
    /// media itself. Note that this is `Invalid` if the output is either muted
    /// (such as squelched) or explicitly disabled.
    pub tx_output_status: OutputStatus,

    /// General Tx failure flag.
    ///
    /// This indicates that an internal and unspecified malfunction has occurred
    /// on the Tx lane.
    pub tx_failure: Option<bool>,

    /// Host-side loss of signal flag.
    ///
    /// This is true if there is no detected electrical signal from the
    /// host-side serdes.
    pub tx_los: Option<bool>,

    /// Host-side loss of lock flag.
    ///
    /// This is true if the module is not able to extract a clock signal from
    /// the host-side electrical signal.
    pub tx_lol: Option<bool>,

    /// A failure in the Tx adaptive input equalization.
    pub tx_adaptive_eq_fail: Option<bool>,

    /// Media-side loss of signal flag.
    ///
    /// This is true if there is no detected input signal from the media-side
    /// (usually optical).
    pub rx_los: Option<bool>,

    /// Media-side loss of lock flag.
    ///
    /// This is true if the module is not able to extract a clock signal from
    /// the media-side signal (usually optical).
    pub rx_lol: Option<bool>,
}

crate::bitfield_enum! {
    name = CmisDatapathState,
    description = "The state of a datapath in the CMIS datapath state machine.",
    bits = 2:0,
    variants = {
        0x1, Deactivated, "Deactivated",
        0x2, Init, "Initializing",
        0x3, Deinit, "Deinitializing",
        0x4, Activated, "Activated",
        0x5, TxTurnOn, "Tx turning on",
        0x6, TxTurnOff, "Tx turning off",
        0x7, Initialized, "Initialized",
    },
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)
)]
#[cfg_attr(any(feature = "api-traits", test), serde(rename_all = "snake_case"))]
pub enum OutputStatus {
    Valid,
    Invalid,
}

impl fmt::Display for OutputStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutputStatus::Valid => write!(f, "Valid"),
            OutputStatus::Invalid => write!(f, "Invalid"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)
)]
#[cfg_attr(any(feature = "api-traits", test), serde(rename_all = "snake_case"))]
pub enum Polarity {
    Normal,
    Flipped,
}

impl fmt::Display for Polarity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Polarity::Normal => write!(f, "Normal"),
            Polarity::Flipped => write!(f, "Flipped"),
        }
    }
}

/// An Application Descriptor describes the supported datapath configurations.
///
/// This is a CMIS-specific concept. It's used for modules to advertise how it
/// can be used by the host. Each application describes the host-side electrical
/// interface; the media-side interface; the number of lanes required; etc.
///
/// Host-side software can select one of these applications to instruct the
/// module to use a specific set of lanes, with the interface on either side of
/// the module.
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)
)]
pub struct ApplicationDescriptor {
    /// The electrical interface with the host side.
    pub host_id: HostElectricalInterfaceId,
    /// The interface, optical or copper, with the media side.
    pub media_id: MediaInterfaceId,
    /// The number of host-side lanes.
    pub host_lane_count: u8,
    /// The number of media-side lanes.
    pub media_lane_count: u8,
    /// The lanes on the host-side supporting this application.
    ///
    /// This is a bit mask with a 1 identifying the lowest lane in a consecutive
    /// group of lanes to which the application can be assigned. This must be
    /// used with the `host_lane_count`. For example a value of `0b0000_0001`
    /// with a host lane count of 4 indicates that the first 4 lanes may be used
    /// in this application.
    ///
    /// An application may support starting from multiple lanes.
    pub host_lane_assignment_options: u8,

    /// The lanes on the media-side supporting this application.
    ///
    /// See `host_lane_assignment_options` for details.
    pub media_lane_assignment_options: u8,
}

impl ApplicationDescriptor {
    fn from_bytes(
        media_type: MediaType,
        bytes: [u8; 4],
        media_lane_assignment_options: u8,
    ) -> Option<Self> {
        let host_id = HostElectricalInterfaceId::from(bytes[0]);
        let media_id = MediaInterfaceId::from_u8(media_type, bytes[1])?;
        let host_lane_count = (bytes[2] & 0xf0) >> 4;
        let media_lane_count = bytes[2] & 0x0f;
        let host_lane_assignment_options = bytes[3];
        Some(Self {
            host_id,
            media_id,
            host_lane_count,
            media_lane_count,
            host_lane_assignment_options,
            media_lane_assignment_options,
        })
    }
}

/// Describes the application to which a specific lane is assigned.
///
/// This identifies which `ApplicationDescriptor`, if any, a lane belongs to,
/// which describes the entire configuration of a datapath.
///
/// See CMIS 5.0 Table 8-82.
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)
)]
pub struct LaneDatapathConfig {
    /// The code (index) of the active Application Descriptor.
    pub app_select_code: u8,
    /// The index of the first lane in the data path containing this lane.
    pub data_path_id: u8,
    /// If true, the SI settings for this lane are controlled by the host.
    ///
    /// Otherwise, the module controls settings autonomously based on the
    /// application.
    pub explicit_control: bool,
}

impl LaneDatapathConfig {
    /// Return `true` if this is lane is assigned to a datapath.
    pub const fn is_assigned(&self) -> bool {
        self.app_select_code != 0
    }
}

impl From<u8> for LaneDatapathConfig {
    fn from(x: u8) -> Self {
        Self {
            app_select_code: (x & 0xf0) >> 4,
            data_path_id: (x & 0b1110) >> 1,
            explicit_control: (x & 0b1) != 0,
        }
    }
}

impl From<&u8> for LaneDatapathConfig {
    fn from(x: &u8) -> Self {
        Self::from(*x)
    }
}

#[cfg(test)]
mod tests {
    use super::ApplicationDescriptor;
    use super::Datapath;
    use super::HostElectricalInterfaceId;
    use super::Identifier;
    use super::MediaInterfaceId;
    use super::MediaType;
    use super::ParseFromModule;
    use super::Sff8636Datapath;
    use crate::ident::SmfMediaInterfaceId;
    use crate::ConnectorType;
    use crate::ExtendedSpecificationComplianceCode;
    use crate::LaneDatapathConfig;
    use crate::SffComplianceCode;

    #[test]
    fn test_decode_cmis_lane_datapath_config() {
        // Lane is part of application descriptor with AppSel code 0b0110 == 6
        // The first lane in the datapath containing this lane is 0b010 == 2
        // This lane is explicitly host-controllable.
        const BYTE: u8 = 0b0110 << 4 | 0b010 << 1 | 0b1;
        let decoded = LaneDatapathConfig::from(BYTE);
        assert_eq!(decoded.app_select_code, 6);
        assert_eq!(decoded.data_path_id, 2);
        assert!(decoded.explicit_control);
    }

    #[test]
    fn test_application_descriptor_from_bytes() {
        let media_type = MediaType::SingleModeFiber;
        let host_id = HostElectricalInterfaceId::IdCaui4;
        let media_id = MediaInterfaceId::Smf(SmfMediaInterfaceId::Id100GBaseLr4);
        let n_lanes = 4;
        let media_lane_assignment_options = 0b1;
        let expected = ApplicationDescriptor {
            host_id,
            media_id,
            host_lane_count: n_lanes,
            media_lane_count: n_lanes,
            host_lane_assignment_options: 0b1,
            media_lane_assignment_options,
        };
        let bytes = [0x0b, 0x0d, (n_lanes << 4) | n_lanes, 0b1];
        let app =
            ApplicationDescriptor::from_bytes(media_type, bytes, media_lane_assignment_options)
                .unwrap();
        assert_eq!(app, expected);
    }

    #[test]
    fn test_parse_sff8636_datapath() {
        let expected = Datapath::Sff8636 {
            connector: ConnectorType::LucentConnector,
            lanes: [Sff8636Datapath {
                tx_enabled: true,
                tx_los: false,
                rx_los: false,
                tx_adaptive_eq_fault: false,
                tx_fault: false,
                tx_lol: true,
                rx_lol: true,
                tx_cdr_enabled: true,
                rx_cdr_enabled: true,
            }; 4],
            specification: SffComplianceCode::Extended(
                ExtendedSpecificationComplianceCode::Id100GBCwdm4,
            ),
        };
        let bytes = [
            // Tx-enable: all 4 lanes enabled
            vec![0b0000],
            // LOS: No LOS, no faults, yes LOL
            vec![0b0000_0000, 0b0000_0000, 0b1111_1111],
            // CDR: All channels have CDR on
            vec![0b1111_1111],
            // Connector type: LC
            // Compliance: Extended
            vec![0x07, 0x80],
            // Extended compliance: 100G CWDM4
            vec![0x06],
        ];
        let parsed = Datapath::parse(
            Identifier::QsfpPlusSff8636,
            bytes.iter().map(|s| s.as_slice()),
        )
        .unwrap();
        assert_eq!(parsed, expected);
    }
}
