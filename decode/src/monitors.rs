// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Decode transceiver health and monitoring data.

use crate::utils::decode_with_scale;
use crate::Error;
use crate::Identifier;
use crate::ParseFromModule;
use transceiver_messages::mgmt::cmis;
use transceiver_messages::mgmt::sff8636;
use transceiver_messages::mgmt::MemoryRead;

/// Free-side device monitoring information.
///
/// Note that all values are optional, as some specifications do not require
/// that modules implement monitoring of those values.
#[derive(Clone, Debug, Default)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)
)]
pub struct Monitors {
    /// The measured cage temperature (degrees C);
    #[cfg_attr(
        any(feature = "api-traits", test),
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub temperature: Option<f32>,

    /// The measured input supply voltage (Volts).
    #[cfg_attr(
        any(feature = "api-traits", test),
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub supply_voltage: Option<f32>,

    /// The measured input optical power (milliwatts);
    ///
    /// Note that due to a limitation in the SFF-8636 specification, it's
    /// possible for receiver power to be zero. See [`ReceiverPower`] for
    /// details.
    #[cfg_attr(
        any(feature = "api-traits", test),
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub receiver_power: Option<Vec<ReceiverPower>>,

    /// The output laser bias current (milliamps).
    #[cfg_attr(
        any(feature = "api-traits", test),
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub transmitter_bias_current: Option<Vec<f32>>,

    /// The measured output optical power (milliwatts).
    #[cfg_attr(
        any(feature = "api-traits", test),
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub transmitter_power: Option<Vec<f32>>,

    /// Auxiliary monitoring values.
    ///
    /// These are only available on CMIS-compatible transceivers, e.g., QSFP-DD.
    #[cfg_attr(
        any(feature = "api-traits", test),
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub aux_monitors: Option<AuxMonitors>,
}

/// Measured receiver optical power.
///
/// The SFF specifications allow for devices to monitor input optical power in
/// several ways. It may either be an average power, over some unspecified time,
/// or a peak-to-peak power. The latter is often abbreviated OMA, for Optical
/// Modulation Amplitude. Again the time interval for peak-to-peak measurments
/// are not specified.
///
/// Details
/// -------
///
/// The SFF-8636 specification has an unfortunate limitation. There is no
/// separate advertisement for whether a module supports measurements of
/// receiver power. Instead, the _kind_ of measurement is advertised. The _same
/// bit value_ could mean that either a peak-to-peak measurement is supported,
/// or the measurements are not supported at all. Thus values of
/// `PeakToPeak(0.0)` may mean that power measurements are not supported.
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)
)]
#[cfg_attr(any(feature = "api-traits", test), serde(rename_all = "snake_case"))]
pub enum ReceiverPower {
    /// The measurement is represents average optical power, in mW.
    Average(f32),

    /// The measurement represents a peak-to-peak, in mW.
    PeakToPeak(f32),
}

impl ReceiverPower {
    /// Return the actual value of the receiver power measurement.
    pub fn value(&self) -> f32 {
        match self {
            ReceiverPower::Average(x) => *x,
            ReceiverPower::PeakToPeak(x) => *x,
        }
    }
}

/// Auxlliary monitored values for CMIS modules.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)
)]
pub struct AuxMonitors {
    /// Auxlliary monitor 1, either a custom value or TEC current.
    #[cfg_attr(
        any(feature = "api-traits", test),
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub aux1: Option<Aux1Monitor>,

    /// Auxlliary monitor 1, either laser temperature or TEC current.
    #[cfg_attr(
        any(feature = "api-traits", test),
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub aux2: Option<Aux2Monitor>,

    /// Auxlliary monitor 1, either laser temperature or additional supply
    /// voltage.
    #[cfg_attr(
        any(feature = "api-traits", test),
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub aux3: Option<Aux3Monitor>,

    /// A custom monitor. The value here is entirely vendor- and part-specific,
    /// so the part's data sheet must be consulted. The value may be either a
    /// signed or unsigned 16-bit integer, and so is included as raw bytes.
    #[cfg_attr(
        any(feature = "api-traits", test),
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub custom: Option<[u8; 2]>,
}

/// The first auxlliary CMIS monitor.
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)
)]
#[cfg_attr(any(feature = "api-traits", test), serde(rename_all = "snake_case"))]
pub enum Aux1Monitor {
    /// The monitored property is custom, i.e., part-specific.
    Custom([u8; 2]),

    /// The current of the laser thermoelectric cooler.
    ///
    /// For actively-cooled laser systems, this specifies the percentage of the
    /// maximum current the thermoelectric cooler supports. If the percentage is
    /// positive, the cooler is heating the laser. If negative, the cooler is
    /// cooling the laser.
    TecCurrent(f32),
}

/// The second auxlliary CMIS monitor.
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)
)]
#[cfg_attr(any(feature = "api-traits", test), serde(rename_all = "snake_case"))]
pub enum Aux2Monitor {
    /// The temperature of the laser itself (degrees C).
    LaserTemperature(f32),

    /// The current of the laser thermoelectric cooler.
    ///
    /// For actively-cooled laser systems, this specifies the percentage of the
    /// maximum current the thermoelectric cooler supports. If the percentage is
    /// positive, the cooler is heating the laser. If negative, the cooler is
    /// cooling the laser.
    TecCurrent(f32),
}

/// The third auxlliary CMIS monitor.
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(
    any(feature = "api-traits", test),
    derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)
)]
#[cfg_attr(any(feature = "api-traits", test), serde(rename_all = "snake_case"))]
pub enum Aux3Monitor {
    /// The temperature of the laser itself (degrees C).
    LaserTemperature(f32),

    /// Measured voltage of an additional power supply (Volts).
    AdditionalSupplyVoltage(f32),
}

// Resolutions for the various measured values.
//
// Transmitter bias current resolution, in Amperes.
const TX_BIAS_CURRENT_RESOLUTION: f32 = 2e-6;

// Temperature resolution, degrees C.
const TEMP_RESOLUTION: f32 = 1.0 / 256.0;

// Supply voltage resolution, in Volts;
const SUPPLY_VOLTAGE_RESOLUTION: f32 = 100e-6;

// Receiver and transmitter optical power resolution, in Watts.
const OPTICAL_POWER_RESOLUTION: f32 = 0.1e-6;

// Conversion from Watts to milliwatts, which we report.
const WATT_TO_MW: f32 = 1e3;

// Conversion from Amps to milliamps, which we report.
const AMP_TO_MA: f32 = 1e3;

fn decode_temperature(bytes: [u8; 2]) -> f32 {
    decode_with_scale::<i16>(bytes, TEMP_RESOLUTION)
}

fn decode_supply_voltage(bytes: [u8; 2]) -> f32 {
    let unscaled = u16::from_be_bytes(bytes);
    f32::from(unscaled) * SUPPLY_VOLTAGE_RESOLUTION
}

fn decode_optical_power(bytes: [u8; 2]) -> f32 {
    let unscaled = u16::from_be_bytes([bytes[0], bytes[1]]);
    f32::from(unscaled) * OPTICAL_POWER_RESOLUTION * WATT_TO_MW
}

fn decode_bias_current(bytes: [u8; 2]) -> f32 {
    let unscaled = u16::from_be_bytes([bytes[0], bytes[1]]);
    f32::from(unscaled) * TX_BIAS_CURRENT_RESOLUTION * AMP_TO_MA
}

fn decode_aux1(bytes: [u8; 2], is_tec: bool) -> Aux1Monitor {
    if is_tec {
        let unscaled = u16::from_be_bytes([bytes[0], bytes[1]]);
        Aux1Monitor::TecCurrent(f32::from(unscaled) / f32::from(i16::MAX))
    } else {
        Aux1Monitor::Custom(bytes)
    }
}

fn decode_aux2(bytes: [u8; 2], is_tec: bool) -> Aux2Monitor {
    if is_tec {
        let unscaled = u16::from_be_bytes([bytes[0], bytes[1]]);
        Aux2Monitor::TecCurrent(f32::from(unscaled) / f32::from(i16::MAX))
    } else {
        Aux2Monitor::LaserTemperature(decode_temperature(bytes))
    }
}

fn decode_aux3(bytes: [u8; 2], is_vcc2: bool) -> Aux3Monitor {
    if is_vcc2 {
        Aux3Monitor::AdditionalSupplyVoltage(decode_supply_voltage(bytes))
    } else {
        Aux3Monitor::LaserTemperature(decode_temperature(bytes))
    }
}

impl ParseFromModule for Monitors {
    fn reads(id: Identifier) -> Result<Vec<MemoryRead>, Error> {
        match id {
            Identifier::QsfpPlusSff8636 | Identifier::Qsfp28 => {
                // First, we'll read support for monitoring values, and the
                // description of how Rx power is measured.
                //
                // See SFF-8636 rev 2.10a Table 6-23.
                let page = sff8636::Page::Upper(sff8636::UpperPage::new(0).unwrap());
                let support = MemoryRead::new(page, 220, 1).unwrap();

                // Next we'll read the actual monitored values.
                //
                // See SFF-8636 rev 2.10a Table 6-7 and 6-8.
                //
                // For the module-wide values of temperature and voltage, we
                // read bytes 22-27, but only pull out 22-23 and 26-27. Those
                // are the MSB and LSB for temperature and voltage respectively.
                let page = sff8636::Page::Lower;
                let module_wide = MemoryRead::new(page, 22, 6).unwrap();

                // For the per-lane monitors, we read all of the possible
                // monitors. Note that this isn't quite accurate, since the
                // number of lanes depends on the host electrical interface code
                // in page 0 byte 192.
                //
                // TODO-completeness.
                //
                // For now, read all of bytes 34 - 57. That's 24 bytes total:
                // 2 bytes per value (u16 or i16), and 4 lanes, and 3 items.
                let page = sff8636::Page::Lower;
                const START: u8 = 34;
                const SIZE: u8 = 8;
                const N_READS: u8 = 3;
                let per_lane =
                    (0..N_READS).map(|i| MemoryRead::new(page, START + SIZE * i, SIZE).unwrap());

                let mut reads = Vec::with_capacity(5);
                reads.push(support);
                reads.push(module_wide);
                reads.extend(per_lane);
                Ok(reads)
            }
            Identifier::QsfpPlusCmis
            | Identifier::QsfpDD
            | Identifier::Osfp8
            | Identifier::OsfpXd => {
                // TODO-completeness: There are two additional complexities
                // here. First, this data is technically only available when the
                // MemoryModel of the module indicates it is paged. Nearly all
                // modules work that way, so we're not checking that now.
                //
                // Second, many of these pages are banked, such as the per-lane
                // monitor values. Each bank supports 8 lanes, which is enough
                // for all the modules we currently support (even when we move
                // to QSFP-DD). However, there may be modules in the future that
                // have more lanes, and thus we'd need to expand the reads and
                // parsing here to handle multiple banks. Presumably issuing
                // those reads in the first place would only be done once we
                // check the number of lanes / banks the module actually
                // supports.

                // There are a number of different pieces of the memory map that
                // we need to read to correctly interpret all the data. This
                // includes the advertisements of which monitors are available,
                // as well as which values those actually measure.
                //
                // Start with reading the support for the various monitors
                // themselves. See CMIS 5.0 section 8.4.9 for description of the
                // advertisements. The first byte (159) indicates support for
                // the module-level monitors. Byte 160 indicates support for
                // per-lane monitors, and scaling factor on the Tx bias current.
                let page = cmis::Page::Upper(cmis::UpperPage::new_unbanked(1).unwrap());
                let support = MemoryRead::new(page, 159, 2).unwrap();

                // Next we need to understand what the monitors actually
                // measure.
                //
                // The values measured in the auxiliary monitors is in byte
                // 145. Byte 151 bit 4 indicates the kind of Rx power
                // measurement, either average or OMA (peak-to-peak). We'll read
                // the whole 7-byte span.
                //
                // TODO-completeness: There is a lot of additional information
                // here, such as temperature / voltage ranges, filtering and
                // equalization parameters, and timing characteristics. We may
                // want to pull these out and parse them as well.
                let page = cmis::Page::Upper(cmis::UpperPage::new_unbanked(1).unwrap());
                let measured_values = MemoryRead::new(page, 145, 7).unwrap();

                // See CMIS section 8.2.5 for module-level monitors. There are
                // 6 values to read: temperature, voltage, 3 auxiliary monitors
                // and the custom monitor. That's 12 octets, so we need two
                // reads here, split into the main temp / voltage, and all the
                // aux for simplicity.
                let page = cmis::Page::Lower;
                let main_module_wide = MemoryRead::new(page, 14, 4).unwrap();
                let aux_monitors = MemoryRead::new(page, 18, 8).unwrap();

                // Read the per-lane monitoring values.
                //
                // See CMIS 5.0 section 8.9.4 for details on these values and
                // their locations in the memory maps. As with SFF-8636, we need
                // to issue several reads to stay within the 8-byte limit.
                const START: u8 = 154;
                const N_LANES_PER_BANK: u8 = 8;
                const N_BYTES_PER_ITEM: u8 = core::mem::size_of::<u16>() as u8;
                const N_ITEMS: u8 = 3; // Tx power, Tx bias, Rx power.
                const N_TOTAL_BYTES: u8 = N_LANES_PER_BANK * N_BYTES_PER_ITEM * N_ITEMS;
                const N_BYTES_PER_READ: u8 = 8;
                let page = cmis::Page::Upper(cmis::UpperPage::new_banked(0x11, 0).unwrap());
                let per_lane_reads = (START..START + N_TOTAL_BYTES)
                    .step_by(usize::from(N_BYTES_PER_READ))
                    .map(|start| MemoryRead::new(page, start, N_BYTES_PER_READ).unwrap());

                let mut reads =
                    Vec::with_capacity(usize::from(4 + N_TOTAL_BYTES / N_BYTES_PER_READ));
                reads.push(support);
                reads.push(measured_values);
                reads.push(main_module_wide);
                reads.push(aux_monitors);
                reads.extend(per_lane_reads);

                Ok(reads)
            }
            _ => Err(Error::UnsupportedIdentifier(id)),
        }
    }

    fn parse<'a>(id: Identifier, mut reads: impl Iterator<Item = &'a [u8]>) -> Result<Self, Error> {
        match id {
            Identifier::QsfpPlusSff8636 | Identifier::Qsfp28 => {
                // Decode the support first, see Table 6-23. We expect one byte
                // first.
                let byte = reads
                    .next()
                    .ok_or(Error::ParseFailed)?
                    .first()
                    .ok_or(Error::ParseFailed)?;
                let temp_supported = (byte & 0b0010_0000) != 0;
                let supply_voltage_supported = (byte & 0b0001_0000) != 0;
                let rx_power_is_average = (byte & 0b0000_1000) != 0;
                let tx_power_supported = (byte & 0b0000_0100) != 0;

                // Decode the temperature, if it is implemented.
                let module_wide = reads.next().ok_or(Error::ParseFailed)?;
                let temperature = if temp_supported {
                    Some(decode_temperature([module_wide[0], module_wide[1]]))
                } else {
                    None
                };

                // Decode supply voltage, if implemented.
                let supply_voltage = if supply_voltage_supported {
                    // Bytes 24-25 are reserved, skip them.
                    Some(decode_supply_voltage([module_wide[4], module_wide[5]]))
                } else {
                    None
                };

                // Decode the per-lane receiver power. We actually can't tell
                // the difference between "unsupported" and a peak-to-peak
                // measurement, which is silly. From SFF-8636, paragraphs after
                // Table 6-23:
                //
                // > Bit 3 indicates whether the received power measurement
                // > represents average input optical power or OMA. The
                // > indication is required, however, support of received power
                // > measurement is optional (see Table 6-8). If the bit is set,
                // > the average power is monitored. If not, received power
                // > measurement is not supported, or OMA is monitored.
                //
                // Great. We'll always decode all the measurements, then, for a
                // total of up to four lanes.
                let rx_power = reads.next().ok_or(Error::ParseFailed)?;
                let receiver_power = Some(
                    rx_power
                        .chunks_exact(core::mem::size_of::<u16>())
                        .map(|chunk| {
                            let power = decode_optical_power([chunk[0], chunk[1]]);
                            if rx_power_is_average {
                                ReceiverPower::Average(power)
                            } else {
                                ReceiverPower::PeakToPeak(power)
                            }
                        })
                        .collect(),
                );

                // Decode transceiver bias current and measured output power, if
                // they're supported.
                let tx_bias = reads.next().ok_or(Error::ParseFailed)?;
                let tx_power = reads.next().ok_or(Error::ParseFailed)?;
                let (transmitter_bias_current, transmitter_power) = if tx_power_supported {
                    let bias = tx_bias
                        .chunks_exact(core::mem::size_of::<u16>())
                        .map(|chunk| decode_bias_current([chunk[0], chunk[1]]))
                        .collect();

                    let power = tx_power
                        .chunks_exact(core::mem::size_of::<u16>())
                        .map(|chunk| decode_optical_power([chunk[0], chunk[1]]))
                        .collect();
                    (Some(bias), Some(power))
                } else {
                    (None, None)
                };

                Ok(Self {
                    temperature,
                    supply_voltage,
                    receiver_power,
                    transmitter_bias_current,
                    transmitter_power,
                    aux_monitors: None,
                })
            }
            Identifier::QsfpPlusCmis
            | Identifier::QsfpDD
            | Identifier::Osfp8
            | Identifier::OsfpXd => {
                // First read of 2 bytes indicates support for module level
                // monitors.
                let support = reads.next().ok_or(Error::ParseFailed)?;
                let byte = support.first().ok_or(Error::ParseFailed)?;
                let custom_supported = (byte & 0b0010_0000) != 0;
                let aux3_supported = (byte & 0b0001_0000) != 0;
                let aux2_supported = (byte & 0b0000_1000) != 0;
                let aux1_supported = (byte & 0b0000_0100) != 0;
                let any_aux_supported = (byte & 0b0001_1111) != 0;
                let voltage_supported = (byte & 0b0000_0010) != 0;
                let temp_supported = (byte & 0b0000_0001) != 0;

                let byte = support.get(1).ok_or(Error::ParseFailed)?;
                let tx_bias_scale: f32 = match (byte >> 3) & 0b11 {
                    0b00 => 1.0,
                    0b01 => 2.0,
                    0b10 => 4.0,
                    _ => unreachable!("This is a reserved scaling encoding"),
                };
                let rx_power_supported = (byte & 0b100) != 0;
                let tx_power_supported = (byte & 0b010) != 0;
                let tx_bias_supported = (byte & 0b001) != 0;

                // The next read describes what's actually being measured by the
                // auxiliary monitors and Rx optical output power.
                let description = reads.next().ok_or(Error::ParseFailed)?;
                let observable = description.first().ok_or(Error::ParseFailed)?;
                let aux3_is_vcc2 = (observable & 0b100) != 0;
                let aux2_is_tec = (observable & 0b010) != 0;
                let aux1_is_tec = (observable & 0b001) != 0;
                let rx_type = description.get(6).ok_or(Error::ParseFailed)?;
                let rx_power_is_average = (rx_type & 0b0001_0000) != 0;

                // Next we start parsing the actual data.
                //
                // First, there's a 4-byte read for the module wide temperature
                // and supply voltage.
                let module_wide = reads.next().ok_or(Error::ParseFailed)?;
                let temperature = if temp_supported {
                    Some(decode_temperature([module_wide[0], module_wide[1]]))
                } else {
                    None
                };
                let supply_voltage = if voltage_supported {
                    Some(decode_supply_voltage([module_wide[2], module_wide[3]]))
                } else {
                    None
                };

                // Next is an 8-byte read for the (up to) 4 auxiliary and custom
                // monitors.
                let aux = reads.next().ok_or(Error::ParseFailed)?;
                let aux1 = if aux1_supported {
                    Some(decode_aux1([aux[0], aux[1]], aux1_is_tec))
                } else {
                    None
                };
                let aux2 = if aux2_supported {
                    Some(decode_aux2([aux[2], aux[3]], aux2_is_tec))
                } else {
                    None
                };
                let aux3 = if aux3_supported {
                    Some(decode_aux3([aux[4], aux[5]], aux3_is_vcc2))
                } else {
                    None
                };
                let custom = if custom_supported {
                    Some([aux[6], aux[7]])
                } else {
                    None
                };
                let aux_monitors = if any_aux_supported {
                    Some(AuxMonitors {
                        aux1,
                        aux2,
                        aux3,
                        custom,
                    })
                } else {
                    None
                };

                // Next, decode the per-lane data itself.
                //
                // This is broken into 6 8-byte read chunks. Each encodes the
                // u16 values for 4 lanes of (tx power, tx bias, rx power).
                //
                // This helper function takes two of those 8-byte reads;
                // concatenates them into one array; and then applies the
                // `decoder` to successive 2-byte chunks.
                fn decode_chunks<T>(
                    read1: &[u8],
                    read2: &[u8],
                    decoder: impl Fn([u8; 2]) -> T,
                ) -> Vec<T> {
                    let all_items = [read1, read2].concat();
                    all_items
                        .as_slice()
                        .chunks_exact(2)
                        .map(|chunk| decoder([chunk[0], chunk[1]]))
                        .collect()
                }

                // Parse transmitter power if supported.
                let tx_power1 = reads.next().ok_or(Error::ParseFailed)?;
                let tx_power2 = reads.next().ok_or(Error::ParseFailed)?;
                let transmitter_power = if tx_power_supported {
                    Some(decode_chunks(tx_power1, tx_power2, decode_optical_power))
                } else {
                    None
                };

                // Parse transmitter bias current if supported. Note that we
                // need to apply the scaling factor.
                let tx_bias1 = reads.next().ok_or(Error::ParseFailed)?;
                let tx_bias2 = reads.next().ok_or(Error::ParseFailed)?;
                let transmitter_bias_current = if tx_bias_supported {
                    let decoder =
                        |bytes: [u8; 2]| -> f32 { decode_bias_current(bytes) * tx_bias_scale };
                    Some(decode_chunks(tx_bias1, tx_bias2, decoder))
                } else {
                    None
                };

                // Parse receiver optical power if supported.
                let rx_power1 = reads.next().ok_or(Error::ParseFailed)?;
                let rx_power2 = reads.next().ok_or(Error::ParseFailed)?;
                let receiver_power = if rx_power_supported {
                    let decoder = |bytes: [u8; 2]| -> ReceiverPower {
                        let pow = decode_optical_power(bytes);
                        if rx_power_is_average {
                            ReceiverPower::Average(pow)
                        } else {
                            ReceiverPower::PeakToPeak(pow)
                        }
                    };
                    Some(decode_chunks(rx_power1, rx_power2, decoder))
                } else {
                    None
                };

                Ok(Self {
                    temperature,
                    supply_voltage,
                    receiver_power,
                    transmitter_bias_current,
                    transmitter_power,
                    aux_monitors,
                })
            }
            _ => Err(Error::UnsupportedIdentifier(id)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Aux1Monitor;
    use super::Aux2Monitor;
    use super::Aux3Monitor;
    use super::AuxMonitors;
    use super::Identifier;
    use super::Monitors;
    use super::ParseFromModule;
    use super::ReceiverPower;
    use super::AMP_TO_MA;
    use super::OPTICAL_POWER_RESOLUTION;
    use super::SUPPLY_VOLTAGE_RESOLUTION;
    use super::TEMP_RESOLUTION;
    use super::TX_BIAS_CURRENT_RESOLUTION;
    use super::WATT_TO_MW;

    // SFF-8636, number of lanes reported.
    const N_LANES: usize = 4;

    // CMIS, number of lanes reported per bank.
    const N_LANES_PER_BANK: usize = 8;

    #[test]
    fn test_sff8636_monitor_reads() {
        let reads = Monitors::reads(Identifier::QsfpPlusSff8636).unwrap();
        assert_eq!(reads.len(), 5);
    }

    #[test]
    fn test_parse_sff8636_monitor_all_supported() {
        // Advertise that everything is supported
        let support = &[0b0011_1100];

        // Encode a module temperature of 50 * LSB \approx 0.19 C.
        let temp: i16 = 50;
        let expected_temp = f32::from(temp) * TEMP_RESOLUTION;

        // Encode a supply voltage of 50 * LSB == 0.005 V.
        let volt: u16 = 50;
        let expected_volt = f32::from(volt) * SUPPLY_VOLTAGE_RESOLUTION;

        // Package up module-level data.
        let mut module_data = Vec::with_capacity(6);
        module_data.extend_from_slice(&temp.to_be_bytes());
        module_data.extend_from_slice(&[0, 0]); // Unused;
        module_data.extend_from_slice(&volt.to_be_bytes());

        // Encode Rx input power of 10 * LSB == 1e-5 W. We are reporting mW, so
        // multiply by 1e3.
        let rx_pow: u16 = 10;
        let rx_pow_mw: f32 = f32::from(rx_pow) * OPTICAL_POWER_RESOLUTION * WATT_TO_MW;
        let expected_rx_pow = vec![ReceiverPower::Average(rx_pow_mw); N_LANES];

        // Same for Tx power, also in mW.
        let expected_tx_pow = vec![rx_pow_mw; N_LANES];

        // Encode a Tx bias current of 20 * LSB == 4e-5 A. We are reporting in
        // mA, so multiply by 1e3.
        let tx_bias: u16 = 20;
        let tx_bias_ma: f32 = f32::from(tx_bias) * TX_BIAS_CURRENT_RESOLUTION * AMP_TO_MA;
        let expected_tx_bias = vec![tx_bias_ma; N_LANES];

        // Package up per-lane data.
        let rx_pow_bytes = [rx_pow.to_be_bytes(); N_LANES].concat();
        let tx_bias_bytes = [tx_bias.to_be_bytes(); N_LANES].concat();
        let tx_pow_bytes = [rx_pow.to_be_bytes(); N_LANES].concat();

        // Package it all up.
        let reads = [
            support.as_slice(),
            &module_data,
            &rx_pow_bytes,
            &tx_bias_bytes,
            &tx_pow_bytes,
        ];

        // Decode and assert.
        let monitors = Monitors::parse(Identifier::QsfpPlusSff8636, reads.into_iter()).unwrap();

        // This is floating-point equality, but we've explicitly picked
        // exactly-representable values.
        assert_eq!(monitors.temperature.unwrap(), expected_temp);
        assert_eq!(monitors.supply_voltage.unwrap(), expected_volt);
        assert_eq!(monitors.receiver_power, Some(expected_rx_pow));
        assert_eq!(monitors.transmitter_bias_current.unwrap(), expected_tx_bias);
        assert_eq!(monitors.transmitter_power.unwrap(), expected_tx_pow);
    }

    #[test]
    fn test_cmis_monitor_reads() {
        let reads = Monitors::reads(Identifier::QsfpPlusCmis).unwrap();
        assert_eq!(reads.len(), 10);
        assert!(reads[4..].iter().all(|read| read.len() == 8));
    }

    #[test]
    fn test_parse_cmis_monitor_all_supported() {
        // Advertise that all module-level monitors are supported. Also
        // advertise support for all per-lane monitors, _except_ custom, and a
        // Tx bias scaling factor of 4.
        let tx_bias_scaling = 0b10;
        let support = [0b0001_1111, 0b0000_0111 | tx_bias_scaling << 3];

        // Describe the measured values.
        //
        // Byte 145, lower 3 bits describe the auxiliary monitors. We'll
        // indicate TEC current, laser temperature, and Vcc2.
        //
        // Byte 151, bit 4 indicates the Rx power measurement. We'll report
        // averages.
        let mut description = [0u8; 7];
        description[0] = 0b101;
        description[6] = 0b0001_0000;

        // Encode a module temperature of 50 * LSB \approx 0.19 C.
        let temp: i16 = 50;
        let expected_temp = f32::from(temp) * TEMP_RESOLUTION;

        // Encode a supply voltage of 20 * LSB == 0.005 V.
        let volt: u16 = 20;
        let expected_volt = f32::from(volt) * SUPPLY_VOLTAGE_RESOLUTION;

        // Package up module-level data.
        let module_data = [temp.to_be_bytes(), volt.to_be_bytes()].concat();

        // Aux 1, TEC current of ~50%.
        let tec_current: i16 = i16::MAX / 2;
        let expected_tec_current = f32::from(tec_current) / f32::from(i16::MAX);

        // Aux 2, laser temperature of 50 * 1 / 256 \approx 0.19 C.
        let laser_temp: i16 = 50;
        let expected_laser_temp = f32::from(laser_temp) * TEMP_RESOLUTION;

        // Aux 3, Vcc2 of 50 * 100uV == 0.005 V.
        let vcc2: i16 = 50;
        let expected_vcc2 = f32::from(vcc2) * SUPPLY_VOLTAGE_RESOLUTION;

        // Package up auxiliary monitors.
        let aux_monitors = [
            tec_current.to_be_bytes(),
            laser_temp.to_be_bytes(),
            vcc2.to_be_bytes(),
            [0, 0], // Custom monitor unsupported
        ]
        .concat();

        // Encode Rx input power of 10 * LSB == 1e-5 W. We are reporting mW, so
        // multiply by 1e3.
        let rx_pow: u16 = 10;
        let rx_pow_mw: f32 = f32::from(rx_pow) * OPTICAL_POWER_RESOLUTION * WATT_TO_MW;
        let expected_rx_pow = vec![ReceiverPower::Average(rx_pow_mw); N_LANES_PER_BANK];

        // Same for Tx power, also in mW.
        let expected_tx_pow = vec![rx_pow_mw; N_LANES_PER_BANK];

        // Encode a Tx bias current of 20 * LSB == 4e-5 A. We are reporting in
        // mA, so multiply by 1e3.
        let tx_bias: u16 = 20;
        let tx_bias_ma: f32 = f32::from(tx_bias) * TX_BIAS_CURRENT_RESOLUTION * AMP_TO_MA;
        let expected_tx_bias = vec![tx_bias_ma * 4.0; N_LANES_PER_BANK];

        // Package up per-lane data.
        //
        // There are two key differences from SFF-8636 here. First, there are
        // up to 8 lanes reported per bank, rather than 4 lanes. Second, we can
        // only _read_ 4 lanes at a time, because of the 8-byte read limit. So
        // we need to be a bit more careful with how we pack this all up.
        let tx_pow_bytes1 = [rx_pow.to_be_bytes(); N_LANES_PER_BANK / 2].concat();
        let tx_pow_bytes2 = [rx_pow.to_be_bytes(); N_LANES_PER_BANK / 2].concat();
        let tx_bias_bytes1 = [tx_bias.to_be_bytes(); N_LANES_PER_BANK / 2].concat();
        let tx_bias_bytes2 = [tx_bias.to_be_bytes(); N_LANES_PER_BANK / 2].concat();
        let rx_pow_bytes1 = [rx_pow.to_be_bytes(); N_LANES_PER_BANK / 2].concat();
        let rx_pow_bytes2 = [rx_pow.to_be_bytes(); N_LANES_PER_BANK / 2].concat();

        // Package up the entire set of expected reads.
        let data = [
            support.as_slice(),
            description.as_slice(),
            &module_data,
            &aux_monitors,
            &tx_pow_bytes1,
            &tx_pow_bytes2,
            &tx_bias_bytes1,
            &tx_bias_bytes2,
            &rx_pow_bytes1,
            &rx_pow_bytes2,
        ];

        // Decode and assert.
        let monitors = Monitors::parse(Identifier::QsfpPlusCmis, data.into_iter()).unwrap();

        // This is floating-point equality, but we've explicitly picked
        // exactly-representable values.
        assert_eq!(monitors.temperature.unwrap(), expected_temp);
        assert_eq!(monitors.supply_voltage.unwrap(), expected_volt);
        assert_eq!(monitors.receiver_power, Some(expected_rx_pow));
        assert_eq!(monitors.transmitter_bias_current.unwrap(), expected_tx_bias);
        assert_eq!(monitors.transmitter_power.unwrap(), expected_tx_pow);

        // Verify the auxiliary monitors.
        assert_eq!(
            monitors.aux_monitors,
            Some(AuxMonitors {
                aux1: Some(Aux1Monitor::TecCurrent(expected_tec_current)),
                aux2: Some(Aux2Monitor::LaserTemperature(expected_laser_temp)),
                aux3: Some(Aux3Monitor::AdditionalSupplyVoltage(expected_vcc2)),
                custom: None,
            })
        );
    }

    #[test]
    fn test_aux1_monitor_serdes() {
        let s = "{\"tec_current\":1.0}";
        let expected = Aux1Monitor::TecCurrent(1.0);
        assert_eq!(expected, serde_json::from_str(s).unwrap());
        assert_eq!(serde_json::to_string(&expected).unwrap().as_str(), s);
    }

    #[test]
    fn test_aux2_monitor_serdes() {
        let s = "{\"laser_temperature\":1.0}";
        let expected = Aux2Monitor::LaserTemperature(1.0);
        assert_eq!(expected, serde_json::from_str(s).unwrap());
        assert_eq!(serde_json::to_string(&expected).unwrap().as_str(), s);
    }

    #[test]
    fn test_aux3_monitor_serdes() {
        let s = "{\"additional_supply_voltage\":1.0}";
        let expected = Aux3Monitor::AdditionalSupplyVoltage(1.0);
        assert_eq!(expected, serde_json::from_str(s).unwrap());
        assert_eq!(serde_json::to_string(&expected).unwrap().as_str(), s);
    }

    #[test]
    fn test_receiver_power_serdes() {
        let s = "{\"average\":1.0}";
        let expected = ReceiverPower::Average(1.0);
        assert_eq!(expected, serde_json::from_str(s).unwrap());
        assert_eq!(serde_json::to_string(&expected).unwrap().as_str(), s);
    }
}
