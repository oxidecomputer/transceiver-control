// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Decoding of transceiver power control information.

use crate::Error;
use crate::Identifier;
use crate::ParseFromModule;
use transceiver_messages::mgmt::cmis;
use transceiver_messages::mgmt::sff8636;
use transceiver_messages::mgmt::MemoryRead;

/// Description of software power control override status for a module.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PowerControl {
    /// The module uses the `LPMode` hardware signal to select low power mode.
    UseLpModePin,

    /// The module is configured for software control of low power mode.
    OverrideLpModePin {
        /// If true, the module is held in low power mode by software. If false,
        /// the module is allowed to enter high power mode.
        low_power: bool,
    },
}

impl ParseFromModule for PowerControl {
    fn reads(id: Identifier) -> Result<Vec<MemoryRead>, Error> {
        match id {
            Identifier::QsfpPlusSff8636 | Identifier::Qsfp28 => {
                // See SFF-8636 rev 2.10a Table 6-9.
                //
                // Byte 93, bit 0 contains the software override bit, and bit 1
                // if the module is forced to low power.
                let page = sff8636::Page::Lower;
                let power = MemoryRead::new(page, 93, 1).unwrap();
                Ok(vec![power])
            }
            Identifier::QsfpPlusCmis | Identifier::QsfpDD => {
                // See CMIS 5.0 table 8-10.
                //
                // Byte 26, bit 6 contains the software override bit, and bit 4
                // if the module is forced to low power. Note that the override
                // bit is really phrased as "allow the module to evaluate the
                // LPMode pin." That is, `0b1` means `LPMode` controls the
                // system, and `0b0` means software does.
                let page = cmis::Page::Lower;
                let power = MemoryRead::new(page, 26, 1).unwrap();
                Ok(vec![power])
            }
            _ => Err(Error::UnsupportedIdentifier(id)),
        }
    }

    fn parse<'a>(id: Identifier, mut reads: impl Iterator<Item = &'a [u8]>) -> Result<Self, Error> {
        match id {
            Identifier::QsfpPlusSff8636 | Identifier::Qsfp28 => {
                // Bit 0 -> override, bit 1 -> force low-power.
                reads
                    .next()
                    .and_then(|bytes| bytes.first())
                    .ok_or(Error::ParseFailed)
                    .map(|power| {
                        if power & 0b1 == 0 {
                            PowerControl::UseLpModePin
                        } else {
                            PowerControl::OverrideLpModePin {
                                low_power: (power & 0b10) != 0,
                            }
                        }
                    })
            }
            Identifier::QsfpPlusCmis | Identifier::QsfpDD => {
                // Bit 6 -> override (but see above), bit 4 -> force low-power.
                reads
                    .next()
                    .and_then(|bytes| bytes.first())
                    .ok_or(Error::ParseFailed)
                    .map(|power| {
                        if (power & 0b0100_0000) != 0 {
                            PowerControl::UseLpModePin
                        } else {
                            PowerControl::OverrideLpModePin {
                                low_power: (power & 0b0001_0000) != 0,
                            }
                        }
                    })
            }
            _ => Err(Error::UnsupportedIdentifier(id)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Identifier;
    use super::ParseFromModule;
    use super::PowerControl;

    #[test]
    fn test_power_control_from_module_sff8636() {
        let id = Identifier::Qsfp28;

        let bytes = [0b10u8]; // NOT power override
        let control = PowerControl::parse(id, std::iter::once(bytes.as_slice())).unwrap();
        assert!(matches!(control, PowerControl::UseLpModePin));

        let bytes = [0b11u8]; // Power override, set to low power.
        let control = PowerControl::parse(id, std::iter::once(bytes.as_slice())).unwrap();
        assert!(matches!(
            control,
            PowerControl::OverrideLpModePin { low_power: true }
        ));

        let bytes = [0b01u8]; // Power override, _not_ set to low power.
        let control = PowerControl::parse(id, std::iter::once(bytes.as_slice())).unwrap();
        assert!(matches!(
            control,
            PowerControl::OverrideLpModePin { low_power: false }
        ));
    }

    #[test]
    fn test_power_control_from_module_cmis() {
        let id = Identifier::QsfpPlusCmis;

        let bytes = [0b0100_0000]; // NOT power override.
        let control = PowerControl::parse(id, std::iter::once(bytes.as_slice())).unwrap();
        assert!(matches!(control, PowerControl::UseLpModePin));

        let bytes = [0b0000_0000]; // YES power override, not low power
        let control = PowerControl::parse(id, std::iter::once(bytes.as_slice())).unwrap();
        assert!(matches!(
            control,
            PowerControl::OverrideLpModePin { low_power: false }
        ));

        let bytes = [0b0001_0000]; // Power override, set to low power.
        let control = PowerControl::parse(id, std::iter::once(bytes.as_slice())).unwrap();
        assert!(matches!(
            control,
            PowerControl::OverrideLpModePin { low_power: true }
        ));
    }
}
