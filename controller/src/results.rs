// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Types for handling data returned by accessing multiple modules.
//!
//! The type [`ModuleId`] is used to address a set of transceiver modules. This
//! is a bit-mask, so that we can address multiple modules at once. That's very
//! flexible and powerful, but makes handling results and errors more
//! complicated. For example, when issuing a read to a set of modules, we'd like
//! to return all the data we can, as well as the failures that we might have
//! hit when accessing those modules.
//!
//! This is different from Rust's common `Result`, which is either a succesful
//! value _or_ an error. We need both, and so we use a struct rather than enum.
//! This module describes the generic [`ModuleResult`] for representing:
//!
//! - The modules addressed.
//! - The data, if any, returned succesfully
//! - The modules we failed to access and the associated errors.
//!
//! The latter is captured in [`FailedModules`].

use crate::PowerMode;
use crate::TransceiverError;
use transceiver_decode::Identifier;
use transceiver_decode::MemoryModel;
use transceiver_decode::Monitors;
use transceiver_decode::PowerControl;
use transceiver_decode::VendorInfo;
use transceiver_messages::merge_module_data;
use transceiver_messages::message::LedState;
use transceiver_messages::message::StatusV2;
use transceiver_messages::remove_module_data;
use transceiver_messages::ModuleId;

/// Information about modules we failed to access.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FailedModules {
    /// The modules we failed to access.
    pub modules: ModuleId,
    /// One error for each module above, specifying the reason for failure.
    pub errors: Vec<TransceiverError>,
}

impl FailedModules {
    /// Merge another set of failed modules and this one, returning their
    /// union.
    ///
    /// Note that `self` and `other` _may_ contain duplicate modules. In that
    /// case, the last error is stored, and others are discarded.
    pub fn merge(&self, other: &Self) -> Self {
        let mut out = self.clone();
        out.merge_into(other);
        out
    }

    /// Merge another set of failed modules _into_ this one, in place.
    pub fn merge_into(&mut self, other: &Self) {
        let (modules, errors) = merge_module_data(
            self.modules,
            self.errors.iter(),
            other.modules,
            other.errors.iter(),
        );
        *self = FailedModules { modules, errors };
    }

    /// Return `Self` with no failures at all.
    pub const fn success() -> Self {
        Self {
            modules: ModuleId::empty(),
            errors: vec![],
        }
    }

    /// Return an iterator over the failures, including the module indices and
    /// corresponding error.
    pub fn iter(&self) -> impl Iterator<Item = (u8, &TransceiverError)> + '_ {
        self.modules.to_indices().zip(self.errors.iter())
    }

    /// Return the error for the module with the provided index, if it exists.
    /// If not, return `None`.
    pub fn nth(&self, index: u8) -> Option<&TransceiverError> {
        self.iter()
            .find(|(ix, _item)| ix == &index)
            .map(|(_ix, item)| item)
    }
}

/// The result of a read operation accessing transceiver memory maps.
pub type ReadResult = ModuleResult<Vec<u8>>;

impl ReadResult {
    /// Return the actual data read from the modules.
    pub fn data(&self) -> &[Vec<u8>] {
        &self.data
    }
}

/// The result of accessing the status of a set of transceivers.
pub type StatusResult = ModuleResult<StatusV2>;

impl StatusResult {
    /// Return the status read from the modules.
    pub fn status(&self) -> &[StatusV2] {
        &self.data
    }
}

/// The result of reading the SFF-8024 identifiers of a set of transceivers.
pub type IdentifierResult = ModuleResult<Identifier>;

impl IdentifierResult {
    /// Return the identifiers read from the modules.
    pub fn identifiers(&self) -> &[Identifier] {
        &self.data
    }
}

/// The result of reading the vendor information for a set of transceivers.
pub type VendorInfoResult = ModuleResult<VendorInfo>;

impl VendorInfoResult {
    /// Return the vendor information read from the modules.
    pub fn vendor_info(&self) -> &[VendorInfo] {
        &self.data
    }
}

/// The result of reading the power-control information for a set of
/// transceivers.
pub(crate) type PowerControlResult = ModuleResult<PowerControl>;

impl PowerControlResult {
    /// Return the power control information read from the modules.
    pub(crate) fn power_control(&self) -> &[PowerControl] {
        &self.data
    }
}

/// The result of reading the memory model of a set of transceivers.
pub type MemoryModelResult = ModuleResult<MemoryModel>;

impl MemoryModelResult {
    /// Return the memory models read from the transceivers.
    pub fn memory_models(&self) -> &[MemoryModel] {
        &self.data
    }
}

/// The result of an operation on transceivers that has no data on success, but
/// may fail.
///
/// This includes things like assert LPMode. We simply acknowledge that or
/// return why it failed, there's no data associated with success.
pub type AckResult = ModuleResult<()>;

impl AckResult {
    /// Return a result with all successes, i.e., no failed modules.
    pub fn ack(modules: ModuleId) -> Self {
        Self::new(modules, FailedModules::success())
    }

    /// Return an `AckResult` from the successful and failed modules.
    pub fn new(modules: ModuleId, failures: FailedModules) -> Self {
        Self {
            modules,
            data: vec![(); modules.selected_transceiver_count()],
            failures,
        }
    }
}

/// The result of reading the power mode of a set of transceivers.
pub type PowerModeResult = ModuleResult<PowerMode>;

impl PowerModeResult {
    /// Return the power mode read from the transceivers.
    pub fn power_modes(&self) -> &[PowerMode] {
        &self.data
    }
}

/// The result of reading the LED state of a set of transceivers.
pub type LedStateResult = ModuleResult<LedState>;

/// The result of reading the monitoring data of a set of transceivers.
pub type MonitorResult = ModuleResult<Monitors>;

/// A generic type for accessing module-specific data and failures.
///
/// Many methods access multiple modules, and may return a piece of data for
/// each. E.g., reading the SFF-8024 Identifier for all modules should return
/// one ID for each one successfully read, plus any failures on the others.
///
/// One should generally use the type aliases for this, such as `ReadResult`,
/// which returns a concrete implementation of this type with the `data` field
/// that matches the method called.
#[derive(Clone, Debug, Default)]
pub struct ModuleResult<P> {
    pub modules: ModuleId,
    pub data: Vec<P>,
    pub failures: FailedModules,
}

impl<P> ModuleResult<P> {
    /// Return an iterator over the module indices and the corresponding data
    /// from that module.
    pub fn iter(&self) -> impl Iterator<Item = (u8, &P)> + '_ {
        self.modules.to_indices().zip(self.data.iter())
    }

    /// Return an iterator over the _errors_ in the result, with the module
    /// indices and the corresponding error.
    pub fn error_iter(&self) -> impl Iterator<Item = (u8, &TransceiverError)> + '_ {
        self.failures.iter()
    }

    /// Return the data item for the module with the provided index, if it
    /// exists. If not, return `None`.
    pub fn nth(&self, index: u8) -> Option<&P> {
        self.iter()
            .find(|(ix, _item)| ix == &index)
            .map(|(_ix, item)| item)
    }

    /// Return the error for the module with the provided index, if it exists.
    /// If not, return `None`.
    pub fn nth_err(&self, index: u8) -> Option<&TransceiverError> {
        self.failures.nth(index)
    }

    /// Return `true` if this result is successful, i.e., contains no failures.
    pub const fn is_success(&self) -> bool {
        self.failures.modules.is_empty()
    }

    /// Return a successful result.
    ///
    /// If the number of modules in `modules` and the length of `data` do not
    /// match, `None` is returned.
    pub fn success(modules: ModuleId, data: Vec<P>) -> Option<Self> {
        if modules.selected_transceiver_count() == data.len() {
            Some(Self {
                modules,
                data,
                failures: FailedModules::success(),
            })
        } else {
            None
        }
    }
}

impl<P: Clone> ModuleResult<P> {
    /// Merge the successful and error data from one result into `self`.
    ///
    /// This will take all the successful module IDs and data, and merge them
    /// into `self`'s success. Any failures in `other` will be merged into
    /// `self.failures`.
    ///
    /// This returns `None` if any of the following occur:
    ///
    /// - `other.modules` and `self.modules` overlap. In this case, it is not
    /// possible to build a consistent result, since we have two values for the
    /// successful data.
    /// - `other.failures` and `self.failures` overlap, for the same reason.
    ///
    /// Note that if a module exists in `other.failures.modules` and
    /// `self.modules`, then it is _removed_ from `self.modules` and added to
    /// the failures. The converse is _not_ true: if a module exists in
    /// `self.failures.modules` and `other.modules` it is _not_ removed. That
    /// is, failures are "sticky" in `self`.
    pub fn merge(&self, other: &Self) -> Option<Self> {
        // The intersection of the successful module IDs should be empty.
        if !(self.modules & other.modules).is_empty() {
            return None;
        }

        // Same for the failed module IDs.
        if !(self.failures.modules & other.failures.modules).is_empty() {
            return None;
        }

        // Remove any successes we currently have that are in the new failures.
        let (remaining_successes, remaining_data) = self.without_failures_from(other);

        // Remove any new successes that are currently in our set of failures.
        // This is to make sure any failures in `self` are sticky.
        let (new_modules, new_data) = other.without_failures_from(self);

        // Merge the new successes and failures in with our own.
        let (modules, data) = merge_module_data(
            remaining_successes,
            remaining_data.iter(),
            new_modules,
            new_data.iter(),
        );
        let failures = self.failures.merge(&other.failures);

        Some(Self {
            modules,
            data,
            failures,
        })
    }

    // Return the data from self with the failures from `other` removed.
    #[must_use]
    fn without_failures_from(&self, other: &Self) -> (ModuleId, Vec<P>) {
        remove_module_data(self.modules, self.data.iter(), other.failures.modules)
    }
}

impl<P> PartialEq for ModuleResult<P>
where
    P: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        if self.modules != other.modules {
            return false;
        }
        if self.data != other.data {
            return false;
        }
        self.failures == other.failures
    }
}

#[cfg(test)]
mod tests {
    use super::FailedModules;
    use super::ModuleId;
    use super::ModuleResult;
    use super::TransceiverError;
    use transceiver_messages::InvalidPort;

    // Test when there is overlap between the success / failure module IDs.
    #[test]
    fn test_merge_module_result_overlap() {
        let a = ModuleResult {
            modules: ModuleId(0b01),
            data: vec![0u8],
            failures: FailedModules::success(),
        };
        assert!(a.merge(&a).is_none());

        let failures = FailedModules {
            modules: ModuleId(0b01),
            errors: vec![TransceiverError::Port(InvalidPort(100))],
        };
        let a = ModuleResult {
            modules: ModuleId(0b01),
            data: vec![0u8],
            failures: failures.clone(),
        };
        let b = ModuleResult {
            modules: ModuleId(0b10),
            data: vec![0u8],
            failures,
        };
        assert!(a.merge(&b).is_none());
    }

    // The happy path, when there is no overlap at all between success IDs or
    // failure IDs.
    #[test]
    fn test_merge_module_result_no_overlap() {
        let failures = FailedModules {
            modules: ModuleId(0b001),
            errors: vec![TransceiverError::Port(InvalidPort(100))],
        };
        let a = ModuleResult {
            modules: ModuleId(0b010),
            data: vec![0u8],
            failures,
        };
        let b = ModuleResult {
            modules: ModuleId(0b100),
            data: vec![1u8],
            failures: FailedModules::success(),
        };
        let c = a.merge(&b).unwrap();
        assert_eq!(c.modules, ModuleId(0b110));
        assert_eq!(c.failures.modules, ModuleId(0b001));
        assert_eq!(c.data, vec![0, 1]);
        assert_eq!(
            c.failures.errors,
            vec![TransceiverError::Port(InvalidPort(100))],
        );
    }

    // Test that we remove the module ID from the first success if the merged-in
    // data indicates it's a failure.
    #[test]
    fn test_merge_module_result_new_failure() {
        // Just one success, no failures.
        let a = ModuleResult {
            modules: ModuleId(0b010),
            data: vec![0u8],
            failures: FailedModules::success(),
        };

        // Merge in data with one success, and one failure that removes the
        // above success.
        let failures = FailedModules {
            modules: ModuleId(0b010),
            errors: vec![TransceiverError::Port(InvalidPort(100))],
        };
        let b = ModuleResult {
            modules: ModuleId(0b100),
            data: vec![1u8],
            failures,
        };
        let c = a.merge(&b).unwrap();
        assert_eq!(c, b);
    }

    // Test that a new success does _not_ undo an earlier failure.
    #[test]
    fn test_merge_module_result_old_failure_is_sticky() {
        // Just one success, one failure.
        let failures = FailedModules {
            modules: ModuleId(0b01),
            errors: vec![TransceiverError::Port(InvalidPort(100))],
        };
        let a = ModuleResult {
            modules: ModuleId(0b010),
            data: vec![0u8],
            failures: failures.clone(),
        };

        // Merge in data with one success, at the previously failed module.
        let b = ModuleResult {
            modules: failures.modules,
            data: vec![1u8],
            failures: FailedModules::success(),
        };

        // Check that we still have the failure, and don't have the success.
        let c = a.merge(&b).unwrap();
        assert_eq!(c, a);
    }
}
