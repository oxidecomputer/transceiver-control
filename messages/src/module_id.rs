// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Types used to address individual transceivers on a Sidecar.

use hubpack::SerializedSize;
use serde::Deserialize;
use serde::Serialize;

// The type used to address the front IO ports.
//
// This is a bitmask where each bit position corresponds to the QSFP port on the
// front IO panel with that logical number. I.e., the QSFP port labeled 0 is at
// bit 0 here.
type MaskType = u64;

/// A bitmask used to identify the set of transceiver ports on a Sidecar.
#[derive(Clone, Copy, Default, Deserialize, Eq, PartialEq, Serialize, SerializedSize)]
#[repr(transparent)]
pub struct ModuleId(pub MaskType);

impl core::fmt::Debug for ModuleId {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "ModuleId(0x{:0x})", self.0)
    }
}

/// Attempt to address an invalid transceiver port.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize, SerializedSize)]
#[cfg_attr(any(test, feature = "std"), derive(thiserror::Error))]
pub struct InvalidPort(pub u8);

impl core::fmt::Display for InvalidPort {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Invalid transceiver port: {}", self.0)
    }
}

impl ModuleId {
    pub const MAX_INDEX: u8 = (core::mem::size_of::<MaskType>() * 8) as _;

    /// Return true if the provided index is set, or false otherwise. If the
    /// index is out of range, and error is returned.
    pub fn is_set(&self, index: u8) -> Result<bool, InvalidPort> {
        if index >= Self::MAX_INDEX {
            Err(InvalidPort(index))
        } else {
            Ok((self.0 & (1 << index)) != 0)
        }
    }

    /// Set the bit at the provided index. If it is out of range, an error is
    /// returned.
    pub fn set(&mut self, index: u8) -> Result<(), InvalidPort> {
        if index >= Self::MAX_INDEX {
            Err(InvalidPort(index))
        } else {
            self.0 |= 1 << index;
            Ok(())
        }
    }

    /// Clear the bit at the provided index. If it is out of range, an error is
    /// returned.
    pub fn clear(&mut self, index: u8) -> Result<(), InvalidPort> {
        if index >= Self::MAX_INDEX {
            Err(InvalidPort(index))
        } else {
            self.0 &= !(1 << index);
            Ok(())
        }
    }

    /// Construct a port bitmask from an iterator over indices.
    ///
    /// If any index is out of bounds, an error is returned.
    pub fn from_index_iter<I: Iterator<Item = u8>>(it: I) -> Result<Self, InvalidPort> {
        let mut out = 0;
        for index in it {
            if index >= Self::MAX_INDEX {
                return Err(InvalidPort(index));
            }
            out |= 1 << index;
        }
        Ok(Self(out))
    }

    /// Construct a port bitmask from a slice of indices.
    ///
    /// If any index is out of bounds, an error is returned.
    pub fn from_indices(indices: &[u8]) -> Result<Self, InvalidPort> {
        Self::from_index_iter(indices.iter().copied())
    }

    /// Return the indices of the ports identified by the bitmask.
    pub fn to_indices(&self) -> impl Iterator<Item = u8> + '_ {
        (0..Self::MAX_INDEX).filter(|i| self.is_set(*i).unwrap())
    }

    /// A convenience function to return a port bitmask identifying a single
    /// port by index.
    pub const fn single(index: u8) -> Result<Self, InvalidPort> {
        if index >= Self::MAX_INDEX {
            Err(InvalidPort(index))
        } else {
            Ok(Self(1 << index))
        }
    }

    /// Return the number of transceivers addressed by `self`.
    pub const fn selected_transceiver_count(&self) -> usize {
        self.0.count_ones() as _
    }

    /// Return true if the number of transceivers is zero.
    pub const fn is_empty(&self) -> bool {
        self.selected_transceiver_count() == 0
    }

    /// Convience function to address all transceivers.
    pub const fn all() -> Self {
        Self(!0)
    }

    /// Convience function to address zero transceivers.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Return the set of modules that are in `self` and not `other`.
    pub const fn remove(&self, other: &Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Merge the set of modules in `self` and `other`, returning a copy.
    pub const fn merge(&self, other: &Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Return `true` if the provided index is contained in set of addressed
    /// modules.
    pub const fn contains(&self, ix: u8) -> bool {
        (self.0 & (1 << ix)) != 0
    }
}

/// A utility function to merge data for two modules.
///
/// Many operations in the controller crate return a list of data items
/// associated with a set of modules. Those operations are often comprised of
/// multiple steps, in which data is split or merged in various ways.
///
/// These are set-like operations on `ModuleId`s. But for a variety of reasons,
/// it's useful to store the data itself as a `Vec<T>`. That means the module
/// indices are not the same as the linear indices in those arrays. The
/// `ModuleId`s are _compressed_.
///
/// This method is used to merge the two `ModuleId`s (a set union), and also
/// merge the data arrays, such that the resulting `ModuleId::to_indices()`
/// method returns the data in the same order as it appears in the output
/// `Vec<T>`.
///
/// # Example
///
/// ```rust
/// use transceiver_messages::ModuleId;
/// use transceiver_messages::merge_module_data;
///
/// let first = ModuleId(0b101);
/// let first_data = vec![0, 2];
/// let second = ModuleId(0b010);
/// let second_data = vec![1];
/// let (modules, data) = merge_module_data(first, first_data.iter(), second, second_data.iter());
/// assert_eq!(modules, ModuleId(0b111));
/// assert_eq!(data, &[0, 1, 2]);
/// ```
///
/// Note that if both `ModuleId`s contain a given index, the second one will be
/// chosen.
#[cfg(any(test, feature = "std"))]
pub fn merge_module_data<'a, T: Clone + 'a>(
    first: ModuleId,
    first_data: impl Iterator<Item = &'a T>,
    second: ModuleId,
    second_data: impl Iterator<Item = &'a T>,
) -> (ModuleId, Vec<T>) {
    let n_items = first.selected_transceiver_count() + second.selected_transceiver_count();
    let mut out = Vec::with_capacity(n_items);

    let mut first_it = first.to_indices().zip(first_data).peekable();
    let mut second_it = second.to_indices().zip(second_data).peekable();
    loop {
        let (Some(f), Some(s)) = (first_it.peek(), second_it.peek()) else {
            break;
        };
        match f.0.cmp(&s.0) {
            std::cmp::Ordering::Less => out.push(first_it.next().unwrap().1.clone()),
            std::cmp::Ordering::Greater => out.push(second_it.next().unwrap().1.clone()),
            std::cmp::Ordering::Equal => {
                // Take both and push the last arbitrarily.
                let _ = first_it.next();
                let item = second_it.next().unwrap();
                out.push(item.1.clone());
            }
        }
    }
    // Only one of these will actually be consumable.
    out.extend(first_it.map(|it| it.1.clone()));
    out.extend(second_it.map(|it| it.1.clone()));

    (first.merge(&second), out)
}

/// Remove all the modules and corresponding data for every module in
/// `to_remove`.
#[cfg(any(test, feature = "std"))]
pub fn remove_module_data<'a, T: Clone + 'a>(
    modules: ModuleId,
    data: impl Iterator<Item = &'a T>,
    to_remove: ModuleId,
) -> (ModuleId, Vec<T>) {
    let new_modules = modules.remove(&to_remove);
    let new_data = modules
        .to_indices()
        .zip(data)
        .filter(|(ix, _elem)| !to_remove.contains(*ix))
        .map(|(_ix, elem)| elem)
        .cloned()
        .collect();
    (new_modules, new_data)
}

/// Keep only the modules and corresponding data for the modules in `to_keep`.
/// All others are removed.
#[cfg(any(test, feature = "std"))]
pub fn keep_module_data<'a, T: Clone + 'a>(
    modules: ModuleId,
    data: impl Iterator<Item = &'a T>,
    to_keep: ModuleId,
) -> (ModuleId, Vec<T>) {
    remove_module_data(modules, data, ModuleId(!to_keep.0))
}

/// Filter the modules and data to those for which a closure returns true.
///
/// This method is similar to `core::iter::Iterator::filter()`. It accepts a
/// closure, and yields elements of `modules` and `data` where the closure
/// returns `true`.
///
/// The callable is provided both the module index and the corresponding item of
/// `data`.
#[cfg(any(test, feature = "std"))]
pub fn filter_module_data<'a, T: Clone + 'a>(
    modules: ModuleId,
    data: impl Iterator<Item = &'a T>,
    f: impl Fn(u8, &'a T) -> bool,
) -> (ModuleId, Vec<T>) {
    let mut new_modules = ModuleId::empty();
    let mut new_data = Vec::new();
    for (ix, item) in modules
        .to_indices()
        .zip(data)
        .filter(|(module_index, item)| f(*module_index, item))
    {
        new_modules.set(ix).expect("Impossible index");
        new_data.push(item.clone());
    }
    (new_modules, new_data)
}

#[cfg(test)]
mod tests {
    use super::filter_module_data;
    use super::keep_module_data;
    use super::merge_module_data;
    use super::remove_module_data;
    use super::MaskType;
    use crate::InvalidPort;
    use crate::ModuleId;

    #[test]
    fn test_module_id_from_indices() {
        let ix = vec![0, 1, 2];
        let modules = ModuleId::from_indices(&ix).unwrap();
        assert_eq!(modules.0, 0b111);
        assert_eq!(modules.to_indices().collect::<Vec<_>>(), ix);
    }

    #[test]
    fn test_module_id_from_indices_out_of_range() {
        let port = ModuleId::MAX_INDEX;
        assert_eq!(ModuleId::from_indices(&[port]), Err(InvalidPort(port)));
    }

    #[test]
    fn test_module_id_test_set_clear() {
        let mut modules = ModuleId(0b101);
        assert!(modules.is_set(0).unwrap());
        assert!(!modules.is_set(1).unwrap());
        assert!(modules.is_set(2).unwrap());

        modules.set(0).unwrap();
        assert!(modules.is_set(0).unwrap());

        modules.set(1).unwrap();
        assert!(modules.is_set(1).unwrap());

        modules.clear(1).unwrap();
        assert!(!modules.is_set(1).unwrap());

        assert!(modules.set(200).is_err());
        assert!(modules.clear(200).is_err());
        assert!(modules.is_set(200).is_err());
    }

    #[test]
    fn test_module_id_all() {
        assert_eq!(ModuleId::all().0, MaskType::MAX);
    }

    #[test]
    fn test_selected_transceiver_count() {
        assert_eq!(ModuleId(0b101).selected_transceiver_count(), 2);
    }

    #[test]
    fn test_module_id_remove() {
        let modules = ModuleId(0b111);
        let other = ModuleId(0b001);
        assert_eq!(modules.remove(&other), ModuleId(0b110));
    }

    #[test]
    fn test_module_id_contains() {
        let modules = ModuleId(0b01);
        assert!(modules.contains(0));
        assert!(!modules.contains(1));
    }

    #[test]
    fn test_merge_module_id() {
        let first = ModuleId(0b101);
        let first_data = vec![0, 2];
        let second = ModuleId(0b010);
        let second_data = vec![1];
        let (modules, data) =
            merge_module_data(first, first_data.iter(), second, second_data.iter());
        assert_eq!(modules, ModuleId(0b111));
        assert_eq!(data, &[0, 1, 2]);
    }

    #[test]
    fn test_remove_module_data() {
        let modules = ModuleId(0b101);
        let data = vec![0, 2];
        let to_remove = ModuleId(0b010);
        let (new_modules, new_data) = remove_module_data(modules, data.iter(), to_remove);
        assert_eq!(modules, new_modules);
        assert_eq!(data, new_data);

        let to_remove = ModuleId(0b100);
        let (new_modules, new_data) = remove_module_data(modules, data.iter(), to_remove);
        assert_eq!(new_modules, ModuleId(0b001));
        assert_eq!(new_data, &[0]);

        let to_keep = ModuleId(0b100);
        let (new_modules, new_data) = keep_module_data(modules, data.iter(), to_keep);
        assert_eq!(new_modules, ModuleId(0b100));
        assert_eq!(new_data, &[2]);
    }

    #[test]
    fn test_filter_module_data() {
        let modules = ModuleId(0b101);
        let data = vec![0, 2];
        let f = |_, d| d % 2 == 0;
        let (new_modules, new_data) = filter_module_data(modules, data.iter(), f);
        assert_eq!(modules, new_modules);
        assert_eq!(data, new_data);

        let modules = ModuleId(0b111);
        let data = vec![0, 1, 2];
        let f = |_, d| d % 2 != 0;
        let (new_modules, new_data) = filter_module_data(modules, data.iter(), f);
        assert_eq!(new_modules, ModuleId(0b010));
        assert_eq!(new_data, vec![1]);
    }
}
