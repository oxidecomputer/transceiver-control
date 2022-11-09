// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Specifications for transceiver management interfaces.

pub mod cmis;
pub mod sff8636;

use crate::Error;
use hubpack::SerializedSize;
use serde::Deserialize;
use serde::Serialize;

/// The specification to which a transciever's management interface conforms.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize, SerializedSize)]
pub enum ManagementInterface {
    /// SFF-8636, which covers QSFP+ and QSFP28.
    Sff8636,
    /// Common Management Interface Specification version 5, which covers QSFPDD
    /// and OSFP.
    Cmis,
    /// Any other interface specification, unsupported at this time.
    Unknown(u8),
}

/// A description of how to page in the upper 128-bytes of a transceiver's
/// memory map.
///
/// There are several specifications that define the memory map for a free-side
/// transceiver monitor. (See [`ManagementInterface`] for details.) Though there
/// are lots of variations, all supported specifications split this space into
/// two 128-byte pages: a fixed lower page and one or more upper pages.
///
/// Paging versus flat
/// ------------------
///
/// No matter the spec, a module's lower page is fixed and always available.
/// This supports data shared across all kinds of devices, and data where access
/// time is important, such as for control. Some simple devices contain a single
/// fixed upper page, in which case the module is considered to have "flat
/// memory".
///
/// For more complex devices, many upper pages are supported, and the map is
/// referred to in the specs as "paged memory". These can be swapped out on
/// demand, by writing to a specific page-select byte, `0x7F` to choose which
/// upper page is accessed. These pages have a set of allow page numbers to
/// identify them, which vary depending on the spec. Also note that not all
/// modules support all allowed pages, instead advertising what is supported in
/// the lower memory page.
///
/// Pages and banks
/// ---------------
///
/// In CMIS 5.0, the concept of page _banks_ was introduced, to allow an
/// additional level of paging. A bank of pages is several "copies" of the same
/// page number. The rationale for another level of nesting is to support
/// information on a per-lane basis, such as independent power measurements or
/// alerts.
///
/// This is only valid for modules conforming to CMIS 5.0. The bank-select by is
/// immediately before the page-select byte, at `0x7E`. As with pages, note that
/// not all banks are supported by all modules.
///
/// Accessing specific pages
/// ------------------------
///
/// This network protocol requires that all memory accesses specify which page
/// they would like to address. This is required so that the SP can correctly
/// ask the actual free-side module to swap in the right page, and then read or
/// write it as the host requested, all atomically from the point of view of the
/// client(s).
///
/// > Important! It's the responsibility of the _host_ to determine if a given
/// page or bank is supported by any particular module. We'd like to keep as
/// much intelligence about parsing the memory maps in the host as possible,
/// including identifying the management specification, and which pages if any
/// are supported for a module. The intention is for the SP to only interpret
/// sections of the map insofar as required for temperature and power
/// monitoring.
///
/// Note that modules generally don't _fail_ a memory access to an unsupported
/// page. Instead, modules generally just revert the page- or bank-select bytes
/// to those known to be valid, usually zero. That means the client _must_ keep
/// track of which bank and/or page is being accessed, and validate that those
/// are actually supported by the module prior to operating on them.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize, SerializedSize)]
pub enum UpperPage {
    Sff8636(sff8636::Page),
    Cmis(cmis::Page),
}

impl UpperPage {
    /// Return the actual page number of the upper page being mapped in.
    pub fn page(&self) -> u8 {
        match self {
            UpperPage::Sff8636(inner) => inner.page(),
            UpperPage::Cmis(inner) => inner.page(),
        }
    }

    /// Return the bank of the upper page being accessed.
    ///
    /// Note that this returns `None` for pages that don't have a bank, e.g.,
    /// those for modules conforming to SFF-8636.
    ///
    /// For those which _may_ have a bank, this _may_ return `Some(_)`. Note
    /// that not all CMIS-defined pages allow a bank, so it may still return
    /// `None` in that case.
    pub fn bank(&self) -> Option<u8> {
        match self {
            UpperPage::Sff8636(_) => None,
            UpperPage::Cmis(inner) => inner.bank(),
        }
    }
}

impl From<sff8636::Page> for UpperPage {
    fn from(p: sff8636::Page) -> Self {
        Self::Sff8636(p)
    }
}

impl From<cmis::Page> for UpperPage {
    fn from(p: cmis::Page) -> Self {
        Self::Cmis(p)
    }
}

/// A description of a region of a transceiver's memory map.
///
/// See [`UpperPage`] for a detailed description of how a module's upper page is
/// mapped in for an operation. This type also performs validation against the
/// offset / length, to ensure they're a valid access for the 256-byte memory
/// map of all transceiver modules we support.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize, SerializedSize)]
pub struct MemoryRegion {
    upper_page: UpperPage,
    offset: u8,
    len: u8,
}

impl MemoryRegion {
    /// Construct a new memory region.
    ///
    /// Note that you must specify an `upper_page`, even if you are only
    /// accessing the fixed, lower page of memory. In that case, you can use
    /// the default for the specification of the accessed module, which uses
    /// page and / or bank zero.
    pub fn new(upper_page: UpperPage, offset: u8, len: u8) -> Result<Self, Error> {
        // The last accessed byte must be within the 256-byte memory map.
        if offset.checked_add(len).is_none() {
            return Err(Error::InvalidMemoryAccess { offset, len });
        }

        // TODO-correctness: Whether / how to handle zero-byte accesses?
        Ok(Self {
            upper_page,
            offset,
            len,
        })
    }

    /// Return the information about the mapped upper page of this memory
    /// region.
    pub fn upper_page(&self) -> &UpperPage {
        &self.upper_page
    }

    /// Return the actual page number of the upper page being mapped in.
    ///
    /// See [`UpperPage::page`] for details.
    pub fn page(&self) -> u8 {
        self.upper_page.page()
    }

    /// Return the bank of the upper page being accessed.
    ///
    /// See [`UpperPage::bank`] for details.
    pub fn bank(&self) -> Option<u8> {
        self.upper_page.bank()
    }

    /// Return the offset into the transceiver memory map for the operation.
    pub fn offset(&self) -> u8 {
        self.offset
    }

    /// Return the length of transceiver memory for the operation.
    pub fn len(&self) -> u8 {
        self.len
    }
}

#[cfg(test)]
mod tests {
    use crate::mgmt::sff8636;
    use crate::mgmt::MemoryRegion;
    use crate::mgmt::UpperPage;
    use crate::Error;

    #[test]
    fn test_memory_region() {
        let page = UpperPage::Sff8636(sff8636::Page::default());
        let region = MemoryRegion::new(page, 0, 10).unwrap();
        assert_eq!(region.upper_page(), &page);
        assert_eq!(region.page(), page.page());
        assert!(region.bank().is_none());

        // Would read past map end.
        assert!(matches!(
            MemoryRegion::new(page, 1, 255).unwrap_err(),
            Error::InvalidMemoryAccess { .. }
        ));
        assert!(matches!(
            MemoryRegion::new(page, 255, 1).unwrap_err(),
            Error::InvalidMemoryAccess { .. }
        ));
    }
}
