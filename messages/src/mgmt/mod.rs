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

/// A description of a single 128-byte page of a transceiver's memory map.
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
pub enum Page {
    Sff8636(sff8636::Page),
    Cmis(cmis::Page),
}

impl Page {
    /// Return the actual page number of the upper page being mapped in, if any.
    ///
    /// If this access is for the lower page, then `None` is returned.
    pub fn page(&self) -> Option<u8> {
        match self {
            Page::Sff8636(inner) => inner.page(),
            Page::Cmis(inner) => inner.page(),
        }
    }

    /// Return the bank of the upper page being accessed, if any.
    ///
    /// Note that this returns `None` for pages that don't have a bank, e.g.,
    /// those for modules conforming to SFF-8636, or for the lower page of a
    /// CMIS module.
    ///
    /// For those which _may_ have a bank, this _may_ return `Some(_)`. Note
    /// that not all CMIS-defined pages allow a bank, so it may still return
    /// `None` in that case.
    pub fn bank(&self) -> Option<u8> {
        match self {
            Page::Sff8636(_) => None,
            Page::Cmis(inner) => inner.bank(),
        }
    }
}

impl From<sff8636::Page> for Page {
    fn from(p: sff8636::Page) -> Self {
        Self::Sff8636(p)
    }
}

impl From<cmis::Page> for Page {
    fn from(p: cmis::Page) -> Self {
        Self::Cmis(p)
    }
}

/// A sized read access to a transceiver memory page.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize, SerializedSize)]
pub struct MemoryRead {
    page: Page,
    offset: u8,
    len: u8,
}

impl MemoryRead {
    /// Create a new validated read from the specific page.
    pub fn new<P>(page: P, offset: u8, len: u8) -> Result<Self, Error>
    where
        P: MemoryPage + Into<Page>,
    {
        verify_read(&page, offset, len)?;
        Ok(Self {
            page: page.into(),
            offset,
            len,
        })
    }

    /// Return the page being read.
    pub fn page(&self) -> &Page {
        &self.page
    }

    /// Return the offset into the page of the start of the read.
    pub fn offset(&self) -> u8 {
        self.offset
    }

    /// Return the number of bytes read.
    pub fn len(&self) -> u8 {
        self.len
    }
}

/// A sized read access to a transceiver memory page.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize, SerializedSize)]
pub struct MemoryWrite {
    page: Page,
    offset: u8,
    len: u8,
}

impl MemoryWrite {
    /// Create a new validated write to the specific page.
    pub fn new<P>(page: P, offset: u8, len: u8) -> Result<Self, Error>
    where
        P: MemoryPage + Into<Page>,
    {
        verify_write(&page, offset, len)?;
        Ok(Self {
            page: page.into(),
            offset,
            len,
        })
    }

    /// Return the page being read.
    pub fn page(&self) -> &Page {
        &self.page
    }

    /// Return the offset into the page of the start of the write.
    pub fn offset(&self) -> u8 {
        self.offset
    }

    /// Return the number of bytes written.
    pub fn len(&self) -> u8 {
        self.len
    }
}

/// A trait describing the limits of a memory page.
pub trait MemoryPage: Copy {
    /// The maximum allowed offset into the memory page.
    fn max_offset(&self) -> u8;

    /// The minimum allowed offset into the memory page.
    ///
    /// Note that these values are always referenced to the full 256-byte
    /// transceiver memory map. So this should be zero for a lower page, and 128
    /// for an upper page.
    fn min_offset(&self) -> u8 {
        0
    }

    /// The upper limit of the page.
    ///
    /// Specifically, this is the offset of the first _invalid_ byte of the
    /// page, or equivalently the maximum offset plus 1.
    fn upper_limit(&self) -> u16 {
        self.max_offset() as u16 + 1
    }

    /// The minimum size of a write operation, in bytes.
    const MIN_WRITE_SIZE: u8 = 1;

    /// The maximum size of a write operation, in bytes.
    const MAX_WRITE_SIZE: u8;

    /// The minimum size of a read operation, in bytes.
    const MIN_READ_SIZE: u8 = 1;

    /// The maximum size of a read operation, in bytes.
    const MAX_READ_SIZE: u8;
}

// Helper to check that the limits provided define a valid read.
fn verify_read<P>(page: &P, offset: u8, len: u8) -> Result<(), Error>
where
    P: MemoryPage,
{
    if offset >= page.min_offset()
        && offset <= page.max_offset()
        && (offset as u16 + len as u16) <= page.upper_limit()
        && len >= P::MIN_READ_SIZE
        && len <= P::MAX_READ_SIZE
    {
        return Ok(());
    }
    Err(Error::InvalidMemoryAccess { offset, len })
}

// Helper to check that the limits provided define a valid write.
fn verify_write<P>(page: &P, offset: u8, len: u8) -> Result<(), Error>
where
    P: MemoryPage,
{
    if offset >= page.min_offset()
        && offset <= page.max_offset()
        && (offset as u16 + len as u16) <= page.upper_limit()
        && len >= P::MIN_WRITE_SIZE
        && len <= P::MAX_WRITE_SIZE
    {
        return Ok(());
    }
    Err(Error::InvalidMemoryAccess { offset, len })
}

#[cfg(test)]
mod tests {
    use crate::mgmt::cmis;
    use crate::mgmt::sff8636;
    use crate::mgmt::MemoryPage;
    use crate::mgmt::MemoryRead;
    use crate::mgmt::MemoryWrite;
    use crate::mgmt::Page;
    use crate::Error;

    fn test_page_memory_read<P>(page: P)
    where
        P: MemoryPage + Into<Page>,
    {
        let wrapped = page.into();

        // Should always be able to read from the minimum offset for up to the
        // maximum read size.
        for len in 1..=P::MAX_READ_SIZE {
            let read = MemoryRead::new(page, page.min_offset(), len).unwrap();
            assert_eq!(read.page(), &wrapped);
            assert_eq!(read.offset(), page.min_offset());
            assert_eq!(read.len(), len);
        }

        // Should always be able to read 1 byte, at any offset.
        for offset in page.min_offset()..page.max_offset() {
            let read = MemoryRead::new(page, offset, 1).unwrap();
            assert_eq!(read.page(), &wrapped);
            assert_eq!(read.offset(), offset);
            assert_eq!(read.len(), 1);
        }

        // Read exactly to the end.
        let (offset, len) = (page.max_offset(), 1);
        let read = MemoryRead::new(page, offset, len).unwrap();
        assert_eq!(read.page(), &wrapped);
        assert_eq!(read.offset(), offset);
        assert_eq!(read.len(), len);

        // Read past the end.
        let len = 2;
        assert_eq!(
            MemoryRead::new(page, offset, 2).unwrap_err(),
            Error::InvalidMemoryAccess { offset, len }
        );
    }

    fn test_page_memory_write<P>(page: P)
    where
        P: MemoryPage + Into<Page>,
    {
        let wrapped = page.into();

        // Should always be able to write from the minimum offset for up to the
        // maximum read size.
        for len in 1..=P::MAX_WRITE_SIZE {
            let read = MemoryWrite::new(page, page.min_offset(), len).unwrap();
            assert_eq!(read.page(), &wrapped);
            assert_eq!(read.offset(), page.min_offset());
            assert_eq!(read.len(), len);
        }

        // Should always be able to write 1 byte, at any offset.
        for offset in page.min_offset()..page.max_offset() {
            let read = MemoryWrite::new(page, offset, 1).unwrap();
            assert_eq!(read.page(), &wrapped);
            assert_eq!(read.offset(), offset);
            assert_eq!(read.len(), 1);
        }

        // Write exactly to the end.
        let (offset, len) = (page.max_offset(), 1);
        let read = MemoryWrite::new(page, offset, len).unwrap();
        assert_eq!(read.page(), &wrapped);
        assert_eq!(read.offset(), offset);
        assert_eq!(read.len(), len);

        // Write past the end.
        let len = 2;
        assert_eq!(
            MemoryWrite::new(page, offset, 2).unwrap_err(),
            Error::InvalidMemoryAccess { offset, len }
        );
    }

    #[test]
    fn test_sff_8636_lower_page_memory_read() {
        test_page_memory_read(sff8636::Page::Lower);
    }

    #[test]
    fn test_sff_8636_upper_page_memory_read() {
        test_page_memory_read(sff8636::Page::Upper(sff8636::UpperPage::new(0).unwrap()));
    }

    #[test]
    fn test_cmis_lower_page_memory_read() {
        test_page_memory_read(cmis::Page::Lower);
    }

    #[test]
    fn test_cmis_upper_page_memory_read() {
        test_page_memory_read(cmis::Page::Upper(cmis::UpperPage::new_unbanked(0).unwrap()));
    }

    #[test]
    fn test_sff_8636_lower_page_memory_write() {
        test_page_memory_write(sff8636::Page::Lower);
    }

    #[test]
    fn test_sff_8636_upper_page_memory_write() {
        test_page_memory_write(sff8636::Page::Upper(sff8636::UpperPage::new(0).unwrap()));
    }

    #[test]
    fn test_cmis_lower_page_memory_write() {
        test_page_memory_write(cmis::Page::Lower);
    }

    #[test]
    fn test_cmis_upper_page_memory_write() {
        test_page_memory_write(cmis::Page::Upper(cmis::UpperPage::new_unbanked(0).unwrap()));
    }
}
