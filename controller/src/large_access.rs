// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Trait for splitting large memory accesses into chunks.
//!
//! The CMIS specification for accessing transceiver memory maps clearly
//! indicates that accesses must be limited in size. Unless otherwise noted,
//! accesses can be no larger than 8 octets. (See CMIS 5.0, section 5.2.2.1 for
//! more details.) While the SFF-8636 specification doesn't explicitly limit the
//! size of an access, experimentation with real transceivers shows that very
//! large accesses (128 bytes, for example) can generate I2C errors.
//!
//! This module contains a trait for describing an arbitrary-sized memory
//! access, and splitting that up into fixed-sized chunks of appropriate size.
//! For CMIS modules, the size is 8 octets. For SFF-8636 modules, the size is
//! currently limited to 64 octets, a value chosen through experimentation.

use crate::mgmt;
use crate::mgmt::MemoryPage;
use crate::Error;

/// A trait for splitting an arbitrary-sized access into limited chunks.
pub trait LargeMemoryAccess<P>: Sized
where
    P: MemoryPage,
    mgmt::Page: From<P>,
{
    /// The size of a single memory access chunk, in octets.
    const SIZE: u8;

    /// A dummy type asserting that the `SIZE` constant is valid.
    const _DUMMY: () = assert!(Self::SIZE > 0 && Self::SIZE <= 128);

    /// Return a single memory access of the provided size.
    fn build_one(page: P, offset: u8, len: u8) -> Result<Self, Error>;

    /// Split a single large access into many, using `Self::build_one()`.
    fn build_many(page: P, offset: u8, len: u8) -> Result<Vec<Self>, Error> {
        // A valid read scenario could lead the "end" to be 256 (e.g., offset = 192 and len = 64).
        // Simply adding these as u8 would result in an overflow.
        let stop = offset as u16 + len as u16;

        // The module memory map is only 256 bytes long, reject reads that attempt to go beyond
        // that.
        if stop > 256 {
            return Err(Error::ByteOutOfRange(stop as usize));
        }

        (offset as u16..stop)
            .step_by(usize::from(Self::SIZE))
            .map(|new_offset| {
                // The length is up to SIZE, or the remainder of the entire
                // operation, whichever is smaller.
                let remainder = (stop - new_offset) as u8;
                let new_len = Self::SIZE.min(remainder);
                Self::build_one(page, new_offset as u8, new_len)
            })
            .collect()
    }
}

impl LargeMemoryAccess<mgmt::sff8636::Page> for mgmt::MemoryRead {
    // TODO-correctness: Empirically this works fine, but not based on the spec.
    const SIZE: u8 = 64;

    fn build_one(page: mgmt::sff8636::Page, offset: u8, len: u8) -> Result<Self, Error> {
        Self::new(page, offset, len).map_err(Error::from)
    }
}

impl LargeMemoryAccess<mgmt::sff8636::Page> for mgmt::MemoryWrite {
    // TODO-correctness: Empirically this works fine, but not based on the spec.
    const SIZE: u8 = 64;

    fn build_one(page: mgmt::sff8636::Page, offset: u8, len: u8) -> Result<Self, Error> {
        Self::new(page, offset, len).map_err(Error::from)
    }
}

impl LargeMemoryAccess<mgmt::cmis::Page> for mgmt::MemoryRead {
    const SIZE: u8 = mgmt::cmis::Page::MAX_READ_SIZE;

    fn build_one(page: mgmt::cmis::Page, offset: u8, len: u8) -> Result<Self, Error> {
        Self::new(page, offset, len).map_err(Error::from)
    }
}

impl LargeMemoryAccess<mgmt::cmis::Page> for mgmt::MemoryWrite {
    const SIZE: u8 = mgmt::cmis::Page::MAX_WRITE_SIZE;

    fn build_one(page: mgmt::cmis::Page, offset: u8, len: u8) -> Result<Self, Error> {
        Self::new(page, offset, len).map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use transceiver_messages::mgmt::cmis::UpperPage;

    use super::mgmt;
    use super::LargeMemoryAccess;
    use super::MemoryPage;

    #[test]
    fn test_build_large_memory_access_even_split() {
        test_build_large_memory_access_even_split_impl::<mgmt::MemoryRead, mgmt::cmis::Page>(
            mgmt::cmis::Page::Lower,
        );
        test_build_large_memory_access_even_split_impl::<mgmt::MemoryWrite, mgmt::cmis::Page>(
            mgmt::cmis::Page::Lower,
        );
        test_build_large_memory_access_even_split_impl::<mgmt::MemoryRead, mgmt::sff8636::Page>(
            mgmt::sff8636::Page::Lower,
        );
        test_build_large_memory_access_even_split_impl::<mgmt::MemoryWrite, mgmt::sff8636::Page>(
            mgmt::sff8636::Page::Lower,
        );
    }

    fn test_build_large_memory_access_even_split_impl<T, P>(page: P)
    where
        T: LargeMemoryAccess<P>,
        P: MemoryPage,
        mgmt::Page: From<P>,
        mgmt::MemoryRead: LargeMemoryAccess<P>,
    {
        let offset = 0;
        let len = 64;
        let reads = mgmt::MemoryRead::build_many(page, offset, len)
            .expect("failed to build multiple accesses");
        assert_eq!(reads.len(), usize::from(len / T::SIZE));

        for (read, expected_offset) in reads.into_iter().zip((0..).step_by(T::SIZE as _)) {
            assert_eq!(read.offset(), expected_offset);
            assert_eq!(read.len(), T::SIZE);
            assert_eq!(read.page(), &mgmt::Page::from(page));
        }
    }

    #[test]
    fn test_build_large_memory_accessad_uneven_split() {
        test_build_large_memory_access_uneven_split_impl::<mgmt::MemoryRead, mgmt::cmis::Page>(
            mgmt::cmis::Page::Lower,
        );
        test_build_large_memory_access_uneven_split_impl::<mgmt::MemoryWrite, mgmt::cmis::Page>(
            mgmt::cmis::Page::Lower,
        );
        test_build_large_memory_access_uneven_split_impl::<mgmt::MemoryRead, mgmt::sff8636::Page>(
            mgmt::sff8636::Page::Lower,
        );
        test_build_large_memory_access_uneven_split_impl::<mgmt::MemoryWrite, mgmt::sff8636::Page>(
            mgmt::sff8636::Page::Lower,
        );
    }

    fn test_build_large_memory_access_uneven_split_impl<T, P>(page: P)
    where
        T: LargeMemoryAccess<P>,
        P: MemoryPage,
        mgmt::Page: From<P>,
        mgmt::MemoryRead: LargeMemoryAccess<P>,
    {
        let offset = 0;
        let len = 63;
        let reads = mgmt::MemoryRead::build_many(page, offset, len)
            .expect("failed to build multiple accesses");
        assert_eq!(reads.len(), usize::from(len / T::SIZE) + 1);

        for (i, (read, expected_offset)) in
            reads.iter().zip((0..).step_by(T::SIZE as _)).enumerate()
        {
            // The first N - 1 should be full reads, and the last exactly the
            // remaining bytes.
            let expected_len = if i < (reads.len() - 1) {
                T::SIZE
            } else {
                T::SIZE - 1
            };
            assert_eq!(read.offset(), expected_offset);
            assert_eq!(read.len(), expected_len);
            assert_eq!(read.page(), &mgmt::Page::from(page));
        }

        // The sum of all the sizes should be exactly the original length.
        assert_eq!(
            reads.iter().map(|read| read.len()).sum::<u8>(),
            len,
            "All reads need to sum to the full expected size",
        );
    }

    #[test]
    fn test_build_large_memory_access_at_boundary() {
        // test at 256
        test_build_large_memory_access_impl::<mgmt::MemoryRead, mgmt::cmis::Page>(
            mgmt::cmis::Page::Upper(UpperPage::new_unbanked(0).unwrap()), 192, 64
        );
        test_build_large_memory_access_impl::<mgmt::MemoryWrite, mgmt::cmis::Page>(
            mgmt::cmis::Page::Upper(UpperPage::new_unbanked(0).unwrap()), 192, 64
        );
        test_build_large_memory_access_impl::<mgmt::MemoryRead, mgmt::sff8636::Page>(
            mgmt::sff8636::Page::Upper(mgmt::sff8636::UpperPage::new(0).unwrap()), 192, 64
        );
        test_build_large_memory_access_impl::<mgmt::MemoryWrite, mgmt::sff8636::Page>(
            mgmt::sff8636::Page::Upper(mgmt::sff8636::UpperPage::new(0).unwrap()), 192, 64
        );
    }

    #[test]
    fn test_build_large_memory_access_exceeding_boundary() {
        // test at 256
        test_build_large_memory_access_impl::<mgmt::MemoryRead, mgmt::cmis::Page>(
            mgmt::cmis::Page::Upper(UpperPage::new_unbanked(0).unwrap()), 192, 65
        );
        test_build_large_memory_access_impl::<mgmt::MemoryWrite, mgmt::cmis::Page>(
            mgmt::cmis::Page::Upper(UpperPage::new_unbanked(0).unwrap()), 192, 65
        );
        test_build_large_memory_access_impl::<mgmt::MemoryRead, mgmt::sff8636::Page>(
            mgmt::sff8636::Page::Upper(mgmt::sff8636::UpperPage::new(0).unwrap()), 192, 65
        );
        test_build_large_memory_access_impl::<mgmt::MemoryWrite, mgmt::sff8636::Page>(
            mgmt::sff8636::Page::Upper(mgmt::sff8636::UpperPage::new(0).unwrap()), 192, 65
        );
    }

    fn test_build_large_memory_access_impl<T, P>(page: P, offset: u8, len: u8)
    where
        T: LargeMemoryAccess<P>,
        P: MemoryPage,
        mgmt::Page: From<P>,
        mgmt::MemoryRead: LargeMemoryAccess<P>,
    {
        let idx = offset as usize + len as usize;
        if idx <= 256 {
            let reads = mgmt::MemoryRead::build_many(page, offset, len)
                .expect("failed to build multiple accesses");
            assert_eq!(reads.len(), usize::from(len / T::SIZE));

            for (read, expected_offset) in reads.into_iter().zip((offset..).step_by(T::SIZE as _)) {
                assert_eq!(read.offset(), expected_offset);
                assert_eq!(read.len(), T::SIZE);
                assert_eq!(read.page(), &mgmt::Page::from(page));
            }
        } else {
            assert_eq!(true, mgmt::MemoryRead::build_many(page, offset, len).is_err())
        }
    }
}
