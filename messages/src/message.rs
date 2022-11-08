// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Message formats and definitions.

use super::Error;
use super::ModuleId;
use hubpack::SerializedSize;
use serde::Deserialize;
use serde::Serialize;

pub mod version {
    pub const V1: u8 = 1;
}

/// A common header to all messages between host and SP.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize, SerializedSize)]
pub struct Header {
    /// The protocol version.
    pub version: u8,
    /// An arbitrary message ID, shared between a request and its response.
    pub message_id: u64,
}

/// A message from either the host or SP.
///
/// All messages share a common [`Header`] and reference a set of QSFP modules
/// on on a Sidecar. For messages which contain variable length data, such as a
/// [`HostRequest::Write`] or [`SpResponse::Read`], the data is contained in the
/// UDP packet, following the `Message` itself.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize, SerializedSize)]
pub struct Message {
    pub header: Header,
    pub modules: ModuleId,
    pub body: MessageBody,
}

/// The body of a message between host and SP.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize, SerializedSize)]
pub enum MessageBody {
    HostRequest(HostRequest),
    HostResponse(HostResponse),
    SpRequest(SpRequest),
    SpResponse(SpResponse),
}

/// A request from the host to the SP.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize, SerializedSize)]
pub enum HostRequest {
    /// Request to read a region of the QSFP memory map.
    Read(MemoryRegion),
    /// Request to write to a region of the QSFP memory map.
    ///
    /// The data to be written is contained in the remainder of the UDP packet.
    Write(MemoryRegion),
    /// Request to return the status of the QSFP modules.
    Status,
    /// Request that the modules be reset.
    Reset,
}

/// A description of a region of the QSFP memory map.
///
/// The QSFP spec, defined in SFF-8636, describes the memory map that all
/// free-side transceiver modules must implement. It's constrained to 256 bytes
/// in total, split into lower and upper 128-byte pages. The lower page is
/// fixed, while the upper page maybe swapped out to refer to extended sections
/// of memory. The upper page to be selected is defined in byte 127 of the lower
/// page.
///
/// All operations through this protocol must define the upper page on which
/// they're operating. Since multiple clients may set the page-select byte
/// independently from one another, clients must explicitly describe which page
/// they're interested in. The SP side ensures that the correct page is selected
/// for the resulting memory operation.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize, SerializedSize)]
pub struct MemoryRegion {
    page: u8,
    offset: u8,
    len: u8,
}

impl MemoryRegion {
    /// Construct a new memory region.
    ///
    /// The `page` must be one of the valid pages for the QSFP spec. See
    /// SFF-8636, revision 2.10a, section 6.1 for the list of acceptable pages.
    /// Note that the requested page may not actually be supported by a
    /// free-side module; that is, you may be able to _construct_ a
    /// `MemoryRegion`, but a request to address that memory on a specific QSFP
    /// module may fail.
    ///
    /// The `offset` and len` are required to address memory entirely within the
    /// 256 bytes of the QSFP memory map.
    pub fn new(page: u8, offset: u8, len: u8) -> Result<Self, Error> {
        if !is_valid_page(page) {
            return Err(Error::InvalidQsfpPage(page));
        }

        // The last accessed byte must be within the 256-byte memory map.
        if offset.checked_add(len).is_none() {
            return Err(Error::InvalidMemoryAccess { page, offset, len });
        }

        // TODO-correctness: Whether / how to handle zero-byte accesses?
        Ok(Self { page, offset, len })
    }

    /// Return the ID of the upper memory page to be paged in for the operation.
    pub fn page(&self) -> u8 {
        self.page
    }

    /// Return the offset into the QSFP memory map for the operation.
    pub fn offset(&self) -> u8 {
        self.offset
    }

    /// Return the length of QSFP memory for the operation.
    pub fn len(&self) -> u8 {
        self.len
    }
}

/// A response to a host request, sent from SP to host.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize, SerializedSize)]
pub enum HostResponse {
    /// The request failed.
    Error(Error),
    /// The result of a read operation.
    ///
    /// The actual data read from the QSFP modules is contained in the remaining
    /// bytes of the UDP packet.
    Read(MemoryRegion),
    /// The result of a write operation.
    Write(MemoryRegion),
    /// The status of a set of QSFP modules.
    ///
    /// Each module may have a different set of status flags set. The
    /// [`Message`] type contains the mask identifying all the modules, and the
    /// remaining bytes of the UDP packet are a list of [`Status`] objects for
    /// each module specified.
    ///
    /// The ordering of the status objects is from lowest index to highest --
    /// that is, taking the output of the returned `ModuleId::to_indices()`
    /// method.
    Status,
    /// A successful response to a reset request.
    Reset,
}

/// A request from the SP to the host.
//
// TODO-implement
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize, SerializedSize)]
pub enum SpRequest {}

/// A response to a SP request, sent from host to SP.
//
// TODO-implement
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize, SerializedSize)]
pub enum SpResponse {}

// See SFF-8636, revision 2.10a, section 6.1.
const fn is_valid_page(page: u8) -> bool {
    match page {
        // Required and optional status / monitoring pages.
        0x00 | 0x01 | 0x02 | 0x03 => true,
        // Additional monitoring parameters.
        0x20 | 0x21 => true,
        // Vendor-specific functions.
        0x04..=0x7F => true,
        // Everything else is reserved.
        _ => false,
    }
}

bitflags::bitflags! {
    /// The status of a single transceiver module.
    #[derive(Deserialize, Serialize, SerializedSize)]
    pub struct Status: u8 {
        /// The module is present in the receptable.
        ///
        /// This translates to the `ModPrsL` pin in SFF-8679 rev 1.8 section
        /// 5.3.4.
        const PRESENT           = 0b0000_0001;

        /// The module's power is enabled.
        ///
        /// Note that this is not part of the QSFP specification, but provided
        /// by the Sidecar board design itself.
        const ENABLED           = 0b0000_0010;

        /// The module is held in reset.
        ///
        /// This translates to the `ResetL` pin in SFF-8679 rev 1.8 section
        /// 5.3.2.
        const RESET             = 0b0000_0100;

        /// The module is held in low-power mode.
        ///
        /// This translates to the `ResetL` pin in SFF-8679 rev 1.8 section
        /// 5.3.3.
        const LOW_POWER_MODE    = 0b0000_1000;

        /// At least one interrupt is signaled on the module. The details of the
        /// interrupt cause can be queried by reading various bytes of the QSFP
        /// memory map, such as bytes 3-21 in the lower memory page. See
        /// SFF-8636 rev 2.10a section 6.2.3 for details.
        ///
        /// This translates to the `IntL` pin in SFF-8679 rev 1.8 section
        /// 5.3.5.
        const INTERRUPT         = 0b0001_0000;
    }
}

#[cfg(test)]
mod tests {
    use super::is_valid_page;
    use super::Error;
    use super::MemoryRegion;

    #[test]
    fn test_is_valid_page() {
        assert!(is_valid_page(0));
        assert!(!is_valid_page(0x80));
    }

    #[test]
    fn test_memory_region() {
        let _ = MemoryRegion::new(0, 0, 10);
        assert_eq!(
            MemoryRegion::new(0x80, 0, 10).unwrap_err(),
            Error::InvalidQsfpPage(0x80)
        );
        // Would read past map end.
        assert!(matches!(
            MemoryRegion::new(0x00, 1, 255).unwrap_err(),
            Error::InvalidMemoryAccess { .. }
        ));
        assert!(matches!(
            MemoryRegion::new(0x00, 255, 1).unwrap_err(),
            Error::InvalidMemoryAccess { .. }
        ));
    }
}
