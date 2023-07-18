// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Decode various transceiver module memory maps and data.

mod ident;
mod memory_model;
mod monitors;
mod performance;
mod power;

pub use ident::*;
pub use memory_model::*;
pub use monitors::*;
pub use performance::*;
pub use power::*;

pub use transceiver_messages::mgmt::Error as MgmtError;
pub use transceiver_messages::mgmt::ManagementInterface;
use transceiver_messages::mgmt::MemoryRead;

/// An error related to decoding a transceiver memory map.
#[derive(Clone, Copy, Debug, PartialEq, thiserror::Error)]
pub enum Error {
    #[error("Unsupported SFF-8024 Identifier: '{0}'")]
    UnsupportedIdentifier(Identifier),

    #[error("Management error")]
    Management(#[from] MgmtError),

    #[error("Memory map parsing failed")]
    ParseFailed,

    #[error("Invalid OUI")]
    InvalidOui,
}

/// A trait used to read and parse data from a transceiver memory map.
///
/// There are many kinds of transceivers, and although they often include the
/// same data, the location of that data in the memory map can be different.
/// This trait provides a way to issue a set of reads from a module's map, and
/// parse the result into a type.
pub trait ParseFromModule: Sized {
    /// The set of memory reads required to parse the data.
    fn reads(id: Identifier) -> Result<Vec<MemoryRead>, Error>;

    /// Parse the result of the above reads into `Self`.
    fn parse<'a>(id: Identifier, reads: impl Iterator<Item = &'a [u8]>) -> Result<Self, Error>;
}
