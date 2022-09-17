/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! This module can be used to parse HDLC frames.
//! # Example
//! ```
//! use hdlcparse::type3::{HdlcAddress, HdlcFrame};
//!
//! let frame: [u8; 33] = [
//!    0x7E, 0xA0, 0x20, 0x76, 0x54, 0xAE, 0x1B, 0x46, 0xA9, 0x13, 0x2F, 0x2F, /*HCS*/
//!    0xE6, 0xE6, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
//!    0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x4E, 0x66, /*FCS*/
//! ];
//! // parse the frame
//! let hdlc_frame = HdlcFrame::parse(&frame).unwrap();
//! // check the destination address
//! assert_eq!(
//!     hdlc_frame.1.dest_addr,
//!     HdlcAddress {
//!         upper: 0x1DAA,
//!         lower: Some(0x2B8D),
//!     }
//! );
//! ```
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_debug_implementations)]

use core::{fmt, num::NonZeroUsize};

use nom::error::ParseError;

pub mod type3;

const FLAG: u8 = 0x7E;

/// Error used to indicate failed `parse` attempt
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Indicates that the start character `0x7E` was not the first character
    InvalidStartCharacter,
    /// This Error is used when the header is not fully present or the length is wrong
    InvalidFormat,
    /// Used to indicate an invalid address
    InvalidAddress,
    /// Used when the checksum of the frame is not as expected
    InvalidChecksum,
    /// Used to indicate that more bytes are needed to fully parse the frame
    Incomplete(Option<NonZeroUsize>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidStartCharacter => write!(f, "invalid start character"),
            Error::InvalidFormat => write!(f, "invalid format"),
            Error::InvalidAddress => write!(f, "invalid address"),
            Error::InvalidChecksum => write!(f, "invalid checksum"),
            Error::Incomplete(_) => write!(f, "incomplete"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl<I> ParseError<I> for Error {
    fn from_error_kind(_input: I, _kind: nom::error::ErrorKind) -> Self {
        Error::InvalidFormat
    }

    fn append(_input: I, _kind: nom::error::ErrorKind, other: Self) -> Self {
        other
    }
}

fn map_err<'a, T>(
    result: Result<(&'a [u8], T), nom::Err<nom::error::Error<&[u8]>>>,
    error: Error,
) -> Result<(&'a [u8], T), nom::Err<Error>> {
    result.map_err(|err| err.map(|_| error))
}
