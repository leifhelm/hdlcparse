/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_debug_implementations)]

use core::{fmt, num::NonZeroUsize};

use nom::error::ParseError;

pub mod type3;

const FLAG: u8 = 0x7E;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidStartCharacter,
    InvalidFormat,
    InvalidAddress,
    InvalidChecksum,
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
