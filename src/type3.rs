/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! Type3 parser
use core::borrow::Borrow;

use nom::{
    bytes::streaming::{tag, take},
    combinator::consumed,
    number::streaming::{be_u16, u8},
    sequence::tuple,
    Finish, IResult,
};

use crate::{map_err, Error, FLAG};

#[derive(Debug, PartialEq, Eq)]
pub struct HdlcFrame<'a> {
    pub src_addr: HdlcAddress,
    pub dest_addr: HdlcAddress,
    pub information: &'a [u8],
    pub control: u8,
    pub segmented: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct HdlcAddress {
    pub upper: u16,
    pub lower: Option<u16>,
}

fn parse_frame_start<'a>(input: &'a [u8]) -> Result<(&'a [u8], &[u8]), nom::Err<Error>> {
    map_err(tag([FLAG])(input), Error::InvalidStartCharacter)
}

fn parse_frame_length<'a>(input: &'a [u8]) -> Result<(&'a [u8], (u16, bool)), nom::Err<Error>> {
    let (input, value) = map_err(be_u16(input), Error::InvalidFormat)?;
    if (value & 0xF000) != 0xA000 {
        return Err(nom::Err::Error(Error::InvalidFormat));
    }
    Ok((input, (value & 0x7FF, value & 0x800 != 0)))
}

fn check_extended(value: u8) -> bool {
    value & 0x01 != 0
}

fn parse_address<'a>(input: &'a [u8]) -> Result<(&'a [u8], HdlcAddress), nom::Err<Error>> {
    let (input, value) = map_err(u8(input), Error::InvalidAddress)?;
    let mut upper = (value >> 1) as u16;
    if check_extended(value) {
        return Ok((input, HdlcAddress { upper, lower: None }));
    }
    let (input, value) = map_err(u8(input), Error::InvalidAddress)?;
    let lower = (value >> 1) as u16;
    if check_extended(value) {
        return Ok((
            input,
            HdlcAddress {
                upper,
                lower: Some(lower),
            },
        ));
    }
    upper = (upper << 7) + lower;
    let (input, (high, low)) = map_err(tuple((u8, u8))(input), Error::InvalidAddress)?;
    if check_extended(high) || !check_extended(low) {
        Err(nom::Err::Error(Error::InvalidAddress))
    } else {
        Ok((
            input,
            HdlcAddress {
                upper,
                lower: Some(((high as u16 & 0xFE) << 6) + (low as u16 >> 1)),
            },
        ))
    }
}

fn parse_header<'a>(
    input: &'a [u8],
) -> Result<(&'a [u8], (u16, bool, HdlcAddress, HdlcAddress, u8)), nom::Err<Error>> {
    let (input, (length, segmented)) = parse_frame_length(input)?;
    let (input, dest_addr) = parse_address(input)?;
    let (input, src_addr) = parse_address(input)?;
    let (input, control) = map_err(u8(input), Error::InvalidFormat)?;
    Ok((input, (length, segmented, dest_addr, src_addr, control)))
}

impl<'a> HdlcFrame<'a> {
    fn parse_without_fcs(input: &'a [u8]) -> IResult<&'a [u8], Self, Error> {
        let (input, (header, (length, segmented, dest_addr, src_addr, control))) =
            consumed(parse_header)(input)?;
        let (input, hcs) = map_err(be_u16(input), Error::InvalidFormat)?;
        let (input, information) = if length as usize - header.len() == 1 {
            (input, &[] as &[u8])
        } else {
            if hcs != calculate_fcs(header) {
                return Err(nom::Err::Error(Error::InvalidChecksum));
            }
            let information_length = length as usize - header.len() - 4;
            take(information_length)(input)?
        };
        Ok((
            input,
            HdlcFrame {
                dest_addr,
                src_addr,
                information,
                control,
                segmented,
            },
        ))
    }

    fn parse_nom(input: &'a [u8]) -> IResult<&'a [u8], Self, Error> {
        let (input, _) = parse_frame_start(input)?;
        let (input, (frame, hdlc_frame)) = consumed(Self::parse_without_fcs)(input)?;
        let (input, fcs) = be_u16(input)?;
        if fcs != calculate_fcs(frame) {
            Err(nom::Err::Error(Error::InvalidChecksum))
        } else {
            Ok((input, hdlc_frame))
        }
    }
    /// Parse one HDLC frame from `input`. On success returns the remaining input and the `HdlcFrame`
    pub fn parse(input: &'a [u8]) -> Result<(&'a [u8], Self), Error> {
        Self::parse_nom(input)
            .map_err(|err| match err {
                nom::Err::Incomplete(needed) => {
                    nom::Err::Failure(Error::Incomplete(match needed {
                        nom::Needed::Unknown => None,
                        nom::Needed::Size(size) => Some(size),
                    }))
                }
                err => err,
            })
            .finish()
    }
}

const FCS_TABLE: [u16; 256] = [
    0x0000, 0x1189, 0x2312, 0x329B, 0x4624, 0x57AD, 0x6536, 0x74BF, 0x8C48, 0x9DC1, 0xAF5A, 0xBED3,
    0xCA6C, 0xDBE5, 0xE97E, 0xF8F7, 0x1081, 0x0108, 0x3393, 0x221A, 0x56A5, 0x472C, 0x75B7, 0x643E,
    0x9CC9, 0x8D40, 0xBFDB, 0xAE52, 0xDAED, 0xCB64, 0xF9FF, 0xE876, 0x2102, 0x308B, 0x0210, 0x1399,
    0x6726, 0x76AF, 0x4434, 0x55BD, 0xAD4A, 0xBCC3, 0x8E58, 0x9FD1, 0xEB6E, 0xFAE7, 0xC87C, 0xD9F5,
    0x3183, 0x200A, 0x1291, 0x0318, 0x77A7, 0x662E, 0x54B5, 0x453C, 0xBDCB, 0xAC42, 0x9ED9, 0x8F50,
    0xFBEF, 0xEA66, 0xD8FD, 0xC974, 0x4204, 0x538D, 0x6116, 0x709F, 0x0420, 0x15A9, 0x2732, 0x36BB,
    0xCE4C, 0xDFC5, 0xED5E, 0xFCD7, 0x8868, 0x99E1, 0xAB7A, 0xBAF3, 0x5285, 0x430C, 0x7197, 0x601E,
    0x14A1, 0x0528, 0x37B3, 0x263A, 0xDECD, 0xCF44, 0xFDDF, 0xEC56, 0x98E9, 0x8960, 0xBBFB, 0xAA72,
    0x6306, 0x728F, 0x4014, 0x519D, 0x2522, 0x34AB, 0x0630, 0x17B9, 0xEF4E, 0xFEC7, 0xCC5C, 0xDDD5,
    0xA96A, 0xB8E3, 0x8A78, 0x9BF1, 0x7387, 0x620E, 0x5095, 0x411C, 0x35A3, 0x242A, 0x16B1, 0x0738,
    0xFFCF, 0xEE46, 0xDCDD, 0xCD54, 0xB9EB, 0xA862, 0x9AF9, 0x8B70, 0x8408, 0x9581, 0xA71A, 0xB693,
    0xC22C, 0xD3A5, 0xE13E, 0xF0B7, 0x0840, 0x19C9, 0x2B52, 0x3ADB, 0x4E64, 0x5FED, 0x6D76, 0x7CFF,
    0x9489, 0x8500, 0xB79B, 0xA612, 0xD2AD, 0xC324, 0xF1BF, 0xE036, 0x18C1, 0x0948, 0x3BD3, 0x2A5A,
    0x5EE5, 0x4F6C, 0x7DF7, 0x6C7E, 0xA50A, 0xB483, 0x8618, 0x9791, 0xE32E, 0xF2A7, 0xC03C, 0xD1B5,
    0x2942, 0x38CB, 0x0A50, 0x1BD9, 0x6F66, 0x7EEF, 0x4C74, 0x5DFD, 0xB58B, 0xA402, 0x9699, 0x8710,
    0xF3AF, 0xE226, 0xD0BD, 0xC134, 0x39C3, 0x284A, 0x1AD1, 0x0B58, 0x7FE7, 0x6E6E, 0x5CF5, 0x4D7C,
    0xC60C, 0xD785, 0xE51E, 0xF497, 0x8028, 0x91A1, 0xA33A, 0xB2B3, 0x4A44, 0x5BCD, 0x6956, 0x78DF,
    0x0C60, 0x1DE9, 0x2F72, 0x3EFB, 0xD68D, 0xC704, 0xF59F, 0xE416, 0x90A9, 0x8120, 0xB3BB, 0xA232,
    0x5AC5, 0x4B4C, 0x79D7, 0x685E, 0x1CE1, 0x0D68, 0x3FF3, 0x2E7A, 0xE70E, 0xF687, 0xC41C, 0xD595,
    0xA12A, 0xB0A3, 0x8238, 0x93B1, 0x6B46, 0x7ACF, 0x4854, 0x59DD, 0x2D62, 0x3CEB, 0x0E70, 0x1FF9,
    0xF78F, 0xE606, 0xD49D, 0xC514, 0xB1AB, 0xA022, 0x92B9, 0x8330, 0x7BC7, 0x6A4E, 0x58D5, 0x495C,
    0x3DE3, 0x2C6A, 0x1EF1, 0x0F78,
];

fn calculate_fcs(input: &[u8]) -> u16 {
    let mut fcs: u16 = 0xFFFF;
    for ch in input {
        fcs = (fcs >> 8) ^ FCS_TABLE[(fcs as u8 ^ *ch) as usize];
    }
    fcs = !fcs;
    fcs = (fcs >> 8) | (fcs << 8);
    return fcs;
}

impl<'i> Borrow<[u8]> for HdlcFrame<'i> {
    fn borrow(&self) -> &[u8] {
        &self.information
    }
}

#[cfg(test)]
mod test {
    use core::fmt;

    use crate::{
        type3::{calculate_fcs, parse_address, parse_frame_length, HdlcAddress, HdlcFrame},
        Error,
    };

    const DEMO_FRAME: [u8; 123] = [
        0x7E, 0xA0, 0x79, 0xCF, 0x00, 0x02, 0x00, 0x23, 0x13, 0xD9, 0x86, 0xE6, 0xE7, 0x00, 0xDB,
        0x08, 0x53, 0x4D, 0x53, 0x67, 0x70, 0x0A, 0x0F, 0x82, 0x5F, 0x20, 0x00, 0x00, 0x40, 0x24,
        0x2D, 0xC2, 0xD5, 0xB1, 0x14, 0x75, 0x7B, 0x32, 0x1D, 0x87, 0x86, 0x1E, 0xD1, 0x3E, 0xDF,
        0xC0, 0x03, 0xBF, 0x04, 0x4B, 0x87, 0xE1, 0x5F, 0xC6, 0xC8, 0xE1, 0x3F, 0xD8, 0x56, 0x40,
        0xC4, 0x8D, 0xB9, 0x3B, 0xF4, 0x5F, 0x29, 0xF7, 0x76, 0xAF, 0x5D, 0x94, 0x98, 0x4B, 0x34,
        0x6E, 0x3C, 0x2D, 0xED, 0xC4, 0xDF, 0x0C, 0x9F, 0x7B, 0x86, 0x0D, 0x81, 0x16, 0x0E, 0x0F,
        0x07, 0x02, 0xBB, 0x6B, 0xCC, 0x5E, 0xA7, 0xE4, 0x34, 0x74, 0x5D, 0x82, 0xBE, 0x8A, 0xAD,
        0xF9, 0x1F, 0xB0, 0x29, 0xEA, 0x44, 0x0B, 0x07, 0x65, 0xDF, 0x90, 0x70, 0xF1, 0xC1, 0x40,
        0x8A, 0x00, 0x7E,
    ];

    #[test]
    fn test_parse_address() {
        let one_byte: [u8; 1] = [0x75];
        let two_bytes: [u8; 2] = [0x74, 0xFF];
        let four_bytes: [u8; 4] = [0x48, 0x68, 0xFE, 0xFF];
        full_parse(
            parse_address(&one_byte),
            HdlcAddress {
                upper: 0x3A,
                lower: None,
            },
        );
        full_parse(
            parse_address(&two_bytes),
            HdlcAddress {
                upper: 0x3A,
                lower: Some(0x7F),
            },
        );
        full_parse(
            parse_address(&four_bytes),
            HdlcAddress {
                upper: 0x1234,
                lower: Some(0x3FFF),
            },
        )
    }

    #[test]
    fn test_parse_frame_length() {
        let valid_length: [u8; 2] = [0xA6, 0x37];
        let invalid_frame_type: [u8; 2] = [0xB0, 0x13];
        full_parse(parse_frame_length(&valid_length), (0x637, false));
        assert_eq!(
            parse_frame_length(&invalid_frame_type),
            Err(nom::Err::Error(Error::InvalidFormat))
        );
    }

    #[test]
    fn test_parse() {
        let frame: [u8; 33] = [
            0x7E, 0xA0, 0x20, 0x76, 0x54, 0xAE, 0x1B, 0x46, 0xA9, 0x13, 0x2F, 0x2F, /*HCS*/
            0xE6, 0xE6, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
            0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x4E, 0x66, /*FCS*/
        ];
        let data: [u8; 19] = [
            0xE6, 0xE6, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
            0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        ];
        let expected = HdlcFrame {
            dest_addr: HdlcAddress {
                upper: 0x1DAA,
                lower: Some(0x2B8D),
            },
            src_addr: HdlcAddress {
                upper: 0x23,
                lower: Some(0x54),
            },
            control: 0x13,
            information: &data,
            segmented: false,
        };
        full_parse(HdlcFrame::parse(&frame), expected);
        let demo_frame = HdlcFrame::parse(&DEMO_FRAME);
        assert!(demo_frame.is_ok())
    }

    #[test]
    fn test_fcs16() {
        let data: [u8; 8] = [0xA0, 0x79, 0xCF, 0x00, 0x02, 0x00, 0x23, 0x13];
        assert_eq!(calculate_fcs(&data), 55686);
        assert_eq!(calculate_fcs(&DEMO_FRAME[1..120]), 0x8A00);
    }

    fn full_parse<'a, T: fmt::Debug + Eq, E: fmt::Debug>(
        result: Result<(&'a [u8], T), E>,
        expected: T,
    ) {
        let (input, value) = result.expect("Expected successful parse");
        assert!(input.len() == 0);
        assert_eq!(value, expected);
    }
}
