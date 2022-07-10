#[derive(Debug)]
pub struct Llc {
    pub dest_sap: u8,
    pub src_sap: u8,
    pub control: u8,
}

pub fn parse_llc<'a>(input: &'a [u8]) -> Option<(&'a [u8], Llc)> {
    if input.len() >= 2 {
        Some((
            &input[3..],
            Llc {
                dest_sap: input[0],
                src_sap: input[1],
                control: input[2],
            },
        ))
    } else {
        None
    }
}
