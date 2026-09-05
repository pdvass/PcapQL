use std::fmt;

use crate::pcap::Cursor;

#[derive(Debug)]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy)]
pub enum TSecs {
    Micro,
    Nano,
}

#[derive(Debug)]
pub struct Header {
    pub endian: Option<Endianness>,
    pub tsec: Option<TSecs>,
    pub major_version: u16,
    pub minor_version: u16,
    pub snap_len: u32,
    pub fcs: u8,
    pub p: u8,
    pub r: u8,
    pub link_type: u16,
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Header's Version {}.{}\nIt's SnapLen is {}.\nFCS: {} | R: {} | P: {}\nIt has a LinkType of {}",
            self.major_version,
            self.minor_version,
            self.snap_len,
            self.fcs,
            self.r,
            self.p,
            self.link_type
        )
    }
}
//
// The RFC says
// 0xA1,0xB2,0xC3,0xD4: little endian file, with timestamps in seconds/microseconds.
// 0x1A,0x2B,0x3C,0x4D: little endian file, with timestamps in seconds/nanoseconds.
// 0xD4,0xC3,0xB2,0xA1: big endian file, with timestamps in seconds/microseconds.
// 0x4D,0x3C,0x2B,0x1A: big endian file, with timestamps in seconds/nanoseconds.
fn detect(magic_word: &[u8]) -> Option<(Endianness, TSecs)> {
    match magic_word {
        [0xD4, 0xC3, 0xB2, 0xA1] => Some((Endianness::Little, TSecs::Micro)),
        [0x4D, 0x3C, 0xB2, 0xA1] => Some((Endianness::Little, TSecs::Nano)),
        [0xA1, 0xB2, 0xC3, 0xD4] => Some((Endianness::Big, TSecs::Micro)),
        [0xA1, 0xB2, 0x3C, 0x4D] => Some((Endianness::Big, TSecs::Nano)),
        _ => None,
    }
}

pub(crate) fn parse_header(header_bytes: &mut Cursor) -> Header {
    let magic_bytes = header_bytes.bytes(4).unwrap();

    let magic_number =
        detect(magic_bytes).unwrap_or_else(|| panic!("Unknown magic number {:02x?}", &magic_bytes));

    header_bytes.set_endianness(&magic_number.0);

    let major_version = header_bytes.u16().unwrap();
    let minor_version = header_bytes.u16().unwrap();
    let reserved = header_bytes.u64().unwrap();
    // Indicates the maximum number of octets captured from each packet.
    // If no limit was specified, the value SHOULD be a number greater than
    // or equal to the largest packet length in the file.
    // Source: https://ietf-opsawg-wg.github.io/draft-ietf-opsawg-pcap/draft-ietf-opsawg-pcap.html
    let snap_len = header_bytes.u32().unwrap();

    // Read the whole 4 byte chunk to avoid endian - bit manip shenanigans.
    let link_type_plus_info = header_bytes.u32().unwrap();
    let fcs = (link_type_plus_info >> 29) & 0b111;
    let p = (link_type_plus_info >> 28) & 0b1;
    let r = (link_type_plus_info >> 16) & 0x0FFF;
    let link_type = (link_type_plus_info & 0x0000_FFFF) as u16;

    if reserved != 0 {
        panic!("Reserved 1 and Reserved 2 should be 0");
    }

    if r != 0 || (fcs != 0 && p == 0) {
        panic!(
            "R {} must be 0 and if P {} is 0 then so must fcs {} be",
            r, p, fcs
        );
    }

    Header {
        endian: Some(magic_number.0),
        tsec: Some(magic_number.1),
        major_version,
        minor_version,
        snap_len,
        fcs: (fcs as u8),
        p: (p as u8),
        r: (r as u8),
        link_type,
    }
}
