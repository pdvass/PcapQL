use std::fmt;

use crate::{network::igmp_types::describe, pcap::Cursor};

// Quick Reference:
// https://en.wikipedia.org/wiki/Internet_Group_Management_Protocol
// https://datatracker.ietf.org/doc/html/rfc3376 (IGMPv3)
pub enum IGMP<'a> {
    V1V2 {
        igmp_type: u8,
        max_resp_time: u8,
        checksum: u16,
        group_address: u32,
    },
    V3Query(IGMPv3Query),
    V3Report(IGMPv3Report<'a>),
}

pub struct IGMPv3Query {
    pub max_resp_time: u32, // decoded, tenths of a second
    pub checksum: u16,
    pub group_address: u32,
    pub suppress_router_side_processing: bool,
    pub qrv: u8,
    pub qqic: u32, // decoded, seconds
    pub sources: Vec<u32>,
}

pub struct IGMPv3Report<'a> {
    pub checksum: u16,
    pub group_records: Vec<GroupRecord<'a>>,
}

pub struct GroupRecord<'a> {
    pub record_type: u8,
    pub multicast_address: u32,
    pub sources: Vec<u32>,
    pub aux_data: &'a [u8],
}

impl<'a> fmt::Display for IGMP<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IGMP::V1V2 { igmp_type, .. } => write!(f, "{}", describe(*igmp_type)),
            IGMP::V3Query(_) => write!(f, "{}", describe(0x11)),
            IGMP::V3Report(_) => write!(f, "{}", describe(0x22)),
        }
    }
}

// RFC 3376 4.1.1 / 4.1.7: Max Resp Code and QQIC use the same "floating
// point" encoding. Values below 128 are the value itself; 128 and above
// pack an exponent/mantissa into the byte to represent a larger range.
fn decode_float_code(code: u8) -> u32 {
    if code < 128 {
        code as u32
    } else {
        let exp = (code >> 4) & 0b0111;
        let mant = (code & 0b0000_1111) as u32;
        (mant | 0x10) << (exp + 3)
    }
}

fn parse_v3_query(
    cur: &mut Cursor,
    max_resp_code: u8,
    checksum: u16,
    group_address: u32,
) -> IGMPv3Query {
    let s_qrv = cur.u8().unwrap();
    let suppress_router_side_processing = (s_qrv & 0b0000_1000) != 0;
    let qrv = s_qrv & 0b0000_0111;
    let qqic = cur.u8().unwrap();
    let num_sources = cur.u16_be().unwrap();

    let mut sources = Vec::with_capacity(num_sources as usize);
    for _ in 0..num_sources {
        sources.push(cur.u32_be().unwrap());
    }

    IGMPv3Query {
        max_resp_time: decode_float_code(max_resp_code),
        checksum,
        group_address,
        suppress_router_side_processing,
        qrv,
        qqic: decode_float_code(qqic),
        sources,
    }
}

fn parse_group_record<'a>(cur: &mut Cursor<'a>) -> GroupRecord<'a> {
    let record_type = cur.u8().unwrap();
    let aux_data_len = cur.u8().unwrap(); // in 32-bit words
    let num_sources = cur.u16_be().unwrap();
    let multicast_address = cur.u32_be().unwrap();

    let mut sources = Vec::with_capacity(num_sources as usize);
    for _ in 0..num_sources {
        sources.push(cur.u32_be().unwrap());
    }

    let aux_data = cur.bytes(aux_data_len as usize * 4).unwrap();

    GroupRecord {
        record_type,
        multicast_address,
        sources,
        aux_data,
    }
}

fn parse_v3_report<'a>(cur: &mut Cursor<'a>) -> IGMPv3Report<'a> {
    let _reserved = cur.u8().unwrap();
    let checksum = cur.u16_be().unwrap();
    let _reserved = cur.u16_be().unwrap();
    let num_group_records = cur.u16_be().unwrap();

    let mut group_records = Vec::with_capacity(num_group_records as usize);
    for _ in 0..num_group_records {
        group_records.push(parse_group_record(cur));
    }

    IGMPv3Report {
        checksum,
        group_records,
    }
}

pub(crate) fn parse_igmp<'a>(cur: &mut Cursor<'a>) -> IGMP<'a> {
    let igmp_type = cur.u8().unwrap();

    match igmp_type {
        0x22 => IGMP::V3Report(parse_v3_report(cur)),
        0x11 => {
            let max_resp_code = cur.u8().unwrap();
            let checksum = cur.u16_be().unwrap();
            let group_address = cur.u32_be().unwrap();

            if cur.has_remaining() {
                IGMP::V3Query(parse_v3_query(cur, max_resp_code, checksum, group_address))
            } else {
                IGMP::V1V2 {
                    igmp_type,
                    max_resp_time: max_resp_code,
                    checksum,
                    group_address,
                }
            }
        }
        0x12 | 0x16 | 0x17 => {
            let max_resp_time = cur.u8().unwrap();
            let checksum = cur.u16_be().unwrap();
            let group_address = cur.u32_be().unwrap();
            IGMP::V1V2 {
                igmp_type,
                max_resp_time,
                checksum,
                group_address,
            }
        }
        other => panic!("Unknown IGMP type {other}"),
    }
}
