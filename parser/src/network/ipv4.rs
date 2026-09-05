use crate::{
    layer::TransportPacket,
    network::icmpv4::parse_icmpv4,
    network::igmp::parse_igmp,
    pcap::Cursor,
    transport::{tcp::parse_tcp, udp::parse_udp},
};

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum Flag {
    Reserved = 0b000,
    DF = 0b010, // Don't Fragment
    MF = 0b001, // More Fragments
}

#[derive(Debug)]
pub enum Protocol {
    ICMP = 1,
    IGMP = 2,
    TCP = 6,
    UDP = 17,
    ENCAP = 41,
    OSPF = 89,
    SCTP = 132,
}

// Quick Reference:
// https://en.wikipedia.org/wiki/IPv4#Flags
pub struct IPv4Packet<'a> {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub id: u16,
    pub flag: Flag,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: Protocol,
    pub header_checksum: u16,
    pub source: u32,
    pub dest: u32,
    pub options: Vec<IpOption<'a>>,
    pub payload: TransportPacket<'a>,
}

// Quick Reference:
// https://en.wikipedia.org/wiki/IPv4#Options
#[derive(Debug)]
pub enum IpOption<'a> {
    EndOfList,
    NoOp,
    RecordRoute(&'a [u8]),
    Timestamp(&'a [u8]),
    StrictSourceRoute(&'a [u8]),
    LooseSourceRoute(&'a [u8]),
    Other { kind: u8, data: &'a [u8] },
}

fn parse_ip_options<'a>(mut data: &'a [u8]) -> Vec<IpOption<'a>> {
    let mut options = Vec::new();

    while !data.is_empty() {
        let kind = data[0];

        // Single-octet options: no length byte, no data.
        if kind == 0 {
            options.push(IpOption::EndOfList);
            break;
        }
        if kind == 1 {
            options.push(IpOption::NoOp);
            data = &data[1..];
            continue;
        }

        // Everything else is type-length-value, where length includes
        // the kind and length octets themselves.
        if data.len() < 2 {
            break;
        }
        let len = data[1] as usize;
        if len < 2 || len > data.len() {
            break;
        }
        let value = &data[2..len];

        let option = match kind {
            7 => IpOption::RecordRoute(value),
            68 => IpOption::Timestamp(value),
            131 => IpOption::LooseSourceRoute(value),
            137 => IpOption::StrictSourceRoute(value),
            other => IpOption::Other {
                kind: other,
                data: value,
            },
        };
        options.push(option);
        data = &data[len..];
    }

    options
}

pub(crate) fn parse_ipv4<'a>(cur: &mut Cursor<'a>) -> IPv4Packet<'a> {
    let version_ihl = cur.u8().unwrap();
    let version = version_ihl >> 4;
    let ihl = version_ihl & 0x0f; // If ihl > 5 there would be options.
    // Check: https://en.wikipedia.org/wiki/IPv4#Options

    let dscp_ecn = cur.u8().unwrap();
    let dscp = dscp_ecn >> 2;
    let ecn = dscp_ecn & 0b0000_0011;

    let total_length = cur.u16_be().unwrap();

    let id = cur.u16_be().unwrap();

    let flags_fragment_offset = cur.u16_be().unwrap();
    let flags_num: u8 = (flags_fragment_offset >> 13) as u8;
    let flag: Flag = match flags_num {
        0 => Flag::Reserved,
        1 => Flag::MF,
        2 => Flag::DF,
        other => panic!("Unknown flag {}", other),
    };
    let fragment_offset = flags_fragment_offset & 0b0001_1111_1111_1111;

    let ttl = cur.u8().unwrap();

    let protocol_num = cur.u8().unwrap();
    let protocol: Protocol = match protocol_num {
        1 => Protocol::ICMP,
        2 => Protocol::IGMP,
        6 => Protocol::TCP,
        17 => Protocol::UDP,
        41 => Protocol::ENCAP,
        89 => Protocol::OSPF,
        132 => Protocol::SCTP,
        other => panic!("Unknown protocol {}", other),
    };

    let header_checksum = cur.u16_be().unwrap();

    let source = cur.u32_be().unwrap();
    let dest = cur.u32_be().unwrap();

    let options_len = (ihl as usize * 4).saturating_sub(20);
    let options = if options_len > 0 {
        parse_ip_options(cur.bytes(options_len).unwrap())
    } else {
        Vec::new()
    };

    let header_len = ihl as usize * 4;
    let payload_len = if total_length == 0 {
        cur.remaining().len()
    } else {
        (total_length as usize).saturating_sub(header_len)
    };
    let mut payload_cur = Cursor::new(cur.bytes(payload_len).unwrap());

    let packet: TransportPacket = match protocol {
        Protocol::TCP => TransportPacket::TCP(parse_tcp(&mut payload_cur)),
        Protocol::UDP => TransportPacket::UDP(parse_udp(&mut payload_cur)),
        Protocol::ICMP => TransportPacket::ICMP(parse_icmpv4(&mut payload_cur)),
        Protocol::IGMP => TransportPacket::IGMP(parse_igmp(&mut payload_cur)),
        other => panic!("Add support for {:#?}", other),
    };

    IPv4Packet {
        version,
        ihl,
        dscp,
        ecn,
        total_length,
        id,
        flag,
        fragment_offset,
        ttl,
        protocol,
        header_checksum,
        source,
        dest,
        options,
        payload: packet,
    }
}
