use crate::{
    layer::TransportPacket,
    network::icmpv6::parse_icmpv6,
    pcap::Cursor,
    transport::{tcp::parse_tcp, udp::parse_udp},
};

pub struct IPv6PacketHeader {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_len: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub source: u128,
    pub dest: u128,
}

// Quick Reference
// https://www.geeksforgeeks.org/computer-networks/internet-protocol-version-6-ipv6-header/
// https://en.wikipedia.org/wiki/IPv6_packet#Extension_headers
pub enum ExtensionHeader<'a> {
    HopByHopOptions {
        next_header: u8,
        data: &'a [u8],
    },
    DestOptions {
        next_header: u8,
        data: &'a [u8],
    },
    RoutingHeader {
        next_header: u8,
        data: &'a [u8],
    },
    FragmentHeader {
        next_header: u8,
        fragment_offset: u16,
        more_fragments: bool,
        identification: u32,
    },
    AuthHeader {
        next_header: u8,
        data: &'a [u8],
    },
    MobilityHeader {
        next_header: u8,
        data: &'a [u8],
    },
}

pub struct IPv6Packet<'a> {
    pub header: IPv6PacketHeader,
    pub extension_headers: Vec<ExtensionHeader<'a>>,
    pub payload: TransportPacket<'a>,
}

fn parse_ipv6_header(cur: &mut Cursor) -> IPv6PacketHeader {
    let first_line = cur.u32_be().unwrap();
    let version = (first_line >> 28) as u8;
    let traffic_class = ((first_line >> 20) & 0xFF) as u8;
    let flow_label = first_line & 0x000F_FFFF;

    let payload_len = cur.u16_be().unwrap();
    let next_header = cur.u8().unwrap();
    let hop_limit = cur.u8().unwrap();
    let source = cur.u128_be().unwrap();
    let dest = cur.u128_be().unwrap();

    IPv6PacketHeader {
        version,
        traffic_class,
        flow_label,
        payload_len,
        next_header,
        hop_limit,
        source,
        dest,
    }
}

// Shared shape for Hop-by-Hop, Destination Options, Routing and Mobility
// headers: next_header (1 byte), hdr_ext_len (1 byte, in 8-octet units not
// counting the first 8 octets), then the rest of the header.
fn parse_generic_extension_header<'a>(cur: &mut Cursor<'a>) -> (u8, &'a [u8]) {
    let next_header = cur.u8().unwrap();
    let hdr_ext_len = cur.u8().unwrap();
    let total_len = (hdr_ext_len as usize + 1) * 8;
    let data = cur.bytes(total_len - 2).unwrap();
    (next_header, data)
}

// AH uses its own length unit: 4-octet units, minus 2 (RFC 4302), unlike
// the other extension headers' 8-octet-units-minus-1.
fn parse_auth_header<'a>(cur: &mut Cursor<'a>) -> (u8, &'a [u8]) {
    let next_header = cur.u8().unwrap();
    let payload_len = cur.u8().unwrap();
    let total_len = (payload_len as usize + 2) * 4;
    let data = cur.bytes(total_len - 2).unwrap();
    (next_header, data)
}

// Fragment header has no length field at all: it's always a fixed 8 bytes.
fn parse_fragment_header(cur: &mut Cursor) -> ExtensionHeader<'static> {
    let next_header = cur.u8().unwrap();
    let _reserved = cur.u8().unwrap();
    let offset_res_m = cur.u16_be().unwrap();
    let fragment_offset = offset_res_m >> 3;
    let more_fragments = (offset_res_m & 0b1) != 0;
    let identification = cur.u32_be().unwrap();

    ExtensionHeader::FragmentHeader {
        next_header,
        fragment_offset,
        more_fragments,
        identification,
    }
}

pub(crate) fn parse_ipv6<'a>(cur: &mut Cursor<'a>) -> IPv6Packet<'a> {
    let header = parse_ipv6_header(cur);

    let mut extension_headers = Vec::new();
    let mut next_header = header.next_header;

    // Loop until we hit a value that isn't an extension header number at all.
    loop {
        match next_header {
            0 => {
                let (nh, data) = parse_generic_extension_header(cur);
                extension_headers.push(ExtensionHeader::HopByHopOptions {
                    next_header: nh,
                    data,
                });
                next_header = nh;
            }
            60 => {
                let (nh, data) = parse_generic_extension_header(cur);
                extension_headers.push(ExtensionHeader::DestOptions {
                    next_header: nh,
                    data,
                });
                next_header = nh;
            }
            43 => {
                let (nh, data) = parse_generic_extension_header(cur);
                extension_headers.push(ExtensionHeader::RoutingHeader {
                    next_header: nh,
                    data,
                });
                next_header = nh;
            }
            135 => {
                let (nh, data) = parse_generic_extension_header(cur);
                extension_headers.push(ExtensionHeader::MobilityHeader {
                    next_header: nh,
                    data,
                });
                next_header = nh;
            }
            51 => {
                let (nh, data) = parse_auth_header(cur);
                extension_headers.push(ExtensionHeader::AuthHeader {
                    next_header: nh,
                    data,
                });
                next_header = nh;
            }
            44 => {
                let fragment = parse_fragment_header(cur);
                next_header = match &fragment {
                    ExtensionHeader::FragmentHeader { next_header, .. } => *next_header,
                    _ => unreachable!(),
                };
                extension_headers.push(fragment);
            }
            _ => break,
        }
    }

    // This requires to keep it in sync with the enum.
    // Should find another way.
    let ext_headers_len: usize = extension_headers
        .iter()
        .map(|eh| match eh {
            ExtensionHeader::HopByHopOptions { data, .. }
            | ExtensionHeader::DestOptions { data, .. }
            | ExtensionHeader::RoutingHeader { data, .. }
            | ExtensionHeader::AuthHeader { data, .. }
            | ExtensionHeader::MobilityHeader { data, .. } => 2 + data.len(),
            ExtensionHeader::FragmentHeader { .. } => 8,
        })
        .sum();

    let total_length = header.payload_len;
    let payload_len = (total_length as usize).saturating_sub(ext_headers_len);

    let mut payload_cur = Cursor::new(cur.bytes(payload_len).unwrap());
    let payload = match next_header {
        6 => TransportPacket::TCP(parse_tcp(&mut payload_cur)),
        17 => TransportPacket::UDP(parse_udp(&mut payload_cur)),
        58 => TransportPacket::ICMPv6(parse_icmpv6(&mut payload_cur)),
        other => panic!("Add support for IPv6 next_header {}", other),
    };

    IPv6Packet {
        header,
        extension_headers,
        payload,
    }
}
