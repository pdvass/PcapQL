mod common;

use common::{nth_frame, parse_hex_u8, parse_hex_u16, read_file, read_tsv_rows};
use parser::layer::NetworkPacket;
use parser::network::ipv4::Protocol;
use std::net::Ipv4Addr;

fn protocol_number(protocol: &Protocol) -> u8 {
    match protocol {
        Protocol::ICMP => 1,
        Protocol::IGMP => 2,
        Protocol::TCP => 6,
        Protocol::UDP => 17,
        Protocol::ENCAP => 41,
        Protocol::OSPF => 89,
        Protocol::SCTP => 132,
    }
}

#[test]
fn first_ipv4_packet_matches_reference() {
    let rows = read_tsv_rows("../tests/cases/ipv4_test_case.tsv");
    assert!(!rows.is_empty(), "no test cases in ipv4_test_case.tsv");

    for row in rows {
        let [
            file,
            dscp,
            ecn,
            len,
            flag,
            offset,
            ttl,
            protocol,
            checksum,
            src,
            dst,
            skip,
        ] = row.as_slice()
        else {
            panic!("malformed row: {:?}", row);
        };

        let skip = skip
            .parse::<usize>()
            .unwrap_or_else(|e| panic!("{}: bad skip: {}", file, e));

        let data = read_file(file);
        let frame = nth_frame(&data, skip);

        let packet = &frame.packet();

        let NetworkPacket::IPv4(ip) = packet else {
            panic!("{}: expected first packet to be IPv4", file);
        };

        assert_eq!(ip.dscp, dscp.parse::<u8>().unwrap(), "{file}: dscp");
        assert_eq!(ip.ecn, ecn.parse::<u8>().unwrap(), "{file}: ecn");
        assert_eq!(
            ip.total_length,
            len.parse::<u16>().unwrap(),
            "{file}: total_length"
        );
        assert_eq!(ip.flag as u8, parse_hex_u8(flag), "{file}: flag");
        assert_eq!(
            ip.fragment_offset,
            offset.parse::<u16>().unwrap(),
            "{file}: fragment_offset"
        );
        assert_eq!(ip.ttl, ttl.parse::<u8>().unwrap(), "{file}: ttl");
        assert_eq!(
            protocol_number(&ip.protocol),
            protocol.parse::<u8>().unwrap(),
            "{file}: protocol"
        );
        assert_eq!(
            ip.header_checksum,
            parse_hex_u16(checksum),
            "{file}: header_checksum"
        );
        assert_eq!(
            Ipv4Addr::from(ip.source),
            src.parse::<Ipv4Addr>().unwrap(),
            "{file}: source ip"
        );
        assert_eq!(
            Ipv4Addr::from(ip.dest),
            dst.parse::<Ipv4Addr>().unwrap(),
            "{file}: dest ip"
        );
    }
}
