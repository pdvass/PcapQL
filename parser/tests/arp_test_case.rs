mod common;

use common::{nth_frame, parse_hex_u16, parse_mac_u64, read_file, read_tsv_rows};
use parser::layer::NetworkPacket;
use std::net::Ipv4Addr;

#[test]
fn first_arp_packet_matches_reference() {
    let rows = read_tsv_rows("../tests/cases/arp_test_case.tsv");
    assert!(!rows.is_empty(), "no test cases in arp_test_case.tsv");

    for row in rows {
        let [
            file,
            hw_type,
            proto_type,
            hw_size,
            proto_size,
            opcode,
            src_mac,
            src_ip,
            dst_mac,
            dst_ip,
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

        let NetworkPacket::ARP(arp) = packet else {
            panic!("{}: expected first ARP packet to be ARP", file);
        };

        assert_eq!(
            arp.hw_type as u8,
            hw_type.parse::<u8>().unwrap(),
            "{file}: hw_type"
        );
        assert_eq!(
            arp.protocol_type as u16,
            parse_hex_u16(proto_type),
            "{file}: protocol_type"
        );
        assert_eq!(
            arp.hw_length,
            hw_size.parse::<u8>().unwrap(),
            "{file}: hw_length"
        );
        assert_eq!(
            arp.protocol_length,
            proto_size.parse::<u8>().unwrap(),
            "{file}: protocol_length"
        );
        assert_eq!(arp.op as u8, opcode.parse::<u8>().unwrap(), "{file}: op");
        assert_eq!(
            arp.sender_hw_addr,
            parse_mac_u64(src_mac),
            "{file}: sender_hw_addr"
        );
        assert_eq!(
            Ipv4Addr::from(arp.sender_protocol_addr),
            src_ip.parse::<Ipv4Addr>().unwrap(),
            "{file}: sender_protocol_addr"
        );
        assert_eq!(
            arp.target_hw_addr,
            parse_mac_u64(dst_mac),
            "{file}: target_hw_addr"
        );
        assert_eq!(
            Ipv4Addr::from(arp.target_protocol_addr),
            dst_ip.parse::<Ipv4Addr>().unwrap(),
            "{file}: target_protocol_addr"
        );
    }
}
