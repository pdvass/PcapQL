mod common;

use common::{nth_frame, parse_hex_u16, read_file, read_tsv_rows};
use parser::layer::{NetworkPacket, TransportPacket};

#[test]
fn first_icmpv6_packet_matches_reference() {
    let rows = read_tsv_rows("../tests/cases/icmpv6_test_case.tsv");
    assert!(!rows.is_empty(), "no test cases in icmpv6_test_case.tsv");

    for row in rows {
        let [file, icmp_type, code, checksum, skip] = row.as_slice() else {
            panic!("malformed row: {:?}", row);
        };

        let skip = skip
            .parse::<usize>()
            .unwrap_or_else(|e| panic!("{}: bad skip: {}", file, e));

        let data = read_file(file);
        let frame = nth_frame(&data, skip);

        let packet = &frame.packet();

        let NetworkPacket::IPv6(ipv6) = packet else {
            panic!(
                "{}: expected first ICMPv6 packet's network layer to be IPv6",
                file
            );
        };
        let TransportPacket::ICMPv6(icmp) = &ipv6.payload else {
            panic!("{}: expected first ICMPv6 packet to be ICMPv6", file);
        };

        assert_eq!(
            icmp.icmp_type,
            icmp_type.parse::<u8>().unwrap(),
            "{file}: icmp_type"
        );
        assert_eq!(icmp.code, code.parse::<u8>().unwrap(), "{file}: code");
        assert_eq!(icmp.checksum, parse_hex_u16(checksum), "{file}: checksum");
    }
}
