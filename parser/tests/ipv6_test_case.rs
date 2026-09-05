mod common;

use common::{nth_frame, parse_hex_u32, read_file, read_tsv_rows};
use parser::layer::NetworkPacket;
use std::net::Ipv6Addr;

#[test]
fn first_ipv6_packet_matches_reference() {
    let rows = read_tsv_rows("../tests/cases/ipv6_test_case.tsv");
    assert!(!rows.is_empty(), "no test cases in ipv6_test_case.tsv");

    for row in rows {
        let [file, version, tclass, flow, plen, nxt, hlim, src, dst, skip] = row.as_slice() else {
            panic!("malformed row: {:?}", row);
        };

        let skip = skip
            .parse::<usize>()
            .unwrap_or_else(|e| panic!("{}: bad skip: {}", file, e));

        let data = read_file(file);
        let frame = nth_frame(&data, skip);

        let packet = &frame.packet();

        let NetworkPacket::IPv6(ipv6) = packet else {
            panic!("{}: expected first IPv6 packet to be IPv6", file);
        };
        let header = &ipv6.header;

        assert_eq!(
            header.version,
            version.parse::<u8>().unwrap(),
            "{file}: version"
        );
        assert_eq!(
            header.traffic_class,
            parse_hex_u32(tclass) as u8,
            "{file}: traffic_class"
        );
        assert_eq!(header.flow_label, parse_hex_u32(flow), "{file}: flow_label");
        assert_eq!(
            header.payload_len,
            plen.parse::<u16>().unwrap(),
            "{file}: payload_len"
        );
        assert_eq!(
            header.next_header,
            nxt.parse::<u8>().unwrap(),
            "{file}: next_header"
        );
        assert_eq!(
            header.hop_limit,
            hlim.parse::<u8>().unwrap(),
            "{file}: hop_limit"
        );
        assert_eq!(
            Ipv6Addr::from(header.source),
            src.parse::<Ipv6Addr>().unwrap(),
            "{file}: source"
        );
        assert_eq!(
            Ipv6Addr::from(header.dest),
            dst.parse::<Ipv6Addr>().unwrap(),
            "{file}: dest"
        );
    }
}
