mod common;

use common::{nth_frame, parse_hex_u8, parse_hex_u16, read_file, read_tsv_rows};
use parser::layer::{NetworkPacket, TransportPacket};
use parser::network::igmp::IGMP;
use std::net::Ipv4Addr;

// Right now it tests only v3
#[test]
fn first_igmp_packet_matches_reference() {
    let rows = read_tsv_rows("../tests/cases/igmp_test_case.tsv");
    assert!(!rows.is_empty(), "no test cases in igmp_test_case.tsv");

    for row in rows {
        let [file, igmp_type, _max_resp, checksum, group_address, skip] = row.as_slice() else {
            panic!("malformed row: {:?}", row);
        };

        assert_eq!(
            parse_hex_u8(igmp_type),
            0x22,
            "{file}: this test only handles a V3 Report row"
        );

        let skip = skip
            .parse::<usize>()
            .unwrap_or_else(|e| panic!("{}: bad skip: {}", file, e));

        let data = read_file(file);
        let frame = nth_frame(&data, skip);

        let packet = &frame.packet();

        let NetworkPacket::IPv4(ip) = packet else {
            panic!(
                "{}: expected first IGMP packet's network layer to be IPv4",
                file
            );
        };
        let TransportPacket::IGMP(igmp) = &ip.payload else {
            panic!("{}: expected first IGMP packet to be IGMP", file);
        };
        let IGMP::V3Report(report) = igmp else {
            panic!("{}: expected first IGMP packet to be a V3 Report", file);
        };

        assert_eq!(report.checksum, parse_hex_u16(checksum), "{file}: checksum");

        let first_record = report
            .group_records
            .first()
            .unwrap_or_else(|| panic!("{}: V3 report has no group records", file));

        assert_eq!(
            Ipv4Addr::from(first_record.multicast_address),
            group_address.parse::<Ipv4Addr>().unwrap(),
            "{file}: first group record's multicast_address"
        );
    }
}
