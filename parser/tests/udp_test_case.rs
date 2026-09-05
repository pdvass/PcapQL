mod common;

use common::{nth_frame, parse_hex_u16, read_file, read_tsv_rows};
use parser::layer::{NetworkPacket, TransportPacket};

#[test]
fn first_udp_packet_matches_reference() {
    let rows = read_tsv_rows("../tests/cases/udp_test_case.tsv");
    assert!(!rows.is_empty(), "no test cases in udp_test_case.tsv");

    for row in rows {
        let [file, srcport, dstport, length, checksum, skip] = row.as_slice() else {
            panic!("malformed row: {:?}", row);
        };

        let skip = skip
            .parse::<usize>()
            .unwrap_or_else(|e| panic!("{}: bad skip: {}", file, e));

        let data = read_file(file);
        let frame = nth_frame(&data, skip);

        let packet = &frame.packet();

        let NetworkPacket::IPv4(ip) = packet else {
            panic!(
                "{}: expected first UDP packet's network layer to be IPv4",
                file
            );
        };
        let TransportPacket::UDP(udp) = &ip.payload else {
            panic!("{}: expected first UDP packet to be UDP", file);
        };

        assert_eq!(
            udp.source,
            srcport.parse::<u16>().unwrap(),
            "{file}: source"
        );
        assert_eq!(udp.dest, dstport.parse::<u16>().unwrap(), "{file}: dest");
        assert_eq!(udp.length, length.parse::<u16>().unwrap(), "{file}: length");
        assert_eq!(udp.checksum, parse_hex_u16(checksum), "{file}: checksum");
    }
}
