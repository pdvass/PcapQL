mod common;

use common::{nth_frame, parse_hex_u16, read_file, read_tsv_rows};
use parser::layer::Frame;

#[test]
fn first_sll_packet_matches_reference() {
    let rows = read_tsv_rows("../tests/cases/sll_packet_test_case.tsv");
    assert!(
        !rows.is_empty(),
        "no test cases in sll_packet_test_case.tsv"
    );

    for row in rows {
        let [file, packet_type, halen, etype, skip] = row.as_slice() else {
            panic!("malformed row: {row:?}");
        };

        let skip: usize = skip
            .parse()
            .unwrap_or_else(|e| panic!("{}: bad skip: {}", file, e));

        let data = read_file(file);
        let frame = nth_frame(&data, skip);

        let Frame::SLL(sll) = frame else {
            panic!("{}: expected first frame to be Linux SLL", file);
        };

        let expected_packet_type = packet_type
            .parse::<u16>()
            .unwrap_or_else(|e| panic!("{}: bad packet_type: {}", file, e));

        let expected_halen = halen
            .parse::<u16>()
            .unwrap_or_else(|e| panic!("{}: bad halen: {}", file, e));

        let expected_etype = parse_hex_u16(etype);

        assert_eq!(sll.packet_type, expected_packet_type, "{file}: packet_type");
        assert_eq!(
            sll.link_layer_addr_length, expected_halen,
            "{file}: link_layer_addr_length"
        );
        assert_eq!(sll.protocol_type, expected_etype, "{file}: protocol_type");
    }
}
