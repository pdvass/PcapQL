mod common;

use common::{nth_frame, parse_mac_bytes, read_file, read_tsv_rows};
use parser::layer::Frame;

#[test]
fn first_ethernet_frame_matches_reference() {
    let rows = read_tsv_rows("../tests/cases/ethernet_test_case.tsv");
    assert!(!rows.is_empty(), "no test cases in ethernet_test_case.tsv");

    for row in rows {
        let [file, mac_dest, mac_source, skip] = row.as_slice() else {
            panic!("malformed row: {:?}", row);
        };

        let skip = skip
            .parse::<usize>()
            .unwrap_or_else(|e| panic!("{}: bad skip: {}", file, e));

        let data = read_file(file);
        let frame = nth_frame(&data, skip);

        let Frame::Ethernet(eth) = frame else {
            panic!(
                "{}: expected first Ethernet-linktype frame to be Ethernet",
                file
            );
        };

        assert_eq!(eth.mac_dest, parse_mac_bytes(mac_dest), "{file}: mac_dest");
        assert_eq!(
            eth.mac_source,
            parse_mac_bytes(mac_source),
            "{file}: mac_source"
        );
    }
}
