mod common;

use common::{parse_header_only, read_file, read_tsv_rows};

/// Recompute canonical form directly from the file's raw bytes
/// so this test also catches a stale/incorrect form.
/// See `acummulate.sh`
fn canonical_magic_number(raw_magic: &[u8]) -> String {
    raw_magic.iter().rev().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn linktype_and_magic_number_match_reference() {
    let rows = read_tsv_rows("../tests/cases/linktype_and_magic_number_test_case.tsv");
    assert!(
        !rows.is_empty(),
        "no test cases in linktype_and_magic_number_test_case.tsv"
    );

    for row in rows {
        // This test only reads the global header, so skip is unused here.
        let [file, linktype, magic, _skip] = row.as_slice() else {
            panic!("malformed row: {:?}", row);
        };

        let data = read_file(file);
        let header = parse_header_only(&data);

        let expected_linktype = linktype
            .parse::<u16>()
            .unwrap_or_else(|e| panic!("{}: bad linktype: {}", file, e));
        assert_eq!(
            header.link_type, expected_linktype,
            "{file}: link_type mismatch"
        );

        let expected_magic = canonical_magic_number(&data[0..4]);
        assert_eq!(&expected_magic, magic, "{file}: magic number mismatch");
    }
}
