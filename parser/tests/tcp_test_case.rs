mod common;

use common::{nth_frame, parse_hex_u8, parse_hex_u16, read_file, read_tsv_rows};
use parser::layer::{NetworkPacket, TransportPacket};

#[test]
fn first_tcp_packet_matches_reference() {
    let rows = read_tsv_rows("../tests/cases/tcp_test_case.tsv");
    assert!(!rows.is_empty(), "no test cases in tcp_test_case.tsv");

    for row in rows {
        let [
            file,
            srcport,
            dstport,
            seq,
            ack,
            flags,
            window,
            checksum,
            urgptr,
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
            panic!(
                "{}: expected first TCP packet's network layer to be IPv4",
                file
            );
        };
        let TransportPacket::TCP(tcp) = &ip.payload else {
            panic!("{}: expected first TCP packet to be TCP", file);
        };

        assert_eq!(
            tcp.source,
            srcport.parse::<u16>().unwrap(),
            "{file}: source"
        );
        assert_eq!(tcp.dest, dstport.parse::<u16>().unwrap(), "{file}: dest");
        assert_eq!(tcp.seq_num, seq.parse::<u32>().unwrap(), "{file}: seq_num");
        assert_eq!(tcp.ack_num, ack.parse::<u32>().unwrap(), "{file}: ack_num");

        let expected_flags = parse_hex_u8(flags);
        assert_eq!(
            tcp.flags.cwr,
            expected_flags & 0b1000_0000 != 0,
            "{file}: cwr"
        );
        assert_eq!(
            tcp.flags.ece,
            expected_flags & 0b0100_0000 != 0,
            "{file}: ece"
        );
        assert_eq!(
            tcp.flags.urg,
            expected_flags & 0b0010_0000 != 0,
            "{file}: urg"
        );
        assert_eq!(
            tcp.flags.ack,
            expected_flags & 0b0001_0000 != 0,
            "{file}: ack"
        );
        assert_eq!(
            tcp.flags.psh,
            expected_flags & 0b0000_1000 != 0,
            "{file}: psh"
        );
        assert_eq!(
            tcp.flags.rst,
            expected_flags & 0b0000_0100 != 0,
            "{file}: rst"
        );
        assert_eq!(
            tcp.flags.syn,
            expected_flags & 0b0000_0010 != 0,
            "{file}: syn"
        );
        assert_eq!(
            tcp.flags.fin,
            expected_flags & 0b0000_0001 != 0,
            "{file}: fin"
        );

        assert_eq!(tcp.window, window.parse::<u16>().unwrap(), "{file}: window");
        assert_eq!(tcp.checksum, parse_hex_u16(checksum), "{file}: checksum");
        assert_eq!(
            tcp.urgent_ptr,
            urgptr.parse::<u16>().unwrap(),
            "{file}: urgent_ptr"
        );
    }
}
