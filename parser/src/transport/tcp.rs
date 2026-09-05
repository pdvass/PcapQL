use crate::pcap::Cursor;

// Quick reference
// https://en.wikipedia.org/wiki/Transmission_Control_Protocol
pub struct TCPPacket<'a> {
    pub source: u16,
    pub dest: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: u8, // Actually u4
    pub reserved: u8,    // Actually u4,
    pub flags: Flags,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
    pub options: Vec<TcpOption<'a>>,
    pub payload: &'a [u8],
}

// Quick reference
// https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-parameters-1
#[derive(Debug)]
pub enum TcpOption<'a> {
    EndOfOptions,
    NoOp,
    MaxSegmentSize(u16),
    WindowScale(u8),
    SackPermitted,
    Sack(&'a [u8]),
    Timestamps { tsval: u32, tsecr: u32 },
    Other { kind: u8, data: &'a [u8] },
}

fn parse_tcp_options<'a>(mut data: &'a [u8]) -> Vec<TcpOption<'a>> {
    let mut options = Vec::new();

    while !data.is_empty() {
        let kind = data[0];

        // Single-octet options: no length byte, no data.
        if kind == 0 {
            options.push(TcpOption::EndOfOptions);
            break;
        }
        if kind == 1 {
            options.push(TcpOption::NoOp);
            data = &data[1..];
            continue;
        }

        // Everything else is type-length-value, where length includes
        // the kind and length octets themselves.
        if data.len() < 2 {
            break;
        }
        let len = data[1] as usize;
        if len < 2 || len > data.len() {
            break;
        }
        let value = &data[2..len];

        let option = match (kind, value.len()) {
            (2, 2) => TcpOption::MaxSegmentSize(u16::from_be_bytes([value[0], value[1]])),
            (3, 1) => TcpOption::WindowScale(value[0]),
            (4, 0) => TcpOption::SackPermitted,
            (5, _) => TcpOption::Sack(value),
            (8, 8) => TcpOption::Timestamps {
                tsval: u32::from_be_bytes(value[0..4].try_into().unwrap()),
                tsecr: u32::from_be_bytes(value[4..8].try_into().unwrap()),
            },
            (other, _) => TcpOption::Other {
                kind: other,
                data: value,
            },
        };
        options.push(option);
        data = &data[len..];
    }

    options
}

pub struct Flags {
    pub cwr: bool,
    pub ece: bool,
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
}

pub(crate) fn parse_tcp<'a>(cur: &mut Cursor<'a>) -> TCPPacket<'a> {
    let source = cur.u16_be().unwrap();
    let dest = cur.u16_be().unwrap();
    let seq_num = cur.u32_be().unwrap();
    let reserved: u8 = 0;
    let ack_num = cur.u32_be().unwrap();
    let data_offset = cur.u8().unwrap() >> 4;
    let flags_bits = cur.u8().unwrap();
    let flags = Flags {
        cwr: flags_bits & 0b1000_0000 != 0,
        ece: flags_bits & 0b0100_0000 != 0,
        urg: flags_bits & 0b0010_0000 != 0,
        ack: flags_bits & 0b0001_0000 != 0,
        psh: flags_bits & 0b0000_1000 != 0,
        rst: flags_bits & 0b0000_0100 != 0,
        syn: flags_bits & 0b0000_0010 != 0,
        fin: flags_bits & 0b0000_0001 != 0,
    };

    let window = cur.u16_be().unwrap();
    let checksum = cur.u16_be().unwrap();
    let urgent_ptr = cur.u16_be().unwrap();

    let options = if data_offset > 5 {
        parse_tcp_options(cur.bytes(((data_offset - 5) * 4) as usize).unwrap())
    } else {
        Vec::new()
    };

    TCPPacket {
        source,
        dest,
        seq_num,
        ack_num,
        data_offset,
        reserved,
        flags,
        window,
        checksum,
        urgent_ptr,
        options,
        payload: cur.remaining(),
    }
}
