use crate::pcap::Cursor;

pub struct UDPPacket<'a> {
    pub source: u16,
    pub dest: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: &'a [u8],
}

pub(crate) fn parse_udp<'a>(cur: &mut Cursor<'a>) -> UDPPacket<'a> {
    let source = cur.u16_be().unwrap();
    let dest = cur.u16_be().unwrap();
    let length = cur.u16_be().unwrap();
    let checksum = cur.u16_be().unwrap();
    let payload = cur.remaining();
    UDPPacket {
        source,
        dest,
        length,
        checksum,
        payload,
    }
}
