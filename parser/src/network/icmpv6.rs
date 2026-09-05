use std::fmt;

use crate::{network::icmpv6_types::describe, pcap::Cursor};

pub struct ICMPv6 {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub rest: u32,
}

impl fmt::Display for ICMPv6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", describe(self.icmp_type, self.code))
    }
}

pub(crate) fn parse_icmpv6(cur: &mut Cursor) -> ICMPv6 {
    let icmp_type = cur.u8().unwrap();
    let code = cur.u8().unwrap();
    let checksum = cur.u16_be().unwrap();
    let rest = cur.u32_be().unwrap();
    ICMPv6 {
        icmp_type,
        code,
        checksum,
        rest,
    }
}
