use std::fmt;

use crate::{network::icmpv4_types::describe, pcap::Cursor};

pub struct ICMP {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub rest: u32,
}

impl fmt::Display for ICMP {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", describe(self.icmp_type, self.code))
    }
}

pub(crate) fn parse_icmpv4(cur: &mut Cursor) -> ICMP {
    let icmp_type = cur.u8().unwrap();
    let code = cur.u8().unwrap();
    let checksum = cur.u16_be().unwrap();
    let rest = cur.u32_be().unwrap();
    ICMP {
        icmp_type,
        code,
        checksum,
        rest,
    }
}
