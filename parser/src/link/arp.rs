use crate::pcap::Cursor;

// Quick Reference:
// https://en.wikipedia.org/wiki/Address_Resolution_Protocol
pub struct ARPPacket<'a> {
    pub hw_type: HardwareType,
    pub protocol_type: EthType,
    pub hw_length: u8,
    pub protocol_length: u8,
    pub op: ARPOperation,
    pub sender_hw_addr: u64,
    pub sender_protocol_addr: u32,
    pub target_hw_addr: u64,
    pub target_protocol_addr: u32,
    pub payload: &'a [u8],
}

// Quick Reference:
// https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
#[derive(Debug, Clone, Copy)]
pub enum HardwareType {
    Eth = 1,
}

// Quick Reference:
// https://en.wikipedia.org/wiki/EtherType#Values
#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum EthType {
    IPv4 = 0x0800,
    ARP = 0x0806,
}

#[derive(Debug, Clone, Copy)]
pub enum ARPOperation {
    Request = 1,
    Reply = 2,
}

pub(crate) fn parse_arp<'a>(cur: &mut Cursor<'a>) -> ARPPacket<'a> {
    let hardware_type_num = cur.u16_be().unwrap();

    let hardware_type = match hardware_type_num {
        1 => HardwareType::Eth,
        other => panic!("Unknown type of {}", other),
    };

    let protocol_type_num = cur.u16_be().unwrap();
    let protocol_type = match protocol_type_num {
        0x0800 => EthType::IPv4,
        0x0806 => EthType::ARP,
        other => panic!(
            "Unknown EtherType type {}. See quick ref for EthType.",
            other
        ),
    };

    let hw_length = cur.u8().unwrap();
    let protocol_length = cur.u8().unwrap();

    let operation_number = cur.u16_be().unwrap();
    let op = match operation_number {
        1 => ARPOperation::Request,
        2 => ARPOperation::Reply,
        other => panic!("Unknown Operation {}", other),
    };

    let sender_hw_addr: u64 = cur
        .bytes(6)
        .unwrap()
        .iter()
        .fold(0u64, |acc, &b| (acc << 8) | b as u64);

    let sender_protocol_addr = cur.u32_be().unwrap();

    let target_hw_addr: u64 = cur
        .bytes(6)
        .unwrap()
        .iter()
        .fold(0u64, |acc, &b| (acc << 8) | b as u64);

    let target_protocol_addr = cur.u32_be().unwrap();

    ARPPacket {
        hw_type: hardware_type,
        protocol_type,
        hw_length,
        protocol_length,
        op,
        sender_hw_addr,
        sender_protocol_addr,
        target_hw_addr,
        target_protocol_addr,
        payload: cur.remaining(),
    }
}
