use crate::layer::Frame::{Ethernet, SLL};
use crate::link::{ARPPacket, parse_ethernet, parse_sll};
use crate::network::icmpv6::ICMPv6;
use crate::network::igmp::IGMP;
use crate::network::ipv6::IPv6Packet;
use crate::network::{ICMP, IPv4Packet};
use crate::pcap::header::{Header, parse_header};
use crate::pcap::{Cursor, Packet, PacketIter};
use crate::transport::{TCPPacket, UDPPacket};

pub struct LinuxSLLFrame<'a> {
    pub packet_type: u16,
    pub arphrd_type: u16,
    pub link_layer_addr_length: u16,
    pub link_layer_addr: u64,
    pub protocol_type: u16,
    pub packet: NetworkPacket<'a>,
}

pub struct EthernetFrame<'a> {
    pub mac_dest: [u8; 6],
    pub mac_source: [u8; 6],
    pub tag: Option<u32>,
    pub packet: NetworkPacket<'a>,
}

pub enum Frame<'a> {
    Ethernet(EthernetFrame<'a>),
    SLL(LinuxSLLFrame<'a>),
}

impl<'a> Frame<'a> {
    pub fn packet(&self) -> &NetworkPacket<'a> {
        match self {
            Frame::Ethernet(frame) => &frame.packet,
            Frame::SLL(frame) => &frame.packet,
        }
    }

    pub fn into_packet(self) -> NetworkPacket<'a> {
        match self {
            Frame::Ethernet(frame) => frame.packet,
            Frame::SLL(frame) => frame.packet,
        }
    }
}

pub enum NetworkPacket<'a> {
    IPv4(IPv4Packet<'a>),
    IPv6(IPv6Packet<'a>),
    ARP(ARPPacket<'a>),
    Unknown { ethertype: u16, data: &'a [u8] },
}

pub enum TransportPacket<'a> {
    TCP(TCPPacket<'a>),
    UDP(UDPPacket<'a>),
    ICMP(ICMP),
    ICMPv6(ICMPv6),
    IGMP(IGMP<'a>),
}

pub fn parse_pcap<'a>(data: &'a [u8]) -> (Header, impl Iterator<Item = Packet<'a>>) {
    let mut cur = Cursor::new(data);
    let header = parse_header(&mut cur);

    let tsec = match header.tsec {
        Some(tsec) => tsec,
        None => panic!("No tsec in header."),
    };
    let packets = PacketIter::new(cur, tsec);

    (header, packets)
}

pub fn parse_packet<'a>(header: &Header, packet: Packet<'a>) -> Frame<'a> {
    match header.link_type {
        1 => Ethernet(parse_ethernet(&mut Cursor::new(packet.payload))),
        113 => SLL(parse_sll(&mut Cursor::new(packet.payload))),
        other => panic!("Add support for {}", other),
    }
}
