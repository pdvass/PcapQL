use crate::layer::{EthernetFrame, NetworkPacket};
use crate::link::parse_arp;
use crate::network::ipv6::parse_ipv6;
use crate::network::parse_ipv4;
use crate::pcap::Cursor;

pub(crate) fn parse_ethernet<'a>(cur: &mut Cursor<'a>) -> EthernetFrame<'a> {
    let dest = cur.bytes(6).unwrap();
    let source = cur.bytes(6).unwrap();
    // 802.1Q uses a TPID of 0x8100.
    // 802.1ad uses a TPID of 0x88a8.
    let tpid = cur.u16_be().unwrap();
    if (tpid == 0x8100) | (tpid == 0x88a8) {
        panic!("VLAN. Should add support.");
    }
    // If < 1500 it indicates length <=> Payload in octets
    // if > 1536 EtherType
    let mut packet: Option<NetworkPacket> = None;
    if tpid > 1536 {
        packet = match tpid {
            0x800 => Some(NetworkPacket::IPv4(parse_ipv4(cur))),
            0x86DD => Some(NetworkPacket::IPv6(parse_ipv6(cur))),
            0x0806 => Some(NetworkPacket::ARP(parse_arp(cur))),
            0x8808 | 0x3e43 => Some(NetworkPacket::Unknown {
                ethertype: 0x8808,
                data: cur.remaining(),
            }), // https://en.wikipedia.org/wiki/Ethernet_flow_control
            // Don't know what to do with it yet.
            // 0x3e43 exists in /data/2015-03-17/snort.log.1426550408
            // can't find it here
            // https://en.wikipedia.org/wiki/EtherType.
            // I haven't figured out yet how to distinguish valid tpids that I should add support for
            // from invalid ones where I should handle an error.
            other => panic!("Unknown ethertype: {:x}", other),
        };
    }
    if tpid < 1500 {
        panic!("Add support for tpid acting as length");
    }

    EthernetFrame {
        mac_dest: dest.try_into().unwrap(),
        mac_source: source.try_into().unwrap(),
        tag: None,
        packet: packet.unwrap(),
    }
}
