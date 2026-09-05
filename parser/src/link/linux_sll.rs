use crate::layer::{LinuxSLLFrame, NetworkPacket};
use crate::link::arp::parse_arp;
use crate::network::ipv4::parse_ipv4;
use crate::network::ipv6::parse_ipv6;
use crate::pcap::Cursor;

pub(crate) fn parse_sll<'a>(cur: &mut Cursor<'a>) -> LinuxSLLFrame<'a> {
    let packet_type = cur.u16_be().unwrap();
    // match packet_type {
    //     0 => println!("The packet was specifically sent to us by somebody else"),
    //     1 => println!("The packet was broadcast by somebody else"),
    //     2 => println!("The packet was multicast, but not broadcast, by somebody else"),
    //     3 => println!("The packet was sent to somebody else by somebody else"),
    //     4 => println!("The packet was sent by us"),
    //     other => println!("Unknown {}", other),
    // }
    let arphrd_type = cur.u16_be().unwrap();
    // Check https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_arp.h
    // as found https://stackoverflow.com/questions/14702363/where-to-get-device-type-constants-description
    match arphrd_type {
        1 => {}
        other => panic!("Should add {}", other),
    }
    let link_layer_addr_length = cur.u16_be().unwrap();

    // The SLL address field is always a fixed 8 bytes, padded with zeros;
    // link_layer_addr_length only says how many of them are meaningful.
    let addr_used_len = (link_layer_addr_length as usize).min(8);
    let mut link_layer_addr = cur.u64_be().unwrap();

    if addr_used_len < 8 {
        link_layer_addr >>= (8 - addr_used_len) * 8;
    }

    let protocol_type = cur.u16_be().unwrap();

    let packet: NetworkPacket = match protocol_type {
        0x800 => NetworkPacket::IPv4(parse_ipv4(cur)),
        0x86DD => NetworkPacket::IPv6(parse_ipv6(cur)),
        0x0806 => NetworkPacket::ARP(parse_arp(cur)),
        other => panic!("Unknown {}", other),
    };

    LinuxSLLFrame {
        packet_type,
        arphrd_type,
        link_layer_addr_length,
        link_layer_addr,
        protocol_type,
        packet,
    }
}
