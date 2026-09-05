// Each `tests/*.rs` file is its own binary crate, so `common` gets recompiled
// per binary and only uses the helpers that particular test needs.
#![allow(dead_code)]

use parser::layer::{Frame, parse_packet, parse_pcap};
use parser::pcap;
use std::fs;

/// Resolves a path relative to the `parser` crate root.
pub fn manifest_path(rel: &str) -> String {
    format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel)
}

pub fn read_file(rel: &str) -> Vec<u8> {
    fs::read(manifest_path(rel)).unwrap_or_else(|e| panic!("failed to read {}: {}", rel, e))
}

pub fn read_tsv_rows(rel: &str) -> Vec<Vec<String>> {
    let content = fs::read_to_string(manifest_path(rel))
        .unwrap_or_else(|e| panic!("failed to read tsv {}: {}", rel, e));
    content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            line.split('\t')
                .map(|field| field.trim().to_string())
                .collect()
        })
        .collect()
}

pub fn parse_header_only(data: &[u8]) -> pcap::header::Header {
    assert!(data.len() >= 24, "file shorter than a pcap global header");
    let (header, _) = parse_pcap(&data[0..24]);
    header
}

/// Parses the global header, then the link-layer frame of the packet at index
/// `n` (0-based, i.e. `n` packets are skipped before the one that's parsed).
pub fn nth_frame(data: &[u8], n: usize) -> Frame<'_> {
    let (header, mut packets) = parse_pcap(data);
    let packet = packets
        .nth(n)
        .unwrap_or_else(|| panic!("file has no packet at index {}", n));
    parse_packet(&header, packet)
}

pub fn parse_hex_u16(s: &str) -> u16 {
    u16::from_str_radix(s.trim_start_matches("0x"), 16)
        .unwrap_or_else(|e| panic!("bad hex '{}': {}", s, e))
}

pub fn parse_hex_u8(s: &str) -> u8 {
    u8::from_str_radix(s.trim_start_matches("0x"), 16)
        .unwrap_or_else(|e| panic!("bad hex '{}': {}", s, e))
}

pub fn parse_hex_u32(s: &str) -> u32 {
    u32::from_str_radix(s.trim_start_matches("0x"), 16)
        .unwrap_or_else(|e| panic!("bad hex '{}': {}", s, e))
}

/// Parses a colon-separated MAC string ("fa:16:3e:74:da:1a") into its 6 octets.
pub fn parse_mac_bytes(s: &str) -> [u8; 6] {
    let bytes: Vec<u8> = s
        .split(':')
        .map(|part| {
            u8::from_str_radix(part, 16).unwrap_or_else(|e| panic!("bad mac '{}': {}", s, e))
        })
        .collect();
    bytes
        .try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("mac '{}' has {} octets, expected 6", s, v.len()))
}

pub fn parse_mac_u64(s: &str) -> u64 {
    parse_mac_bytes(s)
        .iter()
        .fold(0u64, |acc, &b| (acc << 8) | b as u64)
}
