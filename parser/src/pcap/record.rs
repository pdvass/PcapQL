use chrono::{DateTime, Utc};
use std::fmt;

use crate::pcap::{Cursor, header::TSecs};

pub struct Packet<'a> {
    pub timestamp: DateTime<Utc>,
    pub captured_length: u32,
    pub original_length: u32,
    pub truncated: bool,
    pub payload: &'a [u8],
}

impl<'a> fmt::Display for Packet<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Packet received at {}.\nOriginal Length {} and Captured {}.",
            self.timestamp, self.original_length, self.captured_length
        )
    }
}

pub struct PacketIter<'a> {
    cur: Cursor<'a>,
    tsec: TSecs,
}

impl<'a> PacketIter<'a> {
    pub fn new(cur: Cursor<'a>, tsec: TSecs) -> Self {
        PacketIter { cur, tsec }
    }
}

impl<'a> Iterator for PacketIter<'a> {
    type Item = Packet<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.cur.has_remaining() {
            return None;
        }

        let timestamp_secs = self.cur.u32().unwrap();
        let timestamp_nanos = self.cur.u32().unwrap();
        let dt = match self.tsec {
            TSecs::Nano => {
                DateTime::<Utc>::from_timestamp(timestamp_secs as i64, timestamp_nanos).unwrap()
            }
            TSecs::Micro => {
                DateTime::<Utc>::from_timestamp(timestamp_secs as i64, timestamp_nanos * 1_000)
                    .unwrap()
            }
        };

        let captured_length = self.cur.u32().unwrap();
        let original_length = self.cur.u32().unwrap();

        let payload = self.cur.bytes(captured_length as usize).unwrap();
        let packet = Packet {
            timestamp: dt,
            captured_length,
            original_length,
            truncated: captured_length != original_length,
            payload,
        };

        Some(packet)
    }
}
