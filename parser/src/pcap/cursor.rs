use crate::pcap::header::Endianness;

pub struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
    pub endianness: Option<Endianness>,
}

// Make all `be` pub, to make it easier to parse both headers and network packets.
impl<'a> Cursor<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Cursor {
            bytes,
            pos: 0,
            endianness: None,
        }
    }

    pub fn set_endianness(&mut self, endianness: &Endianness) {
        match endianness {
            Endianness::Big => self.endianness = Some(Endianness::Big),
            Endianness::Little => self.endianness = Some(Endianness::Little),
        }
    }

    pub fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.pos..]
    }

    pub fn has_remaining(&self) -> bool {
        self.pos < self.bytes.len()
    }

    // Really useful for arbitrary number of bytes.
    fn take(&mut self, n: usize) -> Result<&'a [u8], CursorError> {
        let end = self.pos + n;
        let slice = self.bytes.get(self.pos..end).ok_or(CursorError::EOF);
        self.pos = end;
        slice
    }

    pub fn u8(&mut self) -> Result<u8, CursorError> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, CursorError> {
        match self.endianness {
            Some(Endianness::Big) => self.u16_be(),
            Some(Endianness::Little) => self.u16_le(),
            None => panic!("Endianness is not defined."),
        }
    }

    pub fn u16_be(&mut self) -> Result<u16, CursorError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u16_le(&mut self) -> Result<u16, CursorError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    pub fn u32(&mut self) -> Result<u32, CursorError> {
        match self.endianness {
            Some(Endianness::Big) => self.u32_be(),
            Some(Endianness::Little) => self.u32_le(),
            None => panic!("Endianness is not defined."),
        }
    }

    pub fn u32_be(&mut self) -> Result<u32, CursorError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u32_le(&mut self) -> Result<u32, CursorError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn u64(&mut self) -> Result<u64, CursorError> {
        match self.endianness {
            Some(Endianness::Big) => self.u64_be(),
            Some(Endianness::Little) => self.u64_le(),
            None => panic!("Endianness is not defined."),
        }
    }

    pub fn u64_be(&mut self) -> Result<u64, CursorError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn u64_le(&mut self) -> Result<u64, CursorError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub fn u128(&mut self) -> Result<u128, CursorError> {
        match self.endianness {
            Some(Endianness::Big) => self.u128_be(),
            Some(Endianness::Little) => self.u128_le(),
            None => panic!("Endianness is not defined."),
        }
    }

    pub fn u128_be(&mut self) -> Result<u128, CursorError> {
        Ok(u128::from_be_bytes(self.take(16)?.try_into().unwrap()))
    }

    fn u128_le(&mut self) -> Result<u128, CursorError> {
        Ok(u128::from_le_bytes(self.take(16)?.try_into().unwrap()))
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], CursorError> {
        self.take(n)
    }
}

#[derive(Debug)]
pub enum CursorError {
    EOF,
}
