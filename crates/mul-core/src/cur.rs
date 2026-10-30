// SPDX-License-Identifier: GPL-3.0-only

use crate::error::FormatError;

/// Bounds-checked cursor over a byte slice. Never panics on input.
#[derive(Debug, Clone, Copy)]
pub struct Cur<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cur<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn at(buf: &'a [u8], pos: usize) -> Result<Self, FormatError> {
        if pos > buf.len() {
            return Err(FormatError::new(pos, "cursor past end"));
        }
        Ok(Self { buf, pos })
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    pub fn buf(&self) -> &'a [u8] {
        self.buf
    }

    fn need(&self, n: usize) -> Result<(), FormatError> {
        if self.remaining() < n {
            Err(FormatError::new(
                self.pos,
                format!("need {n} bytes, have {}", self.remaining()),
            ))
        } else {
            Ok(())
        }
    }

    pub fn u8(&mut self) -> Result<u8, FormatError> {
        self.need(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn u16_le(&mut self) -> Result<u16, FormatError> {
        self.need(2)?;
        let v = u16::from_le_bytes(self.buf[self.pos..self.pos + 2].try_into().unwrap());
        self.pos += 2;
        Ok(v)
    }

    pub fn u32_le(&mut self) -> Result<u32, FormatError> {
        self.need(4)?;
        let v = u32::from_le_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    pub fn u64_le(&mut self) -> Result<u64, FormatError> {
        self.need(8)?;
        let v = u64::from_le_bytes(self.buf[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }

    pub fn i64_le(&mut self) -> Result<i64, FormatError> {
        Ok(self.u64_le()? as i64)
    }

    pub fn i32_le(&mut self) -> Result<i32, FormatError> {
        Ok(self.u32_le()? as i32)
    }

    pub fn f64_le(&mut self) -> Result<f64, FormatError> {
        Ok(f64::from_bits(self.u64_le()?))
    }

    pub fn f32_le(&mut self) -> Result<f32, FormatError> {
        Ok(f32::from_bits(self.u32_le()?))
    }

    /// Read 16 little-endian bytes as a UUID (raw bytes, no RFC byte-swap).
    pub fn uuid_bytes(&mut self) -> Result<[u8; 16], FormatError> {
        let s = self.bytes(16)?;
        let mut out = [0u8; 16];
        out.copy_from_slice(s);
        Ok(out)
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], FormatError> {
        self.need(n)?;
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// NUL-terminated C string; advances past the terminator. Empty if immediate NUL.
    pub fn cstr(&mut self) -> Result<&'a [u8], FormatError> {
        let start = self.pos;
        while self.pos < self.buf.len() {
            if self.buf[self.pos] == 0 {
                let s = &self.buf[start..self.pos];
                self.pos += 1;
                return Ok(s);
            }
            self.pos += 1;
        }
        Err(FormatError::new(start, "unterminated cstr"))
    }

    /// Align `pos` forward to a multiple of `n` (typically 8).
    pub fn align(&mut self, n: usize) -> Result<(), FormatError> {
        if n == 0 {
            return Err(FormatError::new(self.pos, "align by zero"));
        }
        let rem = self.pos % n;
        if rem != 0 {
            let pad = n - rem;
            self.need(pad)?;
            self.pos += pad;
        }
        Ok(())
    }

    pub fn skip(&mut self, n: usize) -> Result<(), FormatError> {
        self.need(n)?;
        self.pos += n;
        Ok(())
    }

    pub fn set_pos(&mut self, pos: usize) -> Result<(), FormatError> {
        if pos > self.buf.len() {
            return Err(FormatError::new(pos, "set_pos past end"));
        }
        self.pos = pos;
        Ok(())
    }

    pub fn slice_from(&self, start: usize, len: usize) -> Result<&'a [u8], FormatError> {
        let end = start
            .checked_add(len)
            .ok_or_else(|| FormatError::new(start, "slice overflow"))?;
        if end > self.buf.len() {
            return Err(FormatError::new(start, "slice past end"));
        }
        Ok(&self.buf[start..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_primitives() {
        let data = [
            0x01u8, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
        ];
        let mut c = Cur::new(&data);
        assert_eq!(c.u8().unwrap(), 1);
        assert_eq!(c.u16_le().unwrap(), 2);
        assert_eq!(c.u32_le().unwrap(), 3);
        assert_eq!(c.u64_le().unwrap(), 4);
    }

    #[test]
    fn rejects_short_read() {
        let mut c = Cur::new(&[1, 2]);
        assert!(c.u32_le().is_err());
    }

    #[test]
    fn cstr_and_align() {
        let data = b"hi\0\0\0\0\0xx";
        let mut c = Cur::new(data);
        assert_eq!(c.cstr().unwrap(), b"hi");
        c.align(8).unwrap();
        assert_eq!(c.pos(), 8);
    }
}
