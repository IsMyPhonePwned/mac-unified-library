// SPDX-License-Identifier: GPL-3.0-only
//! Chunkset (tag 0x600D) BV41 / BV4- / BV4$ LZ4 stream.

use mul_core::{Cur, FormatError};

const BV41: &[u8; 4] = b"bv41";
const BV4_DASH: &[u8; 4] = b"bv4-";
const BV4_END: &[u8; 4] = b"bv4$";

/// Decompress a chunkset payload into `out` (reused buffer). Returns decompressed length.
pub fn decompress_into(data: &[u8], out: &mut Vec<u8>) -> Result<usize, FormatError> {
    out.clear();
    let mut c = Cur::new(data);
    while c.remaining() >= 4 {
        let mag = c.bytes(4)?;
        if mag == BV4_END {
            break;
        }
        if mag == BV41 {
            let unc = c.u32_le()? as usize;
            let comp = c.u32_le()? as usize;
            let payload = c.bytes(comp)?;
            let start = out.len();
            out.resize(start + unc, 0);
            match lz4_flex::block::decompress_into(payload, &mut out[start..]) {
                Ok(n) => {
                    out.truncate(start + n);
                }
                Err(e) => {
                    out.truncate(start);
                    return Err(FormatError::new(
                        c.pos(),
                        format!("lz4 decompress: {e}"),
                    ));
                }
            }
        } else if mag == BV4_DASH {
            let unc = c.u32_le()? as usize;
            let payload = c.bytes(unc)?;
            out.extend_from_slice(payload);
        } else {
            return Err(FormatError::new(
                c.pos().saturating_sub(4),
                format!("unknown chunkset magic {:02x?}", mag),
            ));
        }
    }
    Ok(out.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncompressed_block() {
        let mut data = Vec::new();
        data.extend_from_slice(b"bv4-");
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(b"abcd");
        data.extend_from_slice(b"bv4$");
        let mut out = Vec::new();
        decompress_into(&data, &mut out).unwrap();
        assert_eq!(&out, b"abcd");
    }
}
