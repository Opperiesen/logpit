//! Snappy block decompression (the format Promtail and Alloy use for Loki pushes).
//!
//! A block starts with the uncompressed length as a varint, followed by elements: literals and
//! copies of earlier output. The declared length is checked against a limit before anything is
//! allocated, and every offset and length is checked, so hostile input cannot make this allocate
//! a lot or read out of bounds.

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The input ended in the middle of an element.
    Truncated,
    /// The declared uncompressed size is larger than allowed.
    TooLarge,
    /// A copy refers to data that does not exist, or the output does not match the declared size.
    Corrupt,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Error::Truncated => "truncated snappy data",
            Error::TooLarge => "snappy data too large",
            Error::Corrupt => "corrupt snappy data",
        })
    }
}

/// Decompresses one snappy block, refusing to produce more than `max_len` bytes.
pub fn decompress(input: &[u8], max_len: usize) -> Result<Vec<u8>, Error> {
    // Preamble: uncompressed length as a little-endian base-128 varint.
    let (mut declared, mut shift, mut pos) = (0usize, 0u32, 0usize);
    loop {
        let byte = *input.get(pos).ok_or(Error::Truncated)?;
        pos += 1;
        if shift > 28 {
            return Err(Error::Corrupt);
        }
        declared |= usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    if declared > max_len {
        return Err(Error::TooLarge);
    }
    let mut out: Vec<u8> = Vec::with_capacity(declared);

    while pos < input.len() {
        let tag = input[pos];
        pos += 1;
        let (len, offset) = match tag & 0b11 {
            // Literal: the length is in the tag, or in the 1-4 bytes that follow it.
            0b00 => {
                let mut len = usize::from(tag >> 2);
                if len >= 60 {
                    let extra = len - 59;
                    let bytes = input.get(pos..pos + extra).ok_or(Error::Truncated)?;
                    pos += extra;
                    len = bytes
                        .iter()
                        .rev()
                        .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
                }
                len = len.checked_add(1).ok_or(Error::Corrupt)?;
                let data = input
                    .get(pos..pos.checked_add(len).ok_or(Error::Corrupt)?)
                    .ok_or(Error::Truncated)?;
                if out.len() + len > declared {
                    return Err(Error::Corrupt);
                }
                out.extend_from_slice(data);
                pos += len;
                continue;
            }
            // Copy with a 1-byte offset: length 4-11, offset up to 2047.
            0b01 => {
                let low = *input.get(pos).ok_or(Error::Truncated)?;
                pos += 1;
                (
                    4 + usize::from((tag >> 2) & 0b111),
                    (usize::from(tag >> 5) << 8) | usize::from(low),
                )
            }
            // Copy with a 2-byte offset.
            0b10 => {
                let bytes = input.get(pos..pos + 2).ok_or(Error::Truncated)?;
                pos += 2;
                (
                    1 + usize::from(tag >> 2),
                    usize::from(u16::from_le_bytes([bytes[0], bytes[1]])),
                )
            }
            // Copy with a 4-byte offset.
            _ => {
                let bytes = input.get(pos..pos + 4).ok_or(Error::Truncated)?;
                pos += 4;
                (
                    1 + usize::from(tag >> 2),
                    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize,
                )
            }
        };
        if offset == 0 || offset > out.len() || out.len() + len > declared {
            return Err(Error::Corrupt);
        }
        // The copy may overlap its own output (offset < len repeats a pattern), so go byte by byte.
        let start = out.len() - offset;
        for i in 0..len {
            let b = out[start + i];
            out.push(b);
        }
    }
    if out.len() != declared {
        return Err(Error::Corrupt);
    }
    Ok(out)
}

/// A literal-only encoder, enough to build valid blocks for tests.
#[cfg(test)]
pub(crate) fn compress_literal(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut n = data.len();
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        out.push(if n == 0 { byte } else { byte | 0x80 });
        if n == 0 {
            break;
        }
    }
    for chunk in data.chunks(65_536) {
        let len = chunk.len() - 1;
        if len < 60 {
            out.push((len as u8) << 2);
        } else if len < 256 {
            out.extend([60 << 2, len as u8]);
        } else {
            out.extend([61 << 2, (len & 0xff) as u8, (len >> 8) as u8]);
        }
        out.extend_from_slice(chunk);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_round_trip_across_length_encodings() {
        for size in [
            0usize, 1, 59, 60, 61, 255, 256, 257, 65_535, 65_536, 200_000,
        ] {
            let data: Vec<u8> = (0..size).map(|i| (i * 7 % 251) as u8).collect();
            assert_eq!(
                decompress(&compress_literal(&data), 1 << 20).unwrap(),
                data,
                "size {size}"
            );
        }
    }

    #[test]
    fn copies_including_overlapping_ones() {
        // "abc" then a 2-byte-offset copy of length 9 at offset 3 repeats the pattern.
        let two_byte = [12, 0x08, b'a', b'b', b'c', ((9 - 1) << 2) | 0b10, 3, 0];
        assert_eq!(decompress(&two_byte, 100).unwrap(), b"abcabcabcabc");
        // The same with a 1-byte-offset copy: length 9, offset 3.
        let one_byte = [12, 0x08, b'a', b'b', b'c', ((9 - 4) << 2) | 0b01, 3];
        assert_eq!(decompress(&one_byte, 100).unwrap(), b"abcabcabcabc");
        // And a 4-byte-offset copy.
        let four_byte = [
            12,
            0x08,
            b'a',
            b'b',
            b'c',
            ((9 - 1) << 2) | 0b11,
            3,
            0,
            0,
            0,
        ];
        assert_eq!(decompress(&four_byte, 100).unwrap(), b"abcabcabcabc");
        // A copy that is not overlapping: "hello world " + copy "hello" (offset 12).
        let mut data = vec![17u8, (11 << 2) as u8];
        data.extend_from_slice(b"hello world ");
        data.extend([((5 - 4) << 2) | 0b01, 12]);
        assert_eq!(decompress(&data, 100).unwrap(), b"hello world hello");
    }

    #[test]
    fn invalid_input_is_rejected_without_panicking() {
        assert_eq!(decompress(&[], 10), Err(Error::Truncated));
        assert_eq!(
            decompress(&[0x80], 10),
            Err(Error::Truncated),
            "varint never ends"
        );
        assert_eq!(
            decompress(&[0x90, 0x4e], 10),
            Err(Error::TooLarge),
            "declared size over the limit"
        );
        assert_eq!(
            decompress(&[3, 0x08, b'a'], 10),
            Err(Error::Truncated),
            "literal cut short"
        );
        assert_eq!(
            decompress(&[5, 0x08, b'a', b'b', b'c'], 10),
            Err(Error::Corrupt),
            "output shorter than declared"
        );
        assert_eq!(
            decompress(&[2, 0x08, b'a', b'b', b'c'], 10),
            Err(Error::Corrupt),
            "output longer than declared"
        );
        // A copy before any data, with offset 0, or beyond the output so far.
        assert_eq!(
            decompress(&[4, (3 << 2) | 0b01, 1], 10),
            Err(Error::Corrupt)
        );
        assert_eq!(
            decompress(&[6, 0x00, b'a', (3 << 2) | 0b01, 0], 10),
            Err(Error::Corrupt),
            "offset 0"
        );
        assert_eq!(
            decompress(&[6, 0x00, b'a', (3 << 2) | 0b01, 5], 10),
            Err(Error::Corrupt),
            "offset too far"
        );
        // A varint of more than five bytes is refused.
        assert_eq!(
            decompress(&[0xff, 0xff, 0xff, 0xff, 0xff, 0x7f], usize::MAX),
            Err(Error::Corrupt)
        );
    }

    #[test]
    fn declared_size_is_checked_before_allocating() {
        // 4 GiB declared in five bytes: refused immediately, with nothing allocated.
        assert_eq!(
            decompress(&[0x80, 0x80, 0x80, 0x80, 0x10], 1 << 20),
            Err(Error::TooLarge)
        );
    }

    #[test]
    fn random_garbage_never_panics() {
        // A small xorshift generator: deterministic, so a failure is reproducible.
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..20_000 {
            let len = {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x % 64) as usize
            };
            let data: Vec<u8> = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    (x >> 24) as u8
                })
                .collect();
            let _ = decompress(&data, 4096);
        }
    }
}
