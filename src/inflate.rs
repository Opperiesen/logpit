//! gzip and zlib decompression for request bodies and datagrams (OTLP exporters and many log
//! shippers compress by default). The deflate stream itself is handled by `miniz_oxide`, a pure
//! Rust implementation; the gzip and zlib framing is checked here, including the gzip checksum
//! and length, and the output is capped so a small input cannot expand without limit.

use miniz_oxide::inflate::{decompress_to_vec_with_limit, decompress_to_vec_zlib_with_limit};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Not a gzip or zlib stream, or damaged.
    Invalid(&'static str),
    /// The decompressed data would exceed the limit.
    TooLarge,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Invalid(why) => write!(f, "invalid compressed data: {why}"),
            Error::TooLarge => f.write_str("decompressed data too large"),
        }
    }
}

/// CRC-32 (IEEE), as gzip uses.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn map_error(e: miniz_oxide::inflate::DecompressError) -> Error {
    use miniz_oxide::inflate::TINFLStatus;
    match e.status {
        TINFLStatus::HasMoreOutput => Error::TooLarge,
        TINFLStatus::FailedCannotMakeProgress => Error::Invalid("the stream is cut short"),
        _ => Error::Invalid("the deflate stream is damaged"),
    }
}

/// Decompresses a gzip file (RFC 1952), refusing to produce more than `max_len` bytes.
pub fn gunzip(data: &[u8], max_len: usize) -> Result<Vec<u8>, Error> {
    let bad = Error::Invalid;
    if data.len() < 18 || data[0] != 0x1f || data[1] != 0x8b {
        return Err(bad("not a gzip stream"));
    }
    if data[2] != 8 {
        return Err(bad("unsupported compression method"));
    }
    let flags = data[3];
    let mut pos = 10;
    if flags & 0x04 != 0 {
        // Extra field: a 2-byte length, then that many bytes.
        let len = usize::from(u16::from_le_bytes([
            *data.get(pos).ok_or(bad("truncated header"))?,
            *data.get(pos + 1).ok_or(bad("truncated header"))?,
        ]));
        pos = pos.checked_add(2 + len).ok_or(bad("truncated header"))?;
    }
    for flag in [0x08, 0x10] {
        // File name and comment: zero-terminated strings.
        if flags & flag != 0 {
            let rest = data.get(pos..).ok_or(bad("truncated header"))?;
            pos += rest
                .iter()
                .position(|b| *b == 0)
                .ok_or(bad("truncated header"))?
                + 1;
        }
    }
    if flags & 0x02 != 0 {
        pos += 2; // header checksum
    }
    if data.len() < pos + 8 {
        return Err(bad("truncated stream"));
    }
    let (body, trailer) = data[pos..].split_at(data.len() - pos - 8);
    let out = decompress_to_vec_with_limit(body, max_len).map_err(map_error)?;
    let crc = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    let size = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
    if size != out.len() as u32 {
        return Err(bad("the length does not match the trailer"));
    }
    if crc != crc32(&out) {
        return Err(bad("the checksum does not match the trailer"));
    }
    Ok(out)
}

/// Decompresses a zlib stream (RFC 1950), refusing to produce more than `max_len` bytes.
pub fn zlib(data: &[u8], max_len: usize) -> Result<Vec<u8>, Error> {
    decompress_to_vec_zlib_with_limit(data, max_len).map_err(map_error)
}

/// Whether `data` starts like a gzip file.
pub fn looks_like_gzip(data: &[u8]) -> bool {
    data.starts_with(&[0x1f, 0x8b])
}

/// Whether `data` starts like a zlib stream (CMF byte 0x78, a valid header checksum).
pub fn looks_like_zlib(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0x78 && (u16::from(data[0]) << 8 | u16::from(data[1])) % 31 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // Produced by Python's gzip and zlib modules, an independent implementation.
    const GZIP: &[u8] = &[
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xcb, 0x48, 0xcd, 0xc9, 0xc9,
        0x57, 0xc8, 0x40, 0x27, 0x75, 0x14, 0x7c, 0xf2, 0xd3, 0x03, 0x32, 0x4b, 0x14, 0x31, 0xa5,
        0x48, 0x56, 0xc0, 0xc0, 0xc8, 0xc4, 0xcc, 0xc2, 0xca, 0xc6, 0xce, 0xc1, 0xc9, 0xc5, 0xcd,
        0xc3, 0xcb, 0xc7, 0x2f, 0x20, 0x28, 0x24, 0x2c, 0x22, 0x2a, 0x26, 0x2e, 0x21, 0x29, 0x25,
        0x2d, 0x23, 0x2b, 0x27, 0x0f, 0x00, 0xd3, 0xee, 0xe4, 0x69, 0x83, 0x00, 0x00, 0x00,
    ];
    const GZIP_NAMED: &[u8] = &[
        0x1f, 0x8b, 0x08, 0x08, 0x39, 0x30, 0x00, 0x00, 0x02, 0xff, 0x61, 0x70, 0x70, 0x2e, 0x6c,
        0x6f, 0x67, 0x00, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xc8, 0x40, 0x27, 0x75, 0x14, 0x7c,
        0xf2, 0xd3, 0x03, 0x32, 0x4b, 0x14, 0x31, 0xa5, 0x48, 0x56, 0xc0, 0xc0, 0xc8, 0xc4, 0xcc,
        0xc2, 0xca, 0xc6, 0xce, 0xc1, 0xc9, 0xc5, 0xcd, 0xc3, 0xcb, 0xc7, 0x2f, 0x20, 0x28, 0x24,
        0x2c, 0x22, 0x2a, 0x26, 0x2e, 0x21, 0x29, 0x25, 0x2d, 0x23, 0x2b, 0x27, 0x0f, 0x00, 0xd3,
        0xee, 0xe4, 0x69, 0x83, 0x00, 0x00, 0x00,
    ];
    const ZLIB: &[u8] = &[
        0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xc8, 0x40, 0x27, 0x75, 0x14, 0x7c, 0xf2,
        0xd3, 0x03, 0x32, 0x4b, 0x14, 0x31, 0xa5, 0x48, 0x56, 0xc0, 0xc0, 0xc8, 0xc4, 0xcc, 0xc2,
        0xca, 0xc6, 0xce, 0xc1, 0xc9, 0xc5, 0xcd, 0xc3, 0xcb, 0xc7, 0x2f, 0x20, 0x28, 0x24, 0x2c,
        0x22, 0x2a, 0x26, 0x2e, 0x21, 0x29, 0x25, 0x2d, 0x23, 0x2b, 0x27, 0x0f, 0x00, 0x4d, 0x57,
        0x24, 0x95,
    ];
    const GZIP_EMPTY: &[u8] = &[
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x03, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    const PLAIN: &[u8] = b"hello hello hello hello, LogPit! hello hello hello hello, LogPit! hello hello hello hello, LogPit! \x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";

    #[test]
    fn decompresses_real_gzip_and_zlib_streams() {
        assert_eq!(gunzip(GZIP, 1 << 20).unwrap(), PLAIN);
        assert_eq!(
            gunzip(GZIP_NAMED, 1 << 20).unwrap(),
            PLAIN,
            "a header with a file name"
        );
        assert_eq!(zlib(ZLIB, 1 << 20).unwrap(), PLAIN);
        assert_eq!(gunzip(GZIP_EMPTY, 1 << 20).unwrap(), b"");
        assert_eq!(
            crc32(b"123456789"),
            0xcbf4_3926,
            "the standard CRC-32 check value"
        );
    }

    #[test]
    fn the_output_is_capped() {
        assert_eq!(
            gunzip(GZIP, PLAIN.len()).unwrap(),
            PLAIN,
            "exactly at the limit"
        );
        assert_eq!(gunzip(GZIP, PLAIN.len() - 1), Err(Error::TooLarge));
        assert_eq!(zlib(ZLIB, 10), Err(Error::TooLarge));
        // A decompression bomb: a tiny stream that expands a lot is refused, not materialized.
        let bomb = [
            0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3, 0xed, 0xc1, 1, 1, 0, 0, 0, 0x80, 0x90, 0xfe, 0xaf,
            0x6e,
        ];
        assert!(gunzip(&bomb, 1000).is_err());
    }

    #[test]
    fn damaged_or_foreign_data_is_rejected() {
        assert!(gunzip(b"", 100).is_err());
        assert!(
            gunzip(
                b"not gzip at all, but long enough to pass the length check",
                100
            )
            .is_err()
        );
        assert!(
            gunzip(&GZIP[..GZIP.len() - 3], 1 << 20).is_err(),
            "truncated trailer"
        );
        assert!(
            gunzip(&GZIP[..GZIP.len() / 2], 1 << 20).is_err(),
            "truncated body"
        );
        let mut bad_crc = GZIP.to_vec();
        let n = bad_crc.len();
        bad_crc[n - 8] ^= 0xff;
        assert_eq!(
            gunzip(&bad_crc, 1 << 20),
            Err(Error::Invalid("the checksum does not match the trailer"))
        );
        let mut bad_len = GZIP.to_vec();
        bad_len[n - 1] ^= 0x01;
        assert_eq!(
            gunzip(&bad_len, 1 << 20),
            Err(Error::Invalid("the length does not match the trailer"))
        );
        let mut flipped = GZIP.to_vec();
        flipped[20] ^= 0xff;
        assert!(
            gunzip(&flipped, 1 << 20).is_err(),
            "a flipped bit in the deflate stream"
        );
        assert!(zlib(b"\x78\x9cgarbage", 100).is_err());
        assert!(zlib(&ZLIB[..ZLIB.len() / 2], 1 << 20).is_err());
        // A header claiming optional fields that are not there.
        assert!(
            gunzip(
                &[
                    0x1f, 0x8b, 8, 0x0c, 0, 0, 0, 0, 0, 3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
                ],
                100
            )
            .is_err()
        );
    }

    #[test]
    fn random_garbage_never_panics() {
        let mut x: u64 = 0x1234_5678_9abc_def1;
        for i in 0..20_000 {
            let len = {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x % 96) as usize
            };
            let mut data: Vec<u8> = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    (x >> 24) as u8
                })
                .collect();
            // Half of them look like gzip or zlib so the framing code is exercised too.
            if i % 2 == 0 && data.len() > 2 {
                data[0] = 0x1f;
                data[1] = 0x8b;
                if data.len() > 3 {
                    data[2] = 8;
                }
            } else if data.len() > 2 {
                data[0] = 0x78;
                data[1] = 0x9c;
            }
            let _ = gunzip(&data, 4096);
            let _ = zlib(&data, 4096);
        }
    }

    #[test]
    fn detection() {
        assert!(looks_like_gzip(GZIP) && !looks_like_gzip(ZLIB));
        assert!(looks_like_zlib(ZLIB) && !looks_like_zlib(GZIP));
        assert!(!looks_like_zlib(b"{\"json\":1}") && !looks_like_gzip(b"{\"json\":1}"));
        assert!(!looks_like_zlib(b"x") && !looks_like_gzip(b""));
    }
}
