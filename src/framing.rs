//! Message framing for syslog over TCP and TLS.
//!
//! Two framings are accepted on the same connection and detected per message:
//! octet counting (`<length> <message>`, RFC 5425 / RFC 6587, which is what TLS senders are
//! required to use) and newline-delimited lines (what plain TCP senders usually emit).

use std::io;

use bytes::{Buf, BytesMut};
use tokio_util::codec::Decoder;

/// Longest length prefix accepted (`1234567`, so at most about 9 MB declared).
const MAX_DIGITS: usize = 7;

pub struct SyslogFrames {
    max_len: usize,
}

impl SyslogFrames {
    pub fn new(max_len: usize) -> Self {
        Self { max_len }
    }

    fn too_long(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("syslog frame longer than {} bytes", self.max_len),
        )
    }

    /// Tries octet counting at the start of `src`. `Ok(None)` means more bytes are needed,
    /// `Ok(Some(None))` that this is not octet counting (use newline framing), and
    /// `Ok(Some(Some(frame)))` a complete frame.
    #[allow(clippy::type_complexity)]
    fn octet_counted(&self, src: &mut BytesMut) -> io::Result<Option<Option<String>>> {
        let digits = src.iter().take_while(|b| b.is_ascii_digit()).count();
        if digits > MAX_DIGITS {
            return Ok(Some(None));
        }
        // Need the byte after the digits, and the one after the space to confirm a syslog
        // message (`<PRI>...`) follows, so a line that merely starts with a number is not mistaken
        // for a frame.
        if src.len() < digits + 2 {
            return Ok(None);
        }
        if src[digits] != b' ' || src[digits + 1] != b'<' {
            return Ok(Some(None));
        }
        let len: usize = std::str::from_utf8(&src[..digits])
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(usize::MAX);
        if len == 0 || len > self.max_len {
            return Err(self.too_long());
        }
        let start = digits + 1;
        if src.len() < start + len {
            src.reserve(start + len - src.len());
            return Ok(None);
        }
        src.advance(start);
        let frame = src.split_to(len);
        Ok(Some(Some(String::from_utf8_lossy(&frame).into_owned())))
    }

    fn line(&self, src: &mut BytesMut) -> io::Result<Option<String>> {
        match src.iter().position(|&b| b == b'\n') {
            Some(i) => {
                if i > self.max_len {
                    return Err(self.too_long());
                }
                let line = src.split_to(i + 1);
                Ok(Some(
                    String::from_utf8_lossy(&line)
                        .trim_end_matches(['\r', '\n'])
                        .to_string(),
                ))
            }
            None if src.len() > self.max_len => Err(self.too_long()),
            None => Ok(None),
        }
    }
}

impl Decoder for SyslogFrames {
    type Item = String;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<String>> {
        loop {
            // Blank lines and stray separators between messages carry nothing.
            while src.first().is_some_and(|b| matches!(b, b'\n' | b'\r')) {
                src.advance(1);
            }
            if src.is_empty() {
                return Ok(None);
            }
            if src[0].is_ascii_digit() {
                match self.octet_counted(src)? {
                    None => return Ok(None),
                    Some(Some(frame)) => return Ok(Some(frame)),
                    Some(None) => {} // not a frame: fall through to line framing
                }
            }
            match self.line(src)? {
                Some(line) if line.is_empty() => continue,
                other => return Ok(other),
            }
        }
    }

    /// At end of input, a final line without a trailing newline is still a message.
    fn decode_eof(&mut self, src: &mut BytesMut) -> io::Result<Option<String>> {
        if let Some(frame) = self.decode(src)? {
            return Ok(Some(frame));
        }
        if src.is_empty() {
            return Ok(None);
        }
        let rest = src.split();
        let text = String::from_utf8_lossy(&rest)
            .trim_end_matches(['\r', '\n'])
            .to_string();
        Ok((!text.is_empty()).then_some(text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(input: &[u8], max: usize) -> Vec<String> {
        let mut codec = SyslogFrames::new(max);
        let mut buf = BytesMut::from(input);
        let mut out = Vec::new();
        while let Some(f) = codec.decode(&mut buf).unwrap() {
            out.push(f);
        }
        out
    }

    #[test]
    fn newline_framing_like_before() {
        assert_eq!(
            all(b"<13>a\n<13>b\r\n\n<13>c\n", 1000),
            ["<13>a", "<13>b", "<13>c"]
        );
    }

    #[test]
    fn octet_counting() {
        assert_eq!(
            all(b"5 <1>ab5 <2>cd", 1000),
            ["<1>ab", "<2>cd"].map(String::from)
        );
        // The payload may contain newlines and digits.
        assert_eq!(all(b"9 <13>a\nb 1", 1000), ["<13>a\nb 1"]);
    }

    #[test]
    fn both_framings_on_one_connection() {
        assert_eq!(
            all(b"<13>plain\n6 <13>xy<14>next\n", 1000),
            ["<13>plain", "<13>xy", "<14>next"]
        );
    }

    #[test]
    fn a_line_that_starts_with_a_number_is_not_a_frame() {
        assert_eq!(
            all(b"42 apples\n123\n7 foo\n", 1000),
            ["42 apples", "123", "7 foo"]
        );
    }

    #[test]
    fn partial_input_waits_for_more() {
        let mut codec = SyslogFrames::new(1000);
        let mut buf = BytesMut::new();
        for chunk in [&b"1"[..], b"4 <1", b">hello wo", b"rld", b"X"] {
            buf.extend_from_slice(chunk);
            if chunk == b"rld" {
                assert_eq!(
                    codec.decode(&mut buf).unwrap().as_deref(),
                    Some("<1>hello world")
                );
            } else {
                assert!(codec.decode(&mut buf).unwrap().is_none(), "after {chunk:?}");
            }
        }
        // Not valid UTF-8 is replaced, never an error.
        let mut buf = BytesMut::from(&b"4 <1>\xff"[..]);
        assert_eq!(codec.decode(&mut buf).unwrap().unwrap(), "<1>\u{fffd}");
    }

    #[test]
    fn oversized_input_is_an_error() {
        let mut codec = SyslogFrames::new(10);
        assert!(
            codec
                .decode(&mut BytesMut::from(&b"11 <1>abcdefghi"[..]))
                .is_err()
        );
        assert!(codec.decode(&mut BytesMut::from(&b"0 <1>"[..])).is_err());
        assert!(
            codec
                .decode(&mut BytesMut::from(&b"<13>aaaaaaaaaaaaaaaaaaaa\n"[..]))
                .is_err()
        );
        assert!(
            codec
                .decode(&mut BytesMut::from(&b"<13>aaaaaaaaaaaaaaaaaaaa"[..]))
                .is_err()
        );
        // Absurd length prefixes are treated as text, not allocated.
        let mut roomy = SyslogFrames::new(1000);
        let mut buf = BytesMut::from(&b"99999999999 <1>x\n"[..]);
        assert_eq!(roomy.decode(&mut buf).unwrap().unwrap(), "99999999999 <1>x");
    }

    #[test]
    fn final_line_without_newline_is_kept_at_eof() {
        let mut codec = SyslogFrames::new(1000);
        let mut buf = BytesMut::from(&b"<13>first\n<13>last"[..]);
        assert_eq!(codec.decode_eof(&mut buf).unwrap().unwrap(), "<13>first");
        assert_eq!(codec.decode_eof(&mut buf).unwrap().unwrap(), "<13>last");
        assert!(codec.decode_eof(&mut buf).unwrap().is_none());
    }
}
