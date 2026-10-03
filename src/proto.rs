//! A minimal protobuf wire-format reader, enough for the small messages of Loki's push API and
//! OpenTelemetry's log export. Every read is bounds-checked and returns `None` on malformed input.

pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn done(&self) -> bool {
        self.pos >= self.buf.len()
    }

    pub(crate) fn varint(&mut self) -> Option<u64> {
        let (mut value, mut shift) = (0u64, 0u32);
        loop {
            let byte = *self.buf.get(self.pos)?;
            self.pos += 1;
            if shift >= 64 {
                return None;
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
            shift += 7;
        }
    }

    pub(crate) fn bytes(&mut self) -> Option<&'a [u8]> {
        let len = usize::try_from(self.varint()?).ok()?;
        let end = self.pos.checked_add(len)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    /// The next field's number and wire type.
    pub(crate) fn key(&mut self) -> Option<(u32, u8)> {
        let key = self.varint()?;
        Some((u32::try_from(key >> 3).ok()?, (key & 7) as u8))
    }

    /// Skips a value of the given wire type.
    pub(crate) fn skip(&mut self, wire: u8) -> Option<()> {
        match wire {
            0 => {
                self.varint()?;
            }
            1 => self.pos = self.pos.checked_add(8).filter(|e| *e <= self.buf.len())?,
            2 => {
                self.bytes()?;
            }
            5 => self.pos = self.pos.checked_add(4).filter(|e| *e <= self.buf.len())?,
            _ => return None,
        }
        Some(())
    }

    /// A little-endian `fixed64` (wire type 1).
    pub(crate) fn fixed64(&mut self) -> Option<u64> {
        let end = self.pos.checked_add(8)?;
        let bytes = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(u64::from_le_bytes(bytes.try_into().ok()?))
    }
}

/// Text from bytes; invalid UTF-8 is replaced rather than refused.
pub(crate) fn utf8(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A minimal protobuf encoder for the tests, written independently of the decoder above.
#[cfg(test)]
pub(crate) mod encode {
    pub(crate) fn varint(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return;
            }
            out.push(b | 0x80);
        }
    }

    pub(crate) fn len_field(no: u32, payload: &[u8], out: &mut Vec<u8>) {
        varint(u64::from(no << 3 | 2), out);
        varint(payload.len() as u64, out);
        out.extend_from_slice(payload);
    }

    pub(crate) fn num_field(no: u32, v: u64, out: &mut Vec<u8>) {
        varint(u64::from(no << 3), out);
        varint(v, out);
    }

    pub(crate) fn fixed64_field(no: u32, v: u64, out: &mut Vec<u8>) {
        varint(u64::from(no << 3 | 1), out);
        out.extend_from_slice(&v.to_le_bytes());
    }
}
