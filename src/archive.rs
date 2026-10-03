//! Cold archive: entries leaving the database through retention or the size cap are first
//! appended to one gzip file per UTC day (`<dir>/YYYY/MM/logpit-YYYY-MM-DD.ndjson.gz`), in the
//! NDJSON format `POST /ingest` reads, so they can be inspected with `zcat` or loaded again with
//! `logpit restore`.
//!
//! A file is a series of gzip members, one per batch written, each carrying the length of its
//! compressed data in an extra header field. Standard tools read them as one stream, and
//! `logpit restore` uses the lengths to read member by member, so memory stays small however
//! large a day is.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::Serialize;

use crate::store::Row;

/// Plain bytes put into one gzip member at most.
pub const MEMBER_BYTES: usize = 8 * 1024 * 1024;
/// A member may not expand beyond this when read back (it is never larger than `MEMBER_BYTES`
/// plus one line when written by LogPit).
pub const MAX_MEMBER_PLAIN: usize = 64 * 1024 * 1024;
const LEVEL: u8 = 6;

#[derive(Serialize)]
struct Line<'a> {
    ts: i64,
    host: &'a str,
    app: &'a str,
    severity: u8,
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    fields: Option<&'a serde_json::Value>,
}

/// The NDJSON line of an entry, in the format `/ingest` accepts.
pub fn ndjson_line(r: &Row) -> String {
    let line = Line {
        ts: r.ts,
        host: &r.host,
        app: &r.app,
        severity: r.severity,
        message: &r.message,
        fields: r.fields.as_ref(),
    };
    let mut text = serde_json::to_string(&line).unwrap_or_default();
    text.push('\n');
    text
}

/// One gzip member holding `data`, with the compressed length in an `LP` extra field.
pub fn gzip_member(data: &[u8]) -> Vec<u8> {
    let body = miniz_oxide::deflate::compress_to_vec(data, LEVEL);
    let mut out = Vec::with_capacity(body.len() + 30);
    // Magic, deflate, FEXTRA, no mtime, no extra flags, unknown OS.
    out.extend_from_slice(&[0x1f, 0x8b, 8, 0x04, 0, 0, 0, 0, 0, 0xff]);
    // Extra field: 8 bytes, one subfield "LP" with a 4-byte length.
    out.extend_from_slice(&[8, 0, b'L', b'P', 4, 0]);
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(&crate::inflate::crc32(data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

/// The members of an archive file, as slices. A file whose first member has no `LP` field (a
/// gzip made by another tool) is returned whole.
pub fn split_members(data: &[u8]) -> anyhow::Result<Vec<&[u8]>> {
    let mut members = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let rest = &data[pos..];
        let lp = (rest.len() >= 20
            && rest[..4] == [0x1f, 0x8b, 8, 0x04]
            && rest[10..16] == [8, 0, b'L', b'P', 4, 0])
        .then(|| u32::from_le_bytes([rest[16], rest[17], rest[18], rest[19]]) as usize);
        let Some(body_len) = lp else {
            if pos == 0 {
                return Ok(vec![data]);
            }
            anyhow::bail!("unexpected data at byte {pos}: not a LogPit archive member");
        };
        let end = 20 + body_len + 8;
        anyhow::ensure!(rest.len() >= end, "the archive is truncated at byte {pos}");
        members.push(&rest[..end]);
        pos += end;
    }
    Ok(members)
}

/// The plain text of one member.
pub fn read_member(member: &[u8]) -> anyhow::Result<Vec<u8>> {
    crate::inflate::gunzip(member, MAX_MEMBER_PLAIN).map_err(|e| anyhow::anyhow!("{e:?}"))
}

/// Writes entries to the archive directory.
pub struct Archiver {
    dir: PathBuf,
}

/// `<dir>/YYYY/MM/logpit-YYYY-MM-DD.ndjson.gz` for the UTC day of `ts`.
fn day_path(dir: &Path, ts: i64) -> PathBuf {
    let t = chrono::DateTime::from_timestamp_millis(ts).unwrap_or_default();
    dir.join(t.format("%Y").to_string())
        .join(t.format("%m").to_string())
        .join(t.format("logpit-%Y-%m-%d.ndjson.gz").to_string())
}

impl Archiver {
    /// Creates the directory if needed and checks that it can be written to.
    pub fn new(dir: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("cannot create the archive directory {}", dir.display()))?;
        let probe = dir.join(format!(".write-test-{}", std::process::id()));
        std::fs::write(&probe, b"ok")
            .with_context(|| format!("the archive directory {} is not writable", dir.display()))?;
        let _ = std::fs::remove_file(probe);
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    /// Appends `rows` to the file of each day they belong to and syncs it before returning, so
    /// the caller may delete them. Returns the number of compressed bytes written.
    pub fn write(&self, rows: &[Row]) -> anyhow::Result<u64> {
        let mut by_day: BTreeMap<PathBuf, String> = BTreeMap::new();
        for r in rows {
            by_day
                .entry(day_path(&self.dir, r.ts))
                .or_default()
                .push_str(&ndjson_line(r));
        }
        let mut written = 0;
        for (path, text) in by_day {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("cannot create {}", parent.display()))?;
            }
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .with_context(|| format!("cannot open {}", path.display()))?;
            for chunk in split_lines(&text, MEMBER_BYTES) {
                let member = gzip_member(chunk.as_bytes());
                file.write_all(&member)
                    .with_context(|| format!("cannot write {}", path.display()))?;
                written += member.len() as u64;
            }
            file.sync_data()
                .with_context(|| format!("cannot sync {}", path.display()))?;
        }
        Ok(written)
    }
}

/// `text` cut after a line boundary every `max` bytes or so.
fn split_lines(text: &str, max: usize) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    while start < text.len() {
        let mut end = (start + max).min(text.len());
        if end < text.len() {
            end = text[end..].find('\n').map_or(text.len(), |i| end + i + 1);
        }
        parts.push(&text[start..end]);
        start = end;
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(ts: i64, host: &str, msg: &str) -> Row {
        Row {
            id: 1,
            ts,
            host: host.into(),
            app: "app".into(),
            severity: 4,
            message: msg.into(),
            fields: None,
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("logpit-archive-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn a_member_round_trips_and_is_plain_gzip() {
        let data = b"line one\nline two\n".repeat(100);
        let member = gzip_member(&data);
        assert_eq!(&member[..4], &[0x1f, 0x8b, 8, 4]);
        assert_eq!(read_member(&member).unwrap(), data);
        assert_eq!(split_members(&member).unwrap(), [member.as_slice()]);
        // Empty input is a valid member too.
        assert_eq!(read_member(&gzip_member(b"")).unwrap(), b"");
    }

    #[test]
    fn concatenated_members_split_exactly_and_damage_is_detected() {
        let (a, b, c) = (
            gzip_member(b"first\n"),
            gzip_member(&vec![b'x'; 100_000]),
            gzip_member(b"third\n"),
        );
        let all = [a.clone(), b.clone(), c.clone()].concat();
        let members = split_members(&all).unwrap();
        assert_eq!(members.len(), 3);
        assert_eq!(read_member(members[0]).unwrap(), b"first\n");
        assert_eq!(read_member(members[1]).unwrap().len(), 100_000);
        assert_eq!(read_member(members[2]).unwrap(), b"third\n");
        // Truncated, and with trailing garbage.
        assert!(split_members(&all[..all.len() - 3]).is_err());
        let mut junk = all.clone();
        junk.extend_from_slice(b"junk");
        assert!(split_members(&junk).is_err());
        // A flipped byte in the data fails the checksum.
        let mut bad = b.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 0xff;
        assert!(read_member(&bad).is_err());
        // A gzip from another tool is one member.
        let foreign: &[u8] = &[
            0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3, 0x4b, 0x4c, 0x4a, 0x06, 0x00, 0xc2, 0x41, 0x24,
            0x35, 3, 0, 0, 0,
        ];
        assert_eq!(split_members(foreign).unwrap(), [foreign]);
        assert_eq!(read_member(foreign).unwrap(), b"abc");
    }

    #[test]
    fn lines_are_ingest_format_with_optional_fields() {
        let mut r = row(5, "h", "hello \"world\"\nnext");
        assert_eq!(
            ndjson_line(&r),
            "{\"ts\":5,\"host\":\"h\",\"app\":\"app\",\"severity\":4,\"message\":\"hello \\\"world\\\"\\nnext\"}\n"
        );
        r.fields = Some(serde_json::json!({"k": "v"}));
        let v: serde_json::Value = serde_json::from_str(ndjson_line(&r).trim()).unwrap();
        let back = crate::api::entry_from_json(&v, 0).unwrap();
        assert_eq!(
            (back.ts, back.host.as_str(), back.message.as_str()),
            (5, "h", "hello \"world\"\nnext")
        );
        assert_eq!(back.fields["k"], "v");
        assert!(v.get("id").is_none(), "the database id is not archived");
    }

    #[test]
    fn rows_land_in_the_file_of_their_utc_day_and_append() {
        let dir = temp_dir("days");
        let archiver = Archiver::new(&dir).unwrap();
        // 2026-10-03 23:59:59.999 and 2026-10-04 00:00:00.000 UTC.
        let (late, early) = (1_791_071_999_999, 1_791_072_000_000);
        archiver
            .write(&[row(late, "a", "one"), row(early, "a", "two")])
            .unwrap();
        archiver.write(&[row(late - 1000, "b", "three")]).unwrap();
        let day1 = dir.join("2026/10/logpit-2026-10-03.ndjson.gz");
        let day2 = dir.join("2026/10/logpit-2026-10-04.ndjson.gz");
        let text = |p: &Path| -> String {
            let bytes = std::fs::read(p).unwrap();
            split_members(&bytes)
                .unwrap()
                .into_iter()
                .map(|m| String::from_utf8(read_member(m).unwrap()).unwrap())
                .collect()
        };
        let d1 = text(&day1);
        assert_eq!(d1.lines().count(), 2);
        assert!(d1.contains("\"message\":\"one\"") && d1.contains("\"message\":\"three\""));
        assert_eq!(
            split_members(&std::fs::read(&day1).unwrap()).unwrap().len(),
            2,
            "one member per write"
        );
        assert!(text(&day2).contains("\"message\":\"two\""));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn big_batches_are_split_into_members_on_line_boundaries() {
        let text: String = (0..1000).map(|i| format!("line {i:04}\n")).collect();
        let parts = split_lines(&text, 100);
        assert!(parts.len() > 50);
        assert!(parts.iter().all(|p| p.ends_with('\n')));
        assert_eq!(parts.concat(), text);
        assert_eq!(split_lines("", 100), Vec::<&str>::new());
        assert_eq!(split_lines("no newline", 4), ["no newline"]);
    }

    #[test]
    fn an_unusable_directory_is_refused_up_front() {
        let dir = temp_dir("bad");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("a-file");
        std::fs::write(&file, b"x").unwrap();
        assert!(Archiver::new(&file.join("sub")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
