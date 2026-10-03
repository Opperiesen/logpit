//! ArcSight Common Event Format (CEF) parsing, as emitted by UniFi's SIEM export.
//!
//! `CEF:Version|Vendor|Product|DeviceVersion|SignatureID|Name|Severity|key=value key=value …`
//!
//! Header fields escape `|` and `\` with a backslash. Extension values may contain
//! spaces: a value runs until the next ` key=` and may escape `=`, `\`, `\n`, `\r`.

use std::collections::BTreeMap;

use crate::model::LogEntry;
use crate::structured::{MAX_KEY_BYTES, clip};

const MAX_FIELDS: usize = 64;

#[derive(Debug, PartialEq)]
pub struct Cef {
    pub version: String,
    pub vendor: String,
    pub product: String,
    pub device_version: String,
    pub signature_id: String,
    pub name: String,
    pub severity: String,
    pub extension: Vec<(String, String)>,
}

fn is_key_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'[' | b']')
}

/// Reads one `|`-terminated header field, returning it unescaped and the remainder.
fn header_field(s: &str) -> Option<(String, &str)> {
    let mut out = String::new();
    let mut chars = s.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some((_, n @ ('|' | '\\'))) => out.push(n),
                Some((_, n)) => {
                    out.push('\\');
                    out.push(n);
                }
                None => out.push('\\'),
            },
            '|' => return Some((out, &s[i + 1..])),
            _ => out.push(c),
        }
    }
    None
}

fn unescape_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut chars = v.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some(n @ ('=' | '\\')) => out.push(n),
            Some(n) => {
                out.push('\\');
                out.push(n);
            }
            None => out.push('\\'),
        }
    }
    out
}

pub fn parse_extension(ext: &str) -> Vec<(String, String)> {
    let b = ext.as_bytes();
    // (key start, '=' position) for every `key=` that begins a token.
    let mut marks: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let at_token_start = i == 0 || b[i - 1] == b' ';
        if at_token_start && is_key_byte(b[i]) {
            let mut j = i;
            while j < b.len() && is_key_byte(b[j]) {
                j += 1;
            }
            if j < b.len() && b[j] == b'=' {
                marks.push((i, j));
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }

    marks
        .iter()
        .enumerate()
        .map(|(n, &(key_start, eq))| {
            let end = marks.get(n + 1).map_or(ext.len(), |next| next.0 - 1);
            let value = ext[eq + 1..end].trim_end();
            (ext[key_start..eq].to_string(), unescape_value(value))
        })
        .collect()
}

/// Parses `text` if it is a CEF record (optionally preceded by whitespace).
pub fn parse(text: &str) -> Option<Cef> {
    let rest = text.trim_start().strip_prefix("CEF:")?.trim_start();
    let (version, rest) = header_field(rest)?;
    if version.is_empty() || !version.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (vendor, rest) = header_field(rest)?;
    let (product, rest) = header_field(rest)?;
    let (device_version, rest) = header_field(rest)?;
    let (signature_id, rest) = header_field(rest)?;
    let (name, rest) = header_field(rest)?;
    let (severity, rest) = header_field(rest)?;
    Some(Cef {
        version,
        vendor,
        product,
        device_version,
        signature_id,
        name,
        severity,
        extension: parse_extension(rest),
    })
}

/// If the entry carries a CEF record, replaces its message with a readable summary
/// and moves the structured data into `fields`. Other entries are left untouched.
pub fn enrich(entry: &mut LogEntry) {
    // A syslog 3164 parser reads the leading `CEF` of `CEF:0|…` as the program tag.
    let raw = if entry.app == "CEF" {
        format!("CEF:{}", entry.message)
    } else if entry.message.trim_start().starts_with("CEF:") {
        entry.message.clone()
    } else {
        return;
    };
    let Some(cef) = parse(&raw) else { return };

    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    let header = [
        ("cef_version", &cef.version),
        ("cef_vendor", &cef.vendor),
        ("cef_product", &cef.product),
        ("cef_device_version", &cef.device_version),
        ("cef_signature_id", &cef.signature_id),
        ("cef_name", &cef.name),
        ("cef_severity", &cef.severity),
    ];
    for (k, v) in header {
        fields.insert(k.to_string(), clip(v));
    }
    for (k, v) in &cef.extension {
        if fields.len() >= MAX_FIELDS {
            break;
        }
        if !k.is_empty() && k.len() <= MAX_KEY_BYTES {
            fields.insert(k.clone(), clip(v));
        }
    }

    let msg = cef
        .extension
        .iter()
        .find(|(k, _)| k == "msg")
        .map(|(_, v)| v.as_str());
    entry.message = match (cef.name.is_empty(), msg) {
        (false, Some(m)) if !m.is_empty() => format!("{}: {m}", cef.name),
        (false, _) => cef.name.clone(),
        (true, Some(m)) if !m.is_empty() => m.to_string(),
        (true, _) => entry.message.clone(),
    };
    if !cef.product.is_empty() {
        entry.app = cef.product.clone();
    }
    entry.fields = fields;
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNIFI: &str = "CEF:0|Ubiquiti|UniFi Network|10.6.106|203|Blocked by Firewall|4|UNIFIcategory=Security UNIFIhost=Dream Router 7 proto=TCP spt=64125 dpt=57546 act=blocked app=Other UNIFIpolicyName=Block IoT to LAN";

    fn get<'a>(c: &'a Cef, key: &str) -> Option<&'a str> {
        c.extension
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn parses_unifi_event_with_spaces_in_values() {
        let c = parse(UNIFI).unwrap();
        assert_eq!(
            (c.vendor.as_str(), c.product.as_str()),
            ("Ubiquiti", "UniFi Network")
        );
        assert_eq!(
            (
                c.signature_id.as_str(),
                c.name.as_str(),
                c.severity.as_str()
            ),
            ("203", "Blocked by Firewall", "4")
        );
        assert_eq!(get(&c, "UNIFIhost"), Some("Dream Router 7"));
        assert_eq!(get(&c, "UNIFIpolicyName"), Some("Block IoT to LAN"));
        assert_eq!(get(&c, "spt"), Some("64125"));
        assert_eq!(c.extension.len(), 8);
    }

    #[test]
    fn header_and_value_escapes() {
        let c =
            parse(r"CEF:0|Ven\|dor|Prod\\uct|1|2|Na\|me|5|msg=a\=b\\c\nline src=1.2.3.4").unwrap();
        assert_eq!(c.vendor, "Ven|dor");
        assert_eq!(c.product, r"Prod\uct");
        assert_eq!(c.name, "Na|me");
        assert_eq!(get(&c, "msg"), Some("a=b\\c\nline"));
        assert_eq!(get(&c, "src"), Some("1.2.3.4"));
    }

    #[test]
    fn empty_and_missing_extension() {
        assert!(parse("CEF:0|a|b|c|d|e|1|").unwrap().extension.is_empty());
        let c = parse("CEF:0|a|b|c|d|e|1|k1= k2=v").unwrap();
        assert_eq!(get(&c, "k1"), Some(""));
        assert_eq!(get(&c, "k2"), Some("v"));
    }

    #[test]
    fn rejects_non_cef_and_truncated_headers() {
        for s in [
            "",
            "hello",
            "CEF",
            "CEF:",
            "CEF:0|a|b",
            "CEF:x|a|b|c|d|e|1|k=v",
            "CEF:0|a|b|c|d|e",
            "cef:0|a|b|c|d|e|1|",
        ] {
            assert!(parse(s).is_none(), "{s:?}");
        }
    }

    #[test]
    fn never_panics_on_odd_input() {
        for s in [
            "CEF:0|é|é|é|é|é|é|é=é é=",
            "CEF:0|a|b|c|d|e|1|=",
            "CEF:0|a|b|c|d|e|1|==  =x",
            "CEF:0|a|b|c|d|e|1|\\",
            "CEF:0|a|b|c|d|e|1|k=\\",
            "CEF:0|\\|",
            "CEF:0|a|b|c|d|e|1|a= =b  c=d=",
        ] {
            let _ = parse(s);
        }
    }

    #[test]
    fn enrich_from_syslog_tag_form() {
        // The 3164 parser yields app="CEF" and the rest of the record as message.
        let mut e = LogEntry {
            app: "CEF".into(),
            message: UNIFI.strip_prefix("CEF:").unwrap().into(),
            severity: 6,
            ..Default::default()
        };
        enrich(&mut e);
        assert_eq!(e.app, "UniFi Network");
        assert_eq!(e.message, "Blocked by Firewall");
        assert_eq!(e.severity, 6);
        assert_eq!(e.fields.get("act").map(String::as_str), Some("blocked"));
        assert_eq!(
            e.fields.get("cef_name").map(String::as_str),
            Some("Blocked by Firewall")
        );
    }

    #[test]
    fn enrich_from_message_form_uses_msg() {
        let mut e = LogEntry {
            message: "CEF:0|Ubiquiti|UniFi Network|10|544|Network Accessed|4|src=192.168.1.241 msg=admin accessed UniFi Network".into(),
            ..Default::default()
        };
        enrich(&mut e);
        assert_eq!(e.message, "Network Accessed: admin accessed UniFi Network");
        assert_eq!(
            e.fields.get("src").map(String::as_str),
            Some("192.168.1.241")
        );
    }

    #[test]
    fn enrich_leaves_other_entries_alone() {
        let mut e = LogEntry {
            app: "sshd".into(),
            message: "Accepted publickey".into(),
            ..Default::default()
        };
        let before = e.clone();
        enrich(&mut e);
        assert_eq!(e, before);
        // Looks like CEF but is not parseable: untouched.
        let mut bad = LogEntry {
            app: "CEF".into(),
            message: "not a record".into(),
            ..Default::default()
        };
        let before = bad.clone();
        enrich(&mut bad);
        assert_eq!(bad, before);
    }

    #[test]
    fn field_count_is_capped() {
        let ext: String = (0..200).map(|i| format!("k{i}=v ")).collect();
        let mut e = LogEntry {
            message: format!("CEF:0|a|b|c|d|e|1|{ext}"),
            ..Default::default()
        };
        enrich(&mut e);
        assert_eq!(e.fields.len(), MAX_FIELDS);
    }
}
