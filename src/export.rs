//! Row formatting for `/api/export`: NDJSON (re-ingestable through `/ingest`) and CSV.

use crate::store::Row;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Ndjson,
    Csv,
}

impl Format {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "" | "ndjson" => Some(Format::Ndjson),
            "csv" => Some(Format::Csv),
            _ => None,
        }
    }

    pub fn content_type(self) -> &'static str {
        match self {
            Format::Ndjson => "application/x-ndjson",
            Format::Csv => "text/csv; charset=utf-8",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Format::Ndjson => "ndjson",
            Format::Csv => "csv",
        }
    }

    /// Text to write before the first row.
    pub fn header(self) -> &'static str {
        match self {
            Format::Ndjson => "",
            Format::Csv => "id,ts,time,host,app,severity,message,fields\r\n",
        }
    }

    pub fn write_row(self, out: &mut String, row: &Row) {
        match self {
            Format::Ndjson => {
                // Row only holds strings and numbers, so serialization cannot fail.
                out.push_str(&serde_json::to_string(row).unwrap_or_default());
                out.push('\n');
            }
            Format::Csv => {
                let time = chrono::DateTime::from_timestamp_millis(row.ts)
                    .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
                    .unwrap_or_default();
                let fields = row
                    .fields
                    .as_ref()
                    .map(|v| v.to_string())
                    .unwrap_or_default();
                let cells = [
                    row.id.to_string(),
                    row.ts.to_string(),
                    time,
                    row.host.clone(),
                    row.app.clone(),
                    row.severity.to_string(),
                    row.message.clone(),
                    fields,
                ];
                for (i, cell) in cells.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    csv_cell(out, cell);
                }
                out.push_str("\r\n");
            }
        }
    }
}

/// RFC 4180: quote cells containing a comma, quote or line break, doubling inner quotes.
fn csv_cell(out: &mut String, cell: &str) {
    if cell.contains([',', '"', '\n', '\r']) {
        out.push('"');
        out.push_str(&cell.replace('"', "\"\""));
        out.push('"');
    } else {
        out.push_str(cell);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn row(message: &str, fields: Option<serde_json::Value>) -> Row {
        Row {
            id: 7,
            ts: 1_700_000_000_123,
            host: "pve".into(),
            app: "sshd".into(),
            severity: 3,
            message: message.into(),
            fields,
        }
    }

    #[test]
    fn format_names() {
        assert_eq!(Format::parse(""), Some(Format::Ndjson));
        assert_eq!(Format::parse("csv"), Some(Format::Csv));
        assert_eq!(Format::parse("xml"), None);
    }

    #[test]
    fn ndjson_is_one_json_object_per_line_that_ingest_understands() {
        let mut out = String::new();
        let r = row("multi\nline \"quoted\"", Some(json!({"act": "blocked"})));
        Format::Ndjson.write_row(&mut out, &r);
        assert_eq!(
            out.matches('\n').count(),
            1,
            "embedded newlines are escaped"
        );
        let v: serde_json::Value = serde_json::from_str(out.trim_end()).unwrap();
        // The same keys /ingest reads, so an export can be loaded into another instance.
        let e = crate::api::entry_from_json(&v, 0).unwrap();
        assert_eq!(
            (e.ts, e.host.as_str(), e.app.as_str(), e.severity),
            (r.ts, "pve", "sshd", 3)
        );
        assert_eq!(e.message, r.message);
        assert_eq!(e.fields["act"], "blocked");
    }

    #[test]
    fn csv_quotes_and_escapes() {
        let mut out = String::from(Format::Csv.header());
        Format::Csv.write_row(&mut out, &row("plain", None));
        Format::Csv.write_row(&mut out, &row("a, \"b\"\nc", Some(json!({"k": "v"}))));
        let lines: Vec<&str> = out.split("\r\n").collect();
        assert_eq!(lines[0], "id,ts,time,host,app,severity,message,fields");
        assert_eq!(
            lines[1],
            "7,1700000000123,2023-11-14T22:13:20.123Z,pve,sshd,3,plain,"
        );
        // The message and the JSON fields (which contain quotes) are quoted; the newline
        // inside the message stays inside its quoted cell.
        assert_eq!(
            lines[2],
            "7,1700000000123,2023-11-14T22:13:20.123Z,pve,sshd,3,\"a, \"\"b\"\"\nc\",\"{\"\"k\"\":\"\"v\"\"}\""
        );
        assert!(out.ends_with("\r\n"));
    }
}
