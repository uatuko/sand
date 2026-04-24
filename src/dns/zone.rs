// BIND-style zone file parser
//
// RFC 1035 §5   — master file format ($ORIGIN, $TTL, record syntax)
// RFC 1035 §3.3 — record types: SOA, A, NS, CNAME, MX, PTR, TXT
// RFC 3596 §2   — AAAA record

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use super::message::{RecordData, RecordType, ResourceRecord, CLASS_IN};

pub struct Zone {
    origin: String,
    records: Vec<ResourceRecord>,
}

impl Zone {
    // Load and parse a BIND-style zone file from disk (RFC 1035 §5).
    pub fn load(path: &Path) -> Result<Self, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        parse(&content)
    }

    // Look up records by owner name and QTYPE.
    //
    // Returns `None`  when the name does not exist at all → caller sends NXDOMAIN.
    // Returns `Some` (possibly empty) when the name exists → caller sends NOERROR
    // (with SOA in the authority section if the answer slice is empty — RFC 2308 §3).
    pub fn lookup(&self, name: &str, qtype: u16) -> Option<Vec<&ResourceRecord>> {
        let key = canon(name);
        let matches: Vec<&ResourceRecord> = self
            .records
            .iter()
            .filter(|rr| canon(&rr.name) == key)
            .filter(|rr| {
                qtype == RecordType::Any as u16
                    || RecordType::from_u16(qtype).map_or(false, |t| rr.data.rtype() == t)
            })
            .collect();

        // Distinguish "name not found" from "name found, type not present"
        let name_exists = self.records.iter().any(|rr| canon(&rr.name) == key);
        if !name_exists {
            None
        } else {
            Some(matches)
        }
    }

    // Return the zone SOA record for use in authority sections (RFC 2308 §3).
    pub fn soa(&self) -> Option<&ResourceRecord> {
        self.records
            .iter()
            .find(|rr| matches!(rr.data, RecordData::Soa { .. }))
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }
}

// Normalise a name to a lowercase FQDN without trailing dot for map lookups.
fn canon(name: &str) -> String {
    name.trim_end_matches('.').to_lowercase()
}

// ── Zone file parser ────────────────────────────────────────────────────────

fn parse(content: &str) -> Result<Zone, String> {
    let mut origin = String::new();
    let mut default_ttl = 3600u32;
    let mut records: Vec<ResourceRecord> = Vec::new();
    let mut last_name = String::new();

    for line in preprocess(content).lines() {
        // Check for a name field before trimming — blank-leading lines reuse
        // the previous owner name (RFC 1035 §5 implicit owner).
        let has_name = !line.starts_with(char::is_whitespace);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Directives (RFC 1035 §5.1)
        if let Some(rest) = directive(line, "$ORIGIN") {
            origin = canon(rest);
            last_name = origin.clone();
            continue;
        }
        if let Some(rest) = directive(line, "$TTL") {
            default_ttl = rest
                .parse()
                .map_err(|_| format!("invalid $TTL value: {rest}"))?;
            continue;
        }
        if directive(line, "$INCLUDE").is_some() {
            return Err("$INCLUDE is not supported".into());
        }

        let mut tok: Vec<&str> = line.split_whitespace().collect();
        if tok.is_empty() {
            continue;
        }

        // Owner field
        let name = if has_name {
            let raw = tok.remove(0);
            let n = resolve_name(raw, &origin);
            last_name = n.clone();
            n
        } else {
            last_name.clone()
        };

        // Optional TTL and class can appear in either order before the type
        // field (RFC 1035 §5.1): [ttl] [class] type … or [class] [ttl] type …
        let mut ttl = default_ttl;
        let mut i = 0usize;

        if let Some(t) = tok.get(i).and_then(|s| s.parse().ok()) {
            ttl = t;
            i += 1;
        }
        if tok.get(i).map_or(false, |s| is_class(s)) {
            i += 1;
        }
        if let Some(t) = tok.get(i).and_then(|s| s.parse().ok()) {
            ttl = t;
            i += 1;
        }

        let rtype = match tok.get(i) {
            Some(t) => t.to_ascii_uppercase(),
            None => continue,
        };
        i += 1;
        let rdata = &tok[i..];

        let data = match rtype.as_str() {
            // RFC 1035 §3.4.1
            "A" => {
                let s = rdata.first().ok_or("A: missing address")?;
                RecordData::A(
                    s.parse::<Ipv4Addr>()
                        .map_err(|_| format!("A: invalid address: {s}"))?,
                )
            }
            // RFC 3596 §2.1
            "AAAA" => {
                let s = rdata.first().ok_or("AAAA: missing address")?;
                RecordData::Aaaa(
                    s.parse::<Ipv6Addr>()
                        .map_err(|_| format!("AAAA: invalid address: {s}"))?,
                )
            }
            // RFC 1035 §3.3.11
            "NS" => {
                let s = rdata.first().ok_or("NS: missing nameserver")?;
                RecordData::Ns(resolve_name(s, &origin))
            }
            // RFC 1035 §3.3.1
            "CNAME" => {
                let s = rdata.first().ok_or("CNAME: missing target")?;
                RecordData::Cname(resolve_name(s, &origin))
            }
            // RFC 1035 §3.3.12
            "PTR" => {
                let s = rdata.first().ok_or("PTR: missing target")?;
                RecordData::Ptr(resolve_name(s, &origin))
            }
            // RFC 1035 §3.3.9
            "MX" => {
                let pri: u16 = rdata
                    .first()
                    .ok_or("MX: missing priority")?
                    .parse()
                    .map_err(|_| "MX: invalid priority")?;
                let exch = rdata.get(1).ok_or("MX: missing exchange")?;
                RecordData::Mx {
                    priority: pri,
                    exchange: resolve_name(exch, &origin),
                }
            }
            // RFC 1035 §3.3.14 — one or more quoted strings
            "TXT" => RecordData::Txt(parse_txt_strings(&rdata.join(" "))),
            // RFC 1035 §3.3.13
            "SOA" => {
                if rdata.len() < 7 {
                    return Err(format!(
                        "SOA for '{name}': need 7 fields, got {}",
                        rdata.len()
                    ));
                }
                RecordData::Soa {
                    mname: resolve_name(rdata[0], &origin),
                    rname: resolve_name(rdata[1], &origin),
                    serial: rdata[2].parse().map_err(|_| "SOA: invalid serial")?,
                    refresh: rdata[3].parse().map_err(|_| "SOA: invalid refresh")?,
                    retry: rdata[4].parse().map_err(|_| "SOA: invalid retry")?,
                    expire: rdata[5].parse().map_err(|_| "SOA: invalid expire")?,
                    minimum: rdata[6].parse().map_err(|_| "SOA: invalid minimum")?,
                }
            }
            _ => continue, // silently skip unknown record types
        };

        records.push(ResourceRecord {
            name,
            class: CLASS_IN,
            ttl,
            data,
        });
    }

    Ok(Zone { origin, records })
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// Check for a directive keyword at the start of a line, case-insensitively.
fn directive<'a>(line: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(keyword).or_else(|| {
        let upper = line[..line.len().min(keyword.len())].to_ascii_uppercase();
        if upper == keyword {
            Some(&line[keyword.len()..])
        } else {
            None
        }
    })?;
    if rest.is_empty() || rest.starts_with(char::is_whitespace) {
        Some(rest.trim())
    } else {
        None
    }
}

// Resolve a name token from the zone file to a canonical lowercase FQDN
// (without trailing dot).
//
// `@`  expands to the current $ORIGIN.
// Names ending with `.` are already absolute — strip the dot.
// All other names are relative and get the origin appended.
fn resolve_name(raw: &str, origin: &str) -> String {
    if raw == "@" {
        return origin.to_lowercase();
    }
    if raw.ends_with('.') {
        return raw.trim_end_matches('.').to_lowercase();
    }
    if origin.is_empty() {
        raw.to_lowercase()
    } else {
        format!("{}.{}", raw.to_lowercase(), origin)
    }
}

fn is_class(s: &str) -> bool {
    matches!(s.to_ascii_uppercase().as_str(), "IN" | "CH" | "HS" | "ANY")
}

// RFC 1035 §3.3.14 — parse TXT RDATA: one or more quoted strings.
// An unquoted token is treated as a single character-string.
fn parse_txt_strings(text: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;

    for c in text.chars() {
        match c {
            '"' => {
                if in_quote {
                    result.push(std::mem::take(&mut current));
                }
                in_quote = !in_quote;
            }
            _ if in_quote => current.push(c),
            _ => {}
        }
    }

    // Fall back to the whole token if no quoted strings were found
    if result.is_empty() {
        let t = text.trim().to_string();
        if !t.is_empty() {
            result.push(t);
        }
    }
    result
}

// Strip the `;` comment from a line, respecting quoted strings so a semicolon
// inside `"…"` is not treated as a comment delimiter.
fn strip_comment(line: &str) -> &str {
    let mut in_quote = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_quote = !in_quote,
            ';' if !in_quote => return &line[..i],
            _ => {}
        }
    }
    line
}

// Collapse multi-line records delimited by `(` … `)` into single logical lines
// (RFC 1035 §5.1). Comments are stripped from each source line first.
// Leading whitespace of the first line in a group is preserved so that the
// caller can detect the implicit-owner (`last_name`) convention.
fn preprocess(content: &str) -> String {
    let mut out = String::new();
    let mut pending = String::new();
    let mut depth = 0usize;

    for line in content.lines() {
        let stripped = strip_comment(line).trim_end();

        for c in stripped.chars() {
            match c {
                '(' => depth += 1,
                ')' if depth > 0 => depth -= 1,
                _ => pending.push(c),
            }
        }

        if depth == 0 {
            let to_emit = pending.trim_end().to_string();
            pending.clear();
            if !to_emit.trim().is_empty() {
                out.push_str(&to_emit);
                out.push('\n');
            }
        } else {
            // Join continuation lines with a space inside a paren group
            pending.push(' ');
        }
    }

    // Emit any unclosed group (malformed zone file, but be lenient)
    if !pending.trim().is_empty() {
        out.push_str(pending.trim_end());
        out.push('\n');
    }

    out
}
