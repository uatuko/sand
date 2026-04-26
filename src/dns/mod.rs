// DNS resolver — ties together wire-format parsing and zone-file lookup.
//
// RFC 1035 §4.3.2 — query processing algorithm
// RFC 1035 §3.3.1 — CNAME following
// RFC 2308 §3     — SOA in authority section for negative responses

pub mod message;
pub mod zone;

use message::{
    Message, RecordData, RecordType, RCODE_NOERROR, RCODE_NOTIMP, RCODE_NXDOMAIN, RCODE_REFUSED,
};
use zone::Zone;

// Maximum CNAME chain depth to follow before giving up (prevents loops).
const MAX_CNAME_HOPS: usize = 8;

// Resolve a raw UDP datagram and return a serialised DNS response.
// This function never panics; any parse error produces a FORMERR response.
pub fn resolve(buf: &[u8], zone: &Zone) -> Vec<u8> {
    let query = match Message::parse(buf) {
        Ok(q) => q,
        Err(e) => {
            eprintln!("DNS parse error: {e}");
            return Message::formerr(buf).unwrap_or_default();
        }
    };

    // Only standard queries (OPCODE=0) are supported — RFC 1035 §4.1.1
    if query.header.opcode() != 0 {
        return query.response(RCODE_NOTIMP).serialize();
    }

    // Queries originating as responses are silently dropped
    if query.header.qr() {
        return vec![];
    }

    let mut response = query.response(RCODE_NOERROR);

    for q in &query.questions {
        let qname = q.name.trim_end_matches('.').to_lowercase();
        let qtype = q.qtype;
        let qclass = q.qclass;

        // This is an authoritative-only server — refuse out-of-bailiwick queries
        // (RFC 1035 §4.3.1: a name server should not answer for zones it is not
        // authoritative for)
        if qclass != 1 /* IN */ && qclass != 255
        /* ANY */
        {
            response.header.flags = (response.header.flags & !0xf) | RCODE_REFUSED as u16;
            continue;
        }

        answer_question(&mut response, zone, &qname, qtype, 0);
    }

    response.serialize()
}

// Populate the answer/authority sections for one question, following CNAMEs up
// to MAX_CNAME_HOPS deep (RFC 1035 §3.3.1).
fn answer_question(response: &mut Message, zone: &Zone, name: &str, qtype: u16, depth: usize) {
    if depth > MAX_CNAME_HOPS {
        return;
    }

    match zone.lookup(name, qtype) {
        // Name found, records of the requested type found
        Some(records) if !records.is_empty() => {
            response.answers.extend(records.into_iter().cloned());
        }

        // Name exists but has no records of the requested type.
        // Check for a CNAME if we weren't already asking for CNAMEs.
        Some(_) if qtype != RecordType::Cname as u16 && qtype != RecordType::Any as u16 => {
            match zone.lookup(name, RecordType::Cname as u16) {
                Some(cnames) if !cnames.is_empty() => {
                    for cname_rr in cnames {
                        response.answers.push(cname_rr.clone());
                        // Follow the chain (RFC 1035 §3.3.1)
                        if let RecordData::Cname(target) = &cname_rr.data {
                            answer_question(response, zone, target, qtype, depth + 1);
                        }
                    }
                }
                // Name exists, no CNAME either → NODATA (RFC 2308 §2.2)
                // NOERROR + empty answer, SOA in authority (RFC 2308 §3)
                _ => {
                    if let Some(soa) = zone.soa() {
                        response.authority.push(soa.clone());
                    }
                }
            }
        }

        // Name exists, no records (and qtype was CNAME or ANY) → NODATA
        Some(_) => {
            if let Some(soa) = zone.soa() {
                response.authority.push(soa.clone());
            }
        }

        // Name does not exist → NXDOMAIN (RFC 1035 §4.3.2)
        None => {
            // Set NXDOMAIN only if no rcode has been set yet
            let current_rcode = (response.header.flags & 0xf) as u8;
            if current_rcode == RCODE_NOERROR {
                response.header.flags = (response.header.flags & !0xf) | RCODE_NXDOMAIN as u16;
                // RFC 2308 §3 — include SOA in authority section
                if let Some(soa) = zone.soa() {
                    response.authority.push(soa.clone());
                }
            }
        }
    }
}
