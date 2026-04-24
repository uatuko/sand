// DNS wire format
//
// RFC 1035 §4   — message format (header, question, resource record sections)
// RFC 1035 §4.1.4 — name compression (pointer decompression on parse;
//                   uncompressed encoding on serialise — simpler, always correct)
// RFC 1035 §3.2–3.3 — RDATA formats for A, NS, CNAME, SOA, PTR, MX, TXT
// RFC 3596 §2   — AAAA record

use std::net::{Ipv4Addr, Ipv6Addr};

// RFC 1035 §4.1.1 — response codes
pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_NOTIMP: u8 = 4;
pub const RCODE_REFUSED: u8 = 5;

pub const CLASS_IN: u16 = 1;

// RFC 1035 §3.2.2 / RFC 3596 §2 — QTYPE values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    A = 1,
    Ns = 2,
    Cname = 5,
    Soa = 6,
    Ptr = 12,
    Mx = 15,
    Txt = 16,
    Aaaa = 28, // RFC 3596
    Any = 255,
}

impl RecordType {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::A),
            2 => Some(Self::Ns),
            5 => Some(Self::Cname),
            6 => Some(Self::Soa),
            12 => Some(Self::Ptr),
            15 => Some(Self::Mx),
            16 => Some(Self::Txt),
            28 => Some(Self::Aaaa),
            255 => Some(Self::Any),
            _ => None,
        }
    }
}

impl From<RecordType> for u16 {
    fn from(t: RecordType) -> u16 {
        t as u16
    }
}

// RFC 1035 §4.1.1 — header section (12 bytes)
//
// Bit layout of the flags field (MSB → LSB):
//   QR(1) Opcode(4) AA(1) TC(1) RD(1) RA(1) Z(3) RCODE(4)
#[derive(Debug, Clone)]
pub struct Header {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl Header {
    pub fn qr(&self) -> bool {
        self.flags & 0x8000 != 0
    }
    pub fn opcode(&self) -> u8 {
        ((self.flags >> 11) & 0xf) as u8
    }
    pub fn rd(&self) -> bool {
        self.flags & 0x0100 != 0
    }
}

// RFC 1035 §4.1.2 — question section
#[derive(Debug, Clone)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

// RFC 1035 §3.3, RFC 3596 §2.1 — record-specific RDATA
#[derive(Debug, Clone)]
pub enum RecordData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ns(String),
    Cname(String),
    Ptr(String),
    Mx {
        priority: u16,
        exchange: String,
    },
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Txt(Vec<String>),
}

impl RecordData {
    pub fn rtype(&self) -> RecordType {
        match self {
            Self::A(_) => RecordType::A,
            Self::Aaaa(_) => RecordType::Aaaa,
            Self::Ns(_) => RecordType::Ns,
            Self::Cname(_) => RecordType::Cname,
            Self::Ptr(_) => RecordType::Ptr,
            Self::Mx { .. } => RecordType::Mx,
            Self::Soa { .. } => RecordType::Soa,
            Self::Txt(_) => RecordType::Txt,
        }
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::A(a) => buf.extend_from_slice(&a.octets()),
            Self::Aaaa(a) => buf.extend_from_slice(&a.octets()),

            Self::Ns(n) | Self::Cname(n) | Self::Ptr(n) => encode_name(buf, n),

            Self::Mx { priority, exchange } => {
                buf.extend_from_slice(&priority.to_be_bytes());
                encode_name(buf, exchange);
            }

            Self::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                encode_name(buf, mname);
                encode_name(buf, rname);
                buf.extend_from_slice(&serial.to_be_bytes());
                buf.extend_from_slice(&refresh.to_be_bytes());
                buf.extend_from_slice(&retry.to_be_bytes());
                buf.extend_from_slice(&expire.to_be_bytes());
                buf.extend_from_slice(&minimum.to_be_bytes());
            }

            // RFC 1035 §3.3.14 — each character-string is length-prefixed, ≤255 bytes
            Self::Txt(strings) => {
                for s in strings {
                    for chunk in s.as_bytes().chunks(255) {
                        buf.push(chunk.len() as u8);
                        buf.extend_from_slice(chunk);
                    }
                }
            }
        }
    }
}

// RFC 1035 §4.1.3 — resource record format
#[derive(Debug, Clone)]
pub struct ResourceRecord {
    pub name: String,
    pub class: u16,
    pub ttl: u32,
    pub data: RecordData,
}

#[derive(Debug)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authority: Vec<ResourceRecord>,
    pub additional: Vec<ResourceRecord>,
}

#[derive(Debug)]
pub enum ParseError {
    Truncated,
    InvalidName,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "message truncated"),
            Self::InvalidName => write!(f, "invalid domain name"),
        }
    }
}

impl std::error::Error for ParseError {}

impl Message {
    // RFC 1035 §4.1 — parse a DNS message from a UDP datagram
    pub fn parse(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < 12 {
            return Err(ParseError::Truncated);
        }

        let header = Header {
            id: u16::from_be_bytes([buf[0], buf[1]]),
            flags: u16::from_be_bytes([buf[2], buf[3]]),
            qdcount: u16::from_be_bytes([buf[4], buf[5]]),
            ancount: u16::from_be_bytes([buf[6], buf[7]]),
            nscount: u16::from_be_bytes([buf[8], buf[9]]),
            arcount: u16::from_be_bytes([buf[10], buf[11]]),
        };

        let mut offset = 12usize;
        let mut questions = Vec::with_capacity(header.qdcount as usize);

        for _ in 0..header.qdcount {
            let name = parse_name(buf, &mut offset)?;
            if offset + 4 > buf.len() {
                return Err(ParseError::Truncated);
            }
            let qtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let qclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
            offset += 4;
            questions.push(Question {
                name,
                qtype,
                qclass,
            });
        }

        Ok(Self {
            header,
            questions,
            answers: vec![],
            authority: vec![],
            additional: vec![],
        })
    }

    // Build an empty response copying the ID and RD flag from the query.
    // AA=1 since this server is authoritative (RFC 1035 §4.1.1).
    pub fn response(&self, rcode: u8) -> Self {
        Self {
            header: Header {
                id: self.header.id,
                // QR=1, AA=1, RD=copy, all other flags 0
                flags: 0x8400 | if self.header.rd() { 0x0100 } else { 0 } | rcode as u16,
                qdcount: self.questions.len() as u16,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: self.questions.clone(),
            answers: vec![],
            authority: vec![],
            additional: vec![],
        }
    }

    // RFC 1035 §4.1 — serialise a DNS message to a byte buffer.
    // Section counts are derived from the actual vecs, not the header fields,
    // so callers may freely push records without keeping counts in sync.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);

        buf.extend_from_slice(&self.header.id.to_be_bytes());
        buf.extend_from_slice(&self.header.flags.to_be_bytes());
        buf.extend_from_slice(&(self.questions.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.answers.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.authority.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.additional.len() as u16).to_be_bytes());

        for q in &self.questions {
            encode_name(&mut buf, &q.name);
            buf.extend_from_slice(&q.qtype.to_be_bytes());
            buf.extend_from_slice(&q.qclass.to_be_bytes());
        }

        for section in [&self.answers, &self.authority, &self.additional] {
            for rr in section {
                encode_name(&mut buf, &rr.name);
                buf.extend_from_slice(&u16::from(rr.data.rtype()).to_be_bytes());
                buf.extend_from_slice(&rr.class.to_be_bytes());
                buf.extend_from_slice(&rr.ttl.to_be_bytes());

                // Write RDLENGTH placeholder, encode RDATA, then back-fill the length
                let rdlen_pos = buf.len();
                buf.extend_from_slice(&[0u8; 2]);
                rr.data.encode(&mut buf);
                let rdlen = (buf.len() - rdlen_pos - 2) as u16;
                buf[rdlen_pos..rdlen_pos + 2].copy_from_slice(&rdlen.to_be_bytes());
            }
        }

        buf
    }

    // Produce a minimal FORMERR response when parsing failed but at least the
    // message ID (first two bytes) could be read — RFC 1035 §4.1.1.
    pub fn formerr(buf: &[u8]) -> Option<Vec<u8>> {
        if buf.len() < 2 {
            return None;
        }
        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let mut out = vec![0u8; 12];
        out[0..2].copy_from_slice(&id.to_be_bytes());
        out[2..4].copy_from_slice(&0x8001u16.to_be_bytes()); // QR=1, RCODE=FORMERR
        Some(out)
    }
}

// RFC 1035 §4.1.4 — decode a domain name, following compression pointers.
//
// Compression pointers have their top two bits set (0xC0 mask). They carry a
// 14-bit offset from the start of the message. The cursor (*offset) is advanced
// past the two pointer bytes on the first jump; subsequent jumps do not move it.
// A loop counter caps pointer chasing at 10 hops to guard against crafted loops.
pub(super) fn parse_name(buf: &[u8], offset: &mut usize) -> Result<String, ParseError> {
    let mut labels: Vec<&str> = Vec::new();
    let mut pos = *offset;
    let mut jumped = false;
    let mut hops = 0u8;

    loop {
        if pos >= buf.len() {
            return Err(ParseError::Truncated);
        }

        let b = buf[pos];

        if b == 0 {
            if !jumped {
                *offset = pos + 1;
            }
            break;
        }

        if b & 0xC0 == 0xC0 {
            if pos + 1 >= buf.len() {
                return Err(ParseError::Truncated);
            }
            if !jumped {
                *offset = pos + 2;
            }
            jumped = true;
            hops += 1;
            if hops > 10 {
                return Err(ParseError::InvalidName);
            }
            pos = (((b & 0x3F) as usize) << 8) | buf[pos + 1] as usize;
            continue;
        }

        let len = b as usize;
        pos += 1;
        if pos + len > buf.len() {
            return Err(ParseError::Truncated);
        }

        labels
            .push(std::str::from_utf8(&buf[pos..pos + len]).map_err(|_| ParseError::InvalidName)?);
        pos += len;
    }

    Ok(labels.join(".").to_lowercase())
}

// Encode a domain name as length-prefixed labels terminated by a zero byte.
// No compression is applied — straightforward and always correct for responses.
pub(super) fn encode_name(buf: &mut Vec<u8>, name: &str) {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        buf.push(0);
        return;
    }
    for label in name.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
}
