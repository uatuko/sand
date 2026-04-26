# sand

An authoritative DNS server over UDP, written in Rust.

## Usage

```sh
cargo run -- [zone-file]
```

The zone file defaults to `zone.db` in the current directory. A sample zone file can be found at `examples/zone.db`.

To query the server (runs on `127.0.0.1:1053` by default):

```sh
dig @127.0.0.1 -p 1053 www.example.com A
dig @127.0.0.1 -p 1053 example.com MX
dig @127.0.0.1 -p 1053 ftp.example.com A   # CNAME chain
```

## Zone file format

Standard BIND-style master file format (RFC 1035 §5). Supported directives and record types:

| Syntax    | Description |
|-----------|-------------|
| `$ORIGIN` | Sets the default domain origin |
| `$TTL`    | Sets the default TTL (seconds) |
| `SOA`     | Start of authority |
| `NS`      | Nameserver |
| `A`       | IPv4 address |
| `AAAA`    | IPv6 address |
| `CNAME`   | Canonical name alias |
| `MX`      | Mail exchange |
| `PTR`     | Pointer (reverse DNS) |
| `TXT`     | Text record |

Multi-line records (parenthesised) and `;` comments are supported.

## Code structure

| File | Responsibility |
|------|----------------|
| `src/main.rs`        | UDP server loop, zone loading, thread pool dispatch |
| `src/dns/mod.rs`     | Resolver: query processing and CNAME chaining |
| `src/dns/message.rs` | DNS wire format: parse and serialise messages |
| `src/dns/zone.rs`    | Zone file parser and in-memory record store |
| `src/lib.rs`         | Thread pool implementation |

## RFC standards

| RFC | Section | Used for |
|-----|---------|----------|
| RFC 1035 | §4     | Message wire format (header, question, resource record sections) |
| RFC 1035 | §4.1.4 | Name compression (pointer decompression on parse) |
| RFC 1035 | §3.3   | RDATA formats for SOA, NS, CNAME, MX, PTR, TXT |
| RFC 1035 | §4.3.2 | Query processing algorithm |
| RFC 1035 | §5     | BIND-style zone file format |
| RFC 3596 | §2     | AAAA record (IPv6) |
| RFC 2308 | §3     | SOA in authority section for NXDOMAIN and NODATA responses |
