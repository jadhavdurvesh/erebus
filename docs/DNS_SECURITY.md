# EREBUS DNS Security

## Scope and status

The standalone `erebus-dns` crate provides bounded DNS message parsing, domain policy evaluation, request/response correlation, and positive-response caching. The engine-side `DnsSecurityService` connects those capabilities to per-client rate limiting and the bounded EREBUS security-event journal.

This is **not yet a live DNS proxy or system DNS filter**. It does not open sockets, capture packets, forward DNS messages, modify resolver settings, or apply OS firewall rules. A future platform adapter must receive DNS messages, pass parsed messages to the service, then enforce its Allowed/Blocked/RateLimited result.

## Workspace components

| Component | Responsibility |
| --- | --- |
| `erebus-dns::wire` | Bounded DNS wire parser |
| `erebus-dns::policy` | Domain allow/block policy |
| `erebus-dns::config` | Versioned DNS policy TOML |
| `erebus-dns::tracker` | Request/response correlation |
| `erebus-dns::cache` | Bounded positive-response cache |
| `erebus-engine::dns` | Domain policy + client rate limits + tracking + cache + audit events |

## DNS message parser

The parser accepts messages up to 4096 bytes by default, limits question and resource-record counts, and limits compression-pointer hops. It supports:

- DNS header flags and section counts.
- Question names and question type/class.
- A and AAAA address records.
- CNAME, NS, and PTR name records.
- MX, TXT, SRV, and OPT records.
- Unknown record types, whose RDATA is retained as opaque bytes.
- DNS name compression using backwards pointers.

Malformed lengths, truncated records, non-printable/non-ASCII labels, forward pointers, and over-limit structures are rejected. The parser returns ASCII presentation names normalized to lowercase. IDNs must be supplied as ASCII A-labels (punycode); IDNA conversion is not performed here.

The parser is deliberately strict. It does not validate DNSSEC signatures, interpret every RR type, parse TCP DNS framing, or verify network/transport checksums.

## Domain policy

DNS policy schema version 1 uses:

```toml
schema_version = 1

[policy]
default = "allow"

[[rules]]
id = "block-tracker"
domain = "tracker.example"
match = "suffix"
action = "block"

[[rules]]
id = "allow-admin"
domain = "admin.example"
match = "exact"
action = "allow"
```

Supported match types:

- `exact`: matches only the normalized domain itself.
- `suffix`: matches the domain itself and subdomains on a DNS label boundary.

Matching is deterministic: longest domain wins, exact wins a specificity tie, and the first declared rule wins when specificity is equal. The default is explicit and must be `allow` or `block`. Unknown TOML fields and unsupported schema versions are rejected.

Names are ASCII-only A-labels, lowercased, with an optional trailing dot removed. Underscore service labels are accepted. No wildcard syntax, regexes, category lists, or automatic IDNA conversion are implemented.

## Request/response tracking

The bounded tracker correlates a response only when these values match the outstanding request:

- Client and resolver IP addresses and ports.
- UDP or TCP transport.
- DNS transaction ID.
- Normalized question name, type, and class.

Outstanding requests expire after a configurable timeout. A response that does not match an outstanding request is rejected. This is correlation metadata, not a complete DNS transaction validation or anti-spoofing system.

## Positive-response cache

The cache stores only successful, non-truncated responses with one question and at least one answer. It uses the earliest answer TTL (capped by configuration), changes the DNS transaction ID on lookup, and reduces returned TTL values to their remaining lifetime.

It does not cache NXDOMAIN, other error responses, truncated responses, or empty answers. Active entries are not evicted to make room; a full cache returns a capacity error. DNSSEC validation and negative caching are not implemented.

## Engine integration

The engine service provides:

- Domain policy decisions.
- Per-client-IP token-bucket limits.
- Request tracking only for queries permitted by both checks.
- Response correlation and positive-cache admission.
- DNS decision, rate-limit, and response-latency events in the bounded event journal.
- Explicit expiry for tracker, cache, and idle client-rate-limit keys.

The service returns a query status to the adapter. The adapter must enforce it. A returned Blocked status does not itself prevent a packet from reaching a resolver.

## Build and test

```bash
cargo test -p erebus-dns
cargo test -p erebus-engine
cargo run -p erebus-cli -- dns-validate examples/dns-policy.toml
cargo run -p erebus-cli -- dns-export examples/dns-policy.toml
```

All commands are offline policy tooling. None installs a DNS filter or changes host resolver settings.
