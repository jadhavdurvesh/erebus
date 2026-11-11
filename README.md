# EREBUS

**Independent, cross-platform network defence engine.**

EREBUS is an independently designed firewall and network-security platform. Its first integration target is **Sand OS**. Linux and Windows support will be added through native platform adapters.

> Project status: **Portable security-engine foundation**. Policy evaluation, versioned TOML validation, transactional in-memory reload, bounded connection tracking, structured in-memory events, token-bucket rate limiting, a reusable DNS security subsystem, and a portable policy-to-adapter enforcement runtime are implemented. No production OS packet adapter is implemented yet. The DNS proxy supports UDP, TCP, authenticated DoT, and authenticated DoH upstreams.

## Design principles

- **One policy engine:** security decisions live in the portable core, not in operating-system adapters.
- **Native enforcement:** each platform adapter translates core decisions into its own supported networking mechanism.
- **Explicit policy defaults:** the default verdict must be visible and validated.
- **Fail safely:** adapter failures must not silently turn a deny decision into an allow decision.
- **Least privilege:** privileged enforcement is isolated from configuration, UI, and untrusted input parsing.
- **Observable decisions:** security decisions should be explainable and auditable.
- **Bounded state:** connection tables, event journals, and keyed rate-limit tables have explicit capacities.
- **Portable core:** platform-specific APIs stay outside the core crates.

## Architecture

```text
                Applications / Administrators
                            |
                   EREBUS Control Plane
             (configuration, API, audit, status)
                            |
                    EREBUS Policy Core
          (rules, matching, connection context, verdicts)
                            |
              Security State and Observability
       (connection tracking, event journal, rate limiting)
                            |
                   Platform Adapter API
               /             |             \
          Sand OS           Linux         Windows
       native network     nftables /       Windows
          stack           netlink         Filtering
                                           Platform
```

The core does not directly modify packets or call platform APIs. An adapter obtains a normalized packet/flow description and passes it to the portable enforcement runtime. The runtime selects one policy snapshot, asks the adapter to apply the exact verdict, and records metadata-only audit events. The adapter uses the platform's supported enforcement interface.

The policy core supports ordered rules using direction, protocol, IPv4/IPv6 CIDR source and destination prefixes, source/destination ports, and exact interface names. The `erebus-config` crate validates versioned TOML documents and converts them into policy sets. The engine supports transactional in-memory policy replacement: invalid updates do not replace the active snapshot.

The engine also exposes bounded TCP/UDP connection tracking, a metadata-only in-memory security event journal, token-bucket rate-limit primitives, and a platform-neutral enforcement runtime with adapter lifecycle, verdict forwarding, and fail-closed runtime fault handling. The separate `erebus-dns` crate provides bounded DNS parsing, domain policy, request correlation, positive-response caching, and a reusable UDP/TCP proxy. The engine-side DNS service connects those components to per-client rate limits and DNS audit events through a policy adapter interface. The `erebus dns-serve` CLI command runs a loopback proxy without changing system DNS configuration. Native packet interception and automatic resolver integration remain future work.

## Repository layout

```text
.
├── Cargo.toml
├── crates/
│   ├── erebus-types/       # Shared identifiers and normalized traffic metadata
│   ├── erebus-policy/      # Deterministic policy evaluation
│   ├── erebus-config/      # Versioned TOML schema and validation
│   ├── erebus-engine/      # Policy snapshots, security state, enforcement runtime
│   ├── erebus-dns/         # Reusable DNS parsing, policy, tracking, cache, UDP/TCP proxy
│   ├── erebus-adapter-api/ # Contract implemented by OS adapters
│   └── erebus-cli/         # Offline validate/export tooling
├── docs/
│   ├── ARCHITECTURE.md
│   ├── SECURITY_MODEL.md
│   ├── POLICY_MODEL.md
│   ├── CONNECTION_TRACKING.md
│   ├── SECURITY_EVENTS.md
│   ├── RATE_LIMITING.md
│   ├── DNS_SECURITY.md
│   ├── ENFORCEMENT_RUNTIME.md
│   ├── OWNERSHIP_AND_DEPENDENCIES.md
│   ├── ROADMAP.md
│   └── PLATFORM_ADAPTERS.md
├── examples/
│   ├── policy.toml
│   └── dns-policy.toml
└── .github/
    └── workflows/
        └── ci.yml
```

## Build, test, and use

Requires a current stable Rust toolchain.

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

# Validate a policy without changing host networking
cargo run -p erebus-cli -- validate examples/policy.toml

# Print normalized TOML
cargo run -p erebus-cli -- export examples/policy.toml

# Validate and export DNS domain policy
cargo run -p erebus-cli -- dns-validate examples/dns-policy.toml
cargo run -p erebus-cli -- dns-export examples/dns-policy.toml

# Run loopback UDP/TCP proxy (does not change OS DNS settings)
cargo run -p erebus-cli -- dns-serve examples/dns-policy.toml

# Run with authenticated DNS-over-TLS
cargo run -p erebus-cli -- dns-serve examples/dns-policy.toml --upstream 1.1.1.1:853 --upstream-protocol dot --tls-server-name cloudflare-dns.com

# Run with authenticated DNS-over-HTTPS
cargo run -p erebus-cli -- dns-serve examples/dns-policy.toml --upstream 1.1.1.1:443 --upstream-protocol doh --https-url https://cloudflare-dns.com/dns-query
```

The CLI accepts `--output path` with `export` and `dns-export` to write canonical TOML to a file. `dns-serve` opens an explicit local proxy listener but does not change host firewall or system DNS settings. Encrypted upstream modes verify certificates and hostnames, and never fall back to plaintext.

## Safety notice

EREBUS is experimental software. Its portable decision and state-management primitives are not a functioning firewall. The connection tracker uses simplified TCP state observations and is not a replacement for a kernel TCP stack. The enforcement runtime is orchestration only; without a native adapter it cannot capture or block operating-system traffic. The DNS service includes a local proxy but does not automatically intercept system DNS traffic. The event journal is volatile in-memory storage, not a durable audit log. Do not rely on EREBUS to protect a production machine or expose network services.

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md) for milestones and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the technical design.
