# EREBUS

**Independent, cross-platform network defence engine.**

EREBUS is an independently designed firewall and network-security platform. Its first integration target is **Sand OS**. Linux and Windows support will be added through native platform adapters.

> Project status: **Portable security-engine foundation**. Policy evaluation, versioned TOML validation, transactional in-memory reload, bounded connection-tracking, structured in-memory events, and token-bucket rate-limiting primitives are implemented. Live packet capture and OS enforcement are not implemented yet.

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

The core does not directly modify packets or call platform APIs. An adapter obtains a normalized packet/flow description, asks the core for a verdict, and applies that verdict using the platform's supported enforcement interface.

The policy core supports ordered rules using direction, protocol, IPv4/IPv6 CIDR source and destination prefixes, source/destination ports, and exact interface names. The `erebus-config` crate validates versioned TOML documents and converts them into policy sets. The engine supports transactional in-memory policy replacement: invalid updates do not replace the active snapshot.

The engine also exposes bounded TCP/UDP connection tracking, a metadata-only in-memory security event journal, and token-bucket rate-limit primitives. These components are independently tested and are not yet connected to live platform packet callbacks.

## Repository layout

```text
.
├── Cargo.toml
├── crates/
│   ├── erebus-types/       # Shared identifiers and normalized traffic metadata
│   ├── erebus-policy/      # Deterministic policy evaluation
│   ├── erebus-config/      # Versioned TOML schema and validation
│   ├── erebus-engine/      # Policy snapshots and security-state primitives
│   ├── erebus-adapter-api/ # Contract implemented by OS adapters
│   └── erebus-cli/         # Offline validate/export tooling
├── docs/
│   ├── ARCHITECTURE.md
│   ├── SECURITY_MODEL.md
│   ├── POLICY_MODEL.md
│   ├── CONNECTION_TRACKING.md
│   ├── SECURITY_EVENTS.md
│   ├── RATE_LIMITING.md
│   ├── ROADMAP.md
│   └── PLATFORM_ADAPTERS.md
├── examples/
│   └── policy.toml
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
```

The CLI also accepts `--output path` with `export` to write canonical TOML to a file. It has no command that changes host firewall state.

## Safety notice

EREBUS is experimental software. Its portable decision and state-management primitives are not a functioning firewall. The connection tracker uses simplified TCP state observations and is not a replacement for a kernel TCP stack. The event journal is volatile in-memory storage, not a durable audit log. Do not rely on EREBUS to protect a production machine or expose network services.

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md) for milestones and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the technical design.
