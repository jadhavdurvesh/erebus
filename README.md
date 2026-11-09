# EREBUS

**Independent, cross-platform network defence engine.**

EREBUS is an independently designed firewall and network-security platform. Its first integration target is **Sand OS**. Linux and Windows support will be added through native platform adapters.

> Project status: **Portable policy foundation**. Configuration validation and in-memory transactional reload are implemented. Live packet capture and OS enforcement are not implemented yet.

## Design principles

- **One policy engine:** security decisions live in the portable core, not in operating-system adapters.
- **Native enforcement:** each platform adapter translates core decisions into its own supported networking mechanism.
- **Explicit policy defaults:** the default verdict must be visible and validated.
- **Fail safely:** adapter failures must not silently turn a deny decision into an allow decision.
- **Least privilege:** privileged enforcement is isolated from configuration, UI, and untrusted input parsing.
- **Observable decisions:** security decisions should be explainable and auditable.
- **Portable core:** platform-specific APIs stay outside the core crates.

## Planned architecture

```text
                Applications / Administrators
                            |
                   EREBUS Control Plane
             (configuration, API, audit, status)
                            |
                    EREBUS Policy Core
          (rules, matching, connection context, verdicts)
                            |
                   Platform Adapter API
               /             |             \
          Sand OS           Linux         Windows
       native network     nftables /       Windows
          stack           netlink         Filtering
                                           Platform
```

The core does not directly modify packets or call platform APIs. An adapter obtains a normalized packet/flow description, asks the core for a verdict, and applies that verdict using the platform's supported enforcement interface.

The policy core supports ordered rules using direction, protocol, IPv4/IPv6 CIDR source and destination prefixes, source/destination ports, and exact interface names. The `erebus-config` crate validates versioned TOML documents and converts them into policy sets. The engine supports transactional in-memory policy replacement: invalid updates do not replace the active snapshot. See [docs/POLICY_MODEL.md](docs/POLICY_MODEL.md).

## Repository layout

```text
.
├── Cargo.toml
├── crates/
│   ├── erebus-types/       # Shared identifiers and normalized traffic metadata
│   ├── erebus-policy/      # Deterministic policy evaluation
│   ├── erebus-config/      # Versioned TOML schema and validation
│   ├── erebus-engine/      # Portable decisions and atomic policy snapshots
│   ├── erebus-adapter-api/ # Contract implemented by OS adapters
│   └── erebus-cli/         # Offline validate/export tooling
├── docs/
│   ├── ARCHITECTURE.md
│   ├── SECURITY_MODEL.md
│   ├── POLICY_MODEL.md
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

# Validate the example policy without applying it
cargo run -p erebus-cli -- validate examples/policy.toml

# Print normalized TOML
cargo run -p erebus-cli -- export examples/policy.toml
```

The CLI also accepts `--output path` with `export` to write canonical TOML to a file. It has no command that changes host firewall state.

## Safety notice

EREBUS is experimental software. Configuration validation and in-memory policy decisions are not a functioning firewall. Do not rely on EREBUS to protect a production machine or expose network services. Platform enforcement will be introduced only with dedicated tests and explicit recovery documentation.

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md) for milestones and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the technical design.
