# EREBUS

**Independent, cross-platform network defence engine.**

EREBUS is an independently designed firewall and network-security platform. Its first integration target is **Sand OS**. Linux and Windows support will be added through native platform adapters.

> Project status: **Foundation / early development**. No packet filtering or production protection is implemented yet.

## Design principles

- **One policy engine:** security decisions live in the portable core, not in operating-system adapters.
- **Native enforcement:** each platform adapter translates core decisions into its own supported networking mechanism.
- **Default-deny where explicitly configured:** policy defaults must be visible, testable, and never silently weaken host security.
- **Fail safely:** adapter failures must not accidentally turn a deny decision into an allow decision.
- **Least privilege:** privileged packet enforcement is isolated from configuration, UI, and untrusted input parsing.
- **Observable decisions:** security-relevant decisions should be explainable and auditable.
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

The current policy core supports ordered rules using direction, protocol, IPv4/IPv6 CIDR source and destination prefixes, source/destination ports, and exact interface names. See [docs/POLICY_MODEL.md](docs/POLICY_MODEL.md) for matching semantics and limitations. The sample TOML is illustrative only; a configuration loader and live packet enforcement are not implemented yet.

## Repository layout

```text
.
├── Cargo.toml
├── crates/
│   ├── erebus-types/       # Shared identifiers, packet metadata, verdicts
│   ├── erebus-policy/      # Deterministic policy evaluation
│   ├── erebus-engine/      # Portable decision orchestration
│   └── erebus-adapter-api/ # Contract implemented by OS adapters
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

## Build and test

Requires a current stable Rust toolchain.

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## Safety notice

EREBUS is experimental software. The initial workspace is a foundation for development, not a functioning firewall. Do not rely on it to protect a production machine or expose network services. Platform enforcement will be introduced only with dedicated tests and explicit integration documentation.

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md) for milestones and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the initial technical design.
