# EREBUS Roadmap

This roadmap describes intended work; listed items are not claims of completed functionality.

## Milestone 0 — Foundation

- [x] Establish Rust workspace.
- [x] Define portable traffic and verdict types.
- [x] Implement deterministic first-match policy evaluation.
- [x] Define platform adapter contract.
- [x] Add CI and verify formatting, tests, and linting.
- [ ] Define configuration schema and versioning rules.

## Milestone 1 — Portable core hardening and adapter contract

- [x] Add IPv4/IPv6 CIDR prefix representation and containment tests.
- [x] Match source/destination prefixes, ports, direction, protocol, and exact interface names.
- [x] Reject empty interface selectors and duplicate/empty rule IDs.
- [x] Add mock adapter lifecycle, verdict-forwarding, and enforcement-failure tests.
- [x] Define a versioned, validated schema-1 TOML policy document.
- [x] Reject unknown fields, unsupported versions, malformed selectors, and duplicate IDs.
- [x] Add canonical TOML export while preserving rule order.
- [x] Add offline CLI commands for policy validation and export.
- [x] Add transactional in-memory policy snapshots; invalid reloads leave the active policy unchanged.
- [x] Add config, CLI, and engine reload tests.
- [x] Add a bounded structured security-event journal with sequence numbers and explicit rollover reporting.
- [x] Document monotonic timestamp semantics and metadata-only event fields.
- [ ] Add a durable export sink and bounded asynchronous delivery contract.
- [x] Add portable enforcement orchestration: policy snapshot evaluation, adapter lifecycle, verdict forwarding, bounded decision audit, and fail-closed runtime fault handling.
- [x] Integrate bounded per-peer token buckets into packet-level enforcement; rate-limit errors fail closed.
- [x] Integrate TCP/UDP/other flow tracking into packet-level enforcement; tracking failures and capacity exhaustion fail closed.
- [x] Add flow creation/state-transition/expiry events, periodic maintenance API, and state reset on successful adapter shutdown.
- [ ] Connect the packet-level runtime API to real native adapter callbacks.
- [x] Add an ownership/dependency audit distinguishing EREBUS-authored security logic from third-party infrastructure and native OS enforcement.

## Milestone 2 — Sand OS integration research (dependency-gated)

**Dependency:** SAND OS must first implement its planned M9 networking foundation. At the time this roadmap was written, the SAND OS repository is at M3 and contains no network stack or packet/flow hook API. EREBUS must not claim native Sand OS enforcement until those interfaces exist.

- [ ] Re-inspect the SAND OS networking implementation when its M9 work begins.
- [ ] Document packet/flow lifecycle and ownership.
- [ ] Identify safe inbound and outbound enforcement hook points.
- [ ] Define kernel/userspace boundary and IPC contract.
- [ ] Build a real Sand OS adapter against the documented native interfaces.
- [ ] Add simulator and integration tests before enabling enforcement.

## Milestone 3 — Sand OS minimum viable enforcement

- [ ] Implement native adapter using Sand OS networking facilities.
- [ ] Support explicit inbound/outbound allow and deny rules.
- [ ] Add loopback and essential system-traffic protections.
- [ ] Add atomic policy updates and recovery mode.
- [ ] Validate behaviour under adapter crash and restart.
- [ ] Document how to disable or recover the firewall.

## Milestone 4 — Operations and observability

- [ ] Structured event log and audit trail.
- [ ] CLI for status, policy validation, and diagnostics.
- [ ] Secure control-plane permissions.
- [ ] Resource limits and performance benchmarks.

## Milestone 5 — Linux adapter

- [ ] Implement Linux adapter using supported native facilities.
- [ ] Test IPv4/IPv6, TCP/UDP, loopback, and interface changes.
- [ ] Test boot, shutdown, upgrade, and rollback behaviour.

## Milestone 6 — Windows adapter

- [ ] Design WFP integration and service boundary.
- [ ] Implement signed and appropriately packaged components as required.
- [ ] Test service lifecycle, policy persistence, and recovery.
- [ ] Validate IPv4/IPv6 and application identity handling.

## Milestone 7 — Advanced security

- [x] Add bounded TCP/UDP connection tracking with state transitions, timeouts, interface-aware flow keys, and capacity handling.
- [x] Add token-bucket and bounded per-key rate-limiting primitives.
- [x] Integrate trackers and rate limits with the portable packet-level runtime API.
- [ ] Connect tracker/rate-limit processing to native adapter traffic callbacks.
- [x] Add independent DNS wire parser, versioned domain policy, request correlation, and positive-response cache.
- [x] Integrate DNS decisions, per-client rate limiting, response correlation, cache admission, and audit events into the portable engine.
- [x] Add offline DNS policy validation and canonical export CLI commands.
- [x] Add bounded UDP/TCP DNS proxy transport with plain UDP/TCP upstream forwarding.
- [x] Add a loopback-first CLI launcher and live local UDP/TCP forwarding tests.
- [x] Add authenticated DNS-over-TLS upstream transport with certificate and hostname validation.
- [x] Add authenticated DNS-over-HTTPS upstream transport with certificate validation, redirect blocking, numeric bootstrap, content-type checks, and bounded response bodies.
- [x] Add encrypted DNS transport integration tests with an isolated trusted test CA and local TLS/HTTPS fixtures; verify successful DoT/DoH exchanges, untrusted-CA rejection, and hostname mismatch rejection.
- [ ] Connect DNS service to native adapter traffic callbacks and OS resolver configuration.
- [ ] Threat intelligence feeds with provenance and expiry.
- [ ] Anomaly detection as an advisory layer, not an unchecked authority.
- [ ] Optional management dashboard.

## Release gates

A platform is not considered supported until it has repeatable integration tests, documented install/uninstall and recovery procedures, clear privilege requirements, and tested failure behaviour.
