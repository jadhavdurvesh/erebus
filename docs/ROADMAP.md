# EREBUS Roadmap

This roadmap describes intended work; listed items are not claims of completed functionality.

## Milestone 0 — Foundation

- [x] Establish Rust workspace.
- [x] Define portable traffic and verdict types.
- [x] Implement deterministic first-match policy evaluation.
- [x] Define platform adapter contract.
- [ ] Add CI and verify formatting, tests, and linting.
- [ ] Define configuration schema and versioning rules.

## Milestone 1 — Sand OS integration research

- [ ] Document Sand OS network architecture and packet/flow lifecycle.
- [ ] Identify safe inbound and outbound enforcement hook points.
- [ ] Define kernel/userspace boundary and IPC contract.
- [ ] Build a no-op Sand OS adapter for integration testing.
- [ ] Add simulator tests before enabling real enforcement.

## Milestone 2 — Sand OS minimum viable enforcement

- [ ] Implement native adapter using Sand OS networking facilities.
- [ ] Support explicit inbound/outbound allow and deny rules.
- [ ] Add loopback and essential system-traffic protections.
- [ ] Add atomic policy updates and recovery mode.
- [ ] Validate behaviour under adapter crash and restart.
- [ ] Document how to disable or recover the firewall.

## Milestone 3 — Operations and observability

- [ ] Structured event log and audit trail.
- [ ] CLI for status, policy validation, and diagnostics.
- [ ] Secure control-plane permissions.
- [ ] Resource limits and performance benchmarks.

## Milestone 4 — Linux adapter

- [ ] Implement Linux adapter using supported native facilities.
- [ ] Test IPv4/IPv6, TCP/UDP, loopback, and interface changes.
- [ ] Test boot, shutdown, upgrade, and rollback behaviour.

## Milestone 5 — Windows adapter

- [ ] Design WFP integration and service boundary.
- [ ] Implement signed and appropriately packaged components as required.
- [ ] Test service lifecycle, policy persistence, and recovery.
- [ ] Validate IPv4/IPv6 and application identity handling.

## Milestone 6 — Advanced security

- [ ] Stateful connection tracking.
- [ ] DNS policy integration.
- [ ] Rate limiting.
- [ ] Threat intelligence feeds with provenance and expiry.
- [ ] Anomaly detection as an advisory layer, not an unchecked authority.
- [ ] Optional management dashboard.

## Release gates

A platform is not considered supported until it has repeatable integration tests, documented install/uninstall and recovery procedures, clear privilege requirements, and tested failure behaviour.
