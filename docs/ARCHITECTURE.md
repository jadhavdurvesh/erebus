# EREBUS Architecture

## Goals

EREBUS is a portable firewall decision engine with native enforcement integrations. It is not an attempt to replace every operating system's network stack.

## Trust boundaries

1. **Untrusted network input:** packet bytes, flow metadata, interface names, and remote endpoints are untrusted.
2. **Platform adapter:** validates platform-provided metadata and maps native events to normalized descriptors.
3. **Policy core:** evaluates normalized descriptors deterministically; it does not parse arbitrary raw packets.
4. **Control plane:** loads and validates configuration. It must not have unrestricted authority to bypass policy.
5. **Audit path:** records decisions and adapter failures without exposing secrets or allowing log data to alter decisions.

## Decision flow

1. Platform adapter receives a platform-native packet or flow event.
2. Adapter validates lengths, protocol fields, addresses, ports, and interface metadata.
3. Adapter builds a `TrafficDescriptor`.
4. Engine evaluates ordered rules and returns an explainable `PolicyDecision`.
5. Adapter applies Allow or Deny using its platform's supported mechanism.
6. Adapter reports enforcement failures and emits structured telemetry.

## Rule semantics

- Rules are evaluated in declaration order.
- The first matching rule wins.
- A policy must explicitly choose its default verdict.
- Invalid or duplicate rule IDs are rejected at load time.
- A policy update should be validated fully before becoming active.
- Policy replacement should be atomic from the evaluator's perspective.

## Platform strategy

### Sand OS (first target)

Integrate with Sand OS's own network stack and packet/flow lifecycle. Do not add Linux nftables as an internal dependency to Sand OS. The exact hook points depend on Sand OS networking APIs and must be documented before implementation.

### Linux

Use a dedicated adapter around supported Linux interfaces. Candidate enforcement mechanisms include nftables/netlink and, where justified, other kernel facilities. The first implementation should prefer an established kernel enforcement path over a new kernel module.

### Windows

Use Windows Filtering Platform (WFP) through a narrowly scoped adapter. Service installation, driver requirements, signing, and privilege boundaries must be designed explicitly.

## Performance

- Avoid allocating on every packet in hot paths where practical.
- Compile policy rules into indexed structures only after correctness is established.
- Keep logging asynchronous and bounded.
- Define benchmarks before claiming throughput or latency improvements.

## Non-goals for the first milestone

- TLS interception or decryption.
- Antivirus or endpoint detection replacement.
- Automatic blocking based only on an opaque ML score.
- Custom kernel modules for all operating systems.
- Claiming protection before enforcement and failure-path tests exist.
