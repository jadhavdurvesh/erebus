# EREBUS Portable Enforcement Runtime

## Purpose

The enforcement runtime is the orchestration layer between the portable EREBUS policy engine and a platform adapter. It is not a packet capture implementation and does not itself block operating-system traffic.

The runtime accepts a validated `TrafficDescriptor`, evaluates it against one immutable policy generation, forwards the exact `PolicyDecision` to the active adapter, and records metadata-only audit events.

## Processing sequence

1. A platform adapter receives a packet, flow, or platform filtering callback.
2. The adapter validates the OS-provided data and constructs a normalized `TrafficDescriptor`.
3. The runtime verifies that it is initialized and the adapter reports `Ready`.
4. The runtime obtains one immutable policy snapshot and evaluates the descriptor.
5. The runtime attempts to record a `PolicyDecision` event.
6. The runtime sends the exact decision to `PlatformAdapter::enforce`.
7. On success, the caller receives the decision, policy generation, and optional audit sequence.
8. On adapter failure, the runtime records an enforcement-failure event where possible, faults itself, and refuses subsequent traffic until explicit shutdown and successful reinitialization.

## Failure semantics

- Adapter initialization failures fault the runtime. The caller may still call shutdown to release resources acquired during partial initialization.
- An adapter that claims successful initialization but does not report `Ready` is rejected and can be shut down.
- If adapter enforcement fails, the runtime becomes faulted. It does not convert a deny to allow or continue processing new descriptors.
- If the adapter independently leaves `Ready`, the next runtime request faults and is refused.
- A failed shutdown leaves the runtime faulted.
- A successful shutdown clears the runtime fault. Reinitialization is then required before traffic can be processed.
- Audit journal failures are counted and surfaced in metrics, but do not change the policy verdict or skip adapter enforcement. This makes the distinction between enforcement and audit persistence explicit.
- The in-memory journal is not durable. A production release needs a durable event sink and recovery semantics.

The runtime cannot guarantee that a platform's underlying OS enforcement mechanism is fail-closed. Each adapter must document what its OS API actually guarantees and provide its own emergency policy/recovery behavior.

## API

The runtime is exported as `erebus_engine::EnforcementRuntime`.

Primary operations:

- `new(engine, adapter, event_capacity)`
- `initialize()`
- `evaluate_and_enforce(traffic, monotonic_timestamp_ms)`
- `reload_policy(versioned_toml, monotonic_timestamp_ms)`
- `shutdown()`
- `metrics()`
- `events()`

All timestamps supplied to the event journal must use one monotonically increasing clock domain per runtime.

## What this milestone does not do

- Capture or parse raw IP packets.
- Install kernel hooks or OS filtering rules.
- Create a Linux nftables/eBPF, Windows Filtering Platform, or Sand OS networking adapter.
- Persist policies or events to disk.
- Guarantee adapter enforcement after process termination or machine crash.
- Add connection-tracker or rate-limiter feedback to every platform packet callback yet.

Those responsibilities belong to subsequent adapter, operations, and integration milestones.
