# EREBUS Security Events

## Purpose

The event journal gives core components a consistent structured record format for policy decisions, reloads, connection lifecycle changes, rate-limit events, and adapter failures.

## Event fields

Every retained event contains:

- A monotonically increasing in-memory sequence number.
- A caller-supplied monotonic timestamp in milliseconds.
- An optional flow identifier.
- A typed event kind.

Event kinds contain metadata only. Packet payloads, credentials, private keys, DNS query contents, and other secrets must not be recorded.

## Bounded retention

The journal is an in-memory FIFO with a fixed maximum number of entries. When full, recording a new event evicts the oldest entry and returns its sequence number in RecordOutcome. Consumers can detect that the retained in-memory history rolled over.

The journal is **not durable storage**. A process restart loses its contents. Production audit requirements will need a separate persistence/export sink, retention policy, permissions model, and tamper-resistance design.

## Time semantics

Timestamps are monotonic milliseconds from the caller's clock, not wall-clock UTC. Backwards timestamps are rejected. A UI or external log sink should attach wall-clock metadata at the boundary if needed, without changing the monotonic ordering used internally.

## Integration

Call EventJournal::record from the subsystem that knows what happened. Keep event recording out of packet hot paths where possible; production adapters should move export and disk I/O to bounded asynchronous queues. An event write is not proof that a platform enforcement operation succeeded: enforcement results must be separately represented.
