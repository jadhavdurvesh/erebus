# EREBUS Connection Tracking

## Scope

The connection tracker is a bounded, in-memory state model for normalized packet/flow metadata. It is not a packet parser, network sniffer, TCP implementation, or enforcement adapter. It does not inspect payloads, verify TCP checksums, track sequence windows, perform retransmission handling, or infer that an unobserved handshake succeeded.

The caller supplies validated traffic descriptors, TCP flags where applicable, and monotonic timestamps in milliseconds.

## Flow identity

A flow key contains:

- Transport protocol.
- Network interface identity (optional).
- Canonically ordered source and destination IP/port endpoints.

The canonical endpoint order lets a reply packet locate the flow in reverse direction. The first observed packet determines the initiator/responder roles. A midstream TCP observation is marked Midstream and is never automatically promoted to Established merely because subsequent ACK packets arrive.

## TCP states

| State | Meaning |
| --- | --- |
| SynSent | First observed packet is SYN without ACK |
| SynReceived | Reverse SYN+ACK observed |
| Established | Handshake progression observed through final ACK |
| Midstream | First observed TCP packet did not begin with SYN |
| FinWait | One endpoint has sent FIN |
| TimeWait | Both endpoints have sent FIN |
| Reset | RST observed |

These are intentionally simplified states. This implementation does not validate sequence numbers or complete TCP control-block semantics. Adapters must not use the state as proof of a fully valid TCP connection.

## UDP and other protocols

- UDP starts as Unreplied.
- A packet from the reverse endpoint changes it to Replied.
- ICMP and other protocol values use an Other state with a separate timeout. ICMP identifier/type-specific tracking is not implemented.

## Timeouts and bounded capacity

Timeouts are configurable by state family. An entry expires when `expires_at_ms <= now_ms`. Every observation refreshes the timeout for its current state.

The maximum number of entries is set at construction. Interface identifiers are also limited to 256 UTF-8 bytes before being copied into a flow key. Expired entries are pruned during observations or by calling `expire(now_ms)`. Active entries are never evicted to make room: a full table returns CapacityReached. The caller should treat a capacity error as an explicit condition and apply its documented policy; it must not silently assume a flow is established.

All supplied times must be monotonic. A backwards timestamp is rejected.

## Safe integration requirements

1. Validate IP/port/protocol metadata in the platform adapter before calling the tracker.
2. Supply TCP flags only from a trusted native packet/flow parser.
3. Use a monotonic clock, not wall-clock time.
4. Choose timeout values appropriate to the platform and connection type.
5. Bound table size and expose capacity/expiry metrics.
6. Never use tracker state alone as an allow verdict; policy evaluation and native enforcement remain separate.

## Example

```rust
use erebus_engine::{ConnectionTracker, TcpFlags, TrackerConfig};

let mut tracker = ConnectionTracker::new(TrackerConfig::default())?;
let observation = tracker.observe(&validated_traffic, Some(TcpFlags::syn()), monotonic_ms)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```
