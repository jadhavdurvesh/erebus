# EREBUS Rate Limiting

## Scope

The current rate-limiting module provides token-bucket primitives. It does not install operating-system traffic shaping or automatically throttle network packets. A platform adapter or service must call the limiter and decide how to handle a rejected request.

## Token bucket

A TokenBucket is configured with:

- `capacity`: maximum burst tokens.
- `refill_interval_ms`: one token is added for each full interval.

The bucket begins full. A request supplies a token cost. If enough tokens remain, the cost is deducted and the call returns true; otherwise the call returns false. Fractional refill time is retained so frequent checks do not lose elapsed time. A bucket cannot accumulate tokens beyond its configured capacity.

## Keyed limiter

KeyedRateLimiter maintains separate buckets for bounded keys, such as remote IP addresses. Keys implement the RateLimitKey contract and are limited to 128 encoded bytes. Built-in implementations are provided for IP addresses, strings, byte vectors, and fixed-size byte arrays. Configuration controls:

- Bucket capacity and refill interval.
- Maximum number of keys.
- Idle-key timeout.

Idle keys are pruned during access and can be explicitly pruned. Active keys are never evicted to admit a new key. If the table is full, the caller receives KeyCapacityReached and must handle it explicitly.

## Time semantics

All timestamps are monotonic milliseconds. Clock regressions are rejected. Do not pass wall-clock timestamps.

## Security considerations

- Choose keys carefully: attacker-controlled unbounded strings can exhaust the key table, although memory remains capped.
- For network use, prefer normalized IP-address keys or other bounded identifiers.
- A capacity error or oversized key is not an implicit permission to proceed.
- The caller must decide whether a false token result or key-capacity error should cause delay, deny, or another documented action.
- Rate limiting is not a substitute for connection tracking, authentication, or a firewall policy.
