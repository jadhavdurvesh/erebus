# Platform Adapter Strategy

EREBUS keeps policy semantics portable and enforcement native.

| Platform | Priority | Intended integration | Status |
| --- | --- | --- | --- |
| Sand OS | First | Sand OS native networking hooks | Planned |
| Linux | Second | nftables/netlink adapter | Planned |
| Windows | Third | Windows Filtering Platform adapter | Planned |

## Adapter responsibilities

- Validate and normalize platform traffic metadata.
- Translate EREBUS verdicts into platform enforcement actions.
- Report adapter health and enforcement errors.
- Handle lifecycle events, including startup, shutdown, and interface changes.
- Document platform-specific exceptions and limitations.

## Adapter restrictions

- No platform-specific APIs in `erebus-types`, `erebus-policy`, or `erebus-engine`.
- No hidden permissive fallback if enforcement is unavailable.
- No silent conversion of Deny to Allow.
- No packet payload logging by default.
- No claim of platform support until integration tests pass.

## Sand OS readiness

The current SAND OS repository roadmap places its networking foundation at M9. Its current source tree provides the boot chain, x86 interrupt/paging and memory foundations, PIT timer, kernel threads, and synchronization primitives, but no network stack, network drivers, or packet/flow hook API.

Therefore, the EREBUS Sand OS adapter is **blocked on the SAND OS networking foundation**. Do not add a placeholder that suggests traffic is being filtered. In the meantime, validate the portable engine through mock-adapter contract tests.

When SAND OS networking work begins, inspect the current source again; do not assume today's architecture will remain unchanged.

Before coding the native adapter, document:

1. Does the kernel currently have Ethernet and IP layer support?
2. Where are inbound and outbound packets represented?
3. Is there an interface abstraction and routing layer?
4. Can the network stack invoke a synchronous policy hook?
5. Is userspace networking or a privileged service available?
6. What mechanism safely transports policy updates to the kernel?
7. How will boot recovery work if a policy prevents normal network access?
