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

## Sand OS questions to resolve

Before coding the first native adapter, inspect Sand OS and document:

1. Does the kernel currently have Ethernet and IP layer support?
2. Where are inbound and outbound packets represented?
3. Is there an interface abstraction and routing layer?
4. Can the network stack invoke a synchronous policy hook?
5. Is userspace networking or a privileged service available?
6. What mechanism safely transports policy updates to the kernel?
7. How will boot recovery work if a policy prevents normal network access?
