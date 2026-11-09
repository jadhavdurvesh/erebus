# EREBUS Security Model

## Assets to protect

- Host availability and network connectivity.
- Integrity of active firewall policy.
- Confidentiality of local network and connection metadata.
- Integrity and availability of the EREBUS control plane.
- Correct enforcement of explicit Allow and Deny decisions.

## Adversaries

- Remote hosts sending malformed or hostile traffic.
- Local unprivileged processes attempting to bypass policy.
- Misconfigured or compromised management clients.
- Malformed configuration and resource-exhaustion inputs.
- Adapter bugs and partial OS integration failures.

## Security requirements

1. Parse and validate untrusted data before policy evaluation.
2. Keep privileged enforcement separate from unprivileged configuration and UI.
3. Reject malformed, ambiguous, duplicate, or unsupported policy fields.
4. Make the default policy explicit; never silently infer a permissive default.
5. Ensure adapter failure behaviour is documented and tested.
6. Bound queues, log buffers, rule counts, and input sizes.
7. Avoid logging secrets or packet payloads by default.
8. Require explicit authorization for policy changes.
9. Preserve an auditable record of policy changes and enforcement errors.
10. Test fail-open/fail-closed behaviour for each supported enforcement mechanism.

## Safety during development

The current repository contains policy-evaluation scaffolding only. It does not capture or block network traffic. Tests must use synthetic descriptors and isolated test environments until a platform adapter is implemented.

## Responsible testing

Only test network enforcement on systems and networks you own or are explicitly authorized to assess. Never deploy an experimental adapter on a remote machine without a recovery path and out-of-band access.
