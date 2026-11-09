# EREBUS Policy Model

## Status

The current Rust policy evaluator supports ordered, first-match rules over normalized traffic metadata. It does not load TOML/JSON configuration and it does not capture, inspect, allow, or block live network packets. The example configuration is illustrative until a validated loader is implemented.

## Rule selectors

Each rule may contain these optional selectors:

| Selector | Match semantics |
| --- | --- |
| `direction` | Exact inbound or outbound match |
| `protocol` | Exact normalized transport protocol match |
| `source` | Source IP address must belong to the configured IPv4 or IPv6 prefix |
| `destination` | Destination IP address must belong to the configured IPv4 or IPv6 prefix |
| `source_port` | Source port must equal the configured port |
| `destination_port` | Destination port must equal the configured port |
| `interface` | Interface name must match exactly |

A selector set to None is a wildcard. All configured selectors in a rule must match for that rule to match.

## CIDR semantics

The `IpNetwork` type accepts IPv4 and IPv6 CIDR strings, for example:

- `192.0.2.0/24`
- `198.51.100.12/32`
- `2001:db8:1234::/48`
- `2001:db8::1/128`

Host bits are normalized to the network boundary. Address families never cross-match: an IPv4 prefix cannot match an IPv6 address and vice versa. Prefix lengths greater than 32 for IPv4 or 128 for IPv6 are rejected.

## Evaluation order

1. Rules are evaluated in the order supplied.
2. The first rule whose populated selectors all match supplies the verdict.
3. If no rule matches, the explicitly configured default policy supplies the verdict.
4. The returned decision records either the matched rule identifier or that the default policy was used.

Duplicate and empty rule IDs are rejected. Empty interface selectors are rejected.

## Important limitations

- Port selectors are exact single-port matches; port ranges are not implemented.
- Interface names use exact string matching; wildcard and alias semantics are not implemented.
- No DNS names, application identities, user identities, schedules, connection states, or packet payload selectors are supported yet.
- Rule matching consumes normalized metadata. The OS adapter must validate that metadata before constructing a descriptor.
- An adapter must not treat a policy verdict as proof that enforcement succeeded; enforcement errors must be reported separately.

## Example

The following is illustrative syntax, not yet accepted by a configuration loader:

```toml
[policy]
default = "deny"

[[rules]]
id = "allow-outbound-web"
direction = "outbound"
protocol = "tcp"
destination = "198.51.100.0/24"
destination_port = 443
action = "allow"

[[rules]]
id = "deny-untrusted-admin"
direction = "inbound"
protocol = "tcp"
source = "0.0.0.0/0"
destination_port = 22
interface = "eth0"
action = "deny"
```
