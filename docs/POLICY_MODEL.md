# EREBUS Policy Model

## Status

The Rust policy evaluator supports ordered, first-match rules over normalized traffic metadata. The `erebus-config` crate loads and validates schema-versioned TOML documents and converts them into policy sets. The `erebus` CLI can validate and canonically export policy files.

These tools do **not** capture, inspect, allow, or block live network packets. A valid policy document is not an installed firewall policy.

## Schema version 1

Every policy file must begin with a supported schema version:

```toml
schema_version = 1

[policy]
default = "deny"

[[rules]]
id = "allow-outbound-web"
direction = "outbound"
protocol = "tcp"
destination = "198.51.100.0/24"
destination_port = 443
action = "allow"
```

The top-level keys are:

| Key | Required | Meaning |
| --- | --- | --- |
| `schema_version` | Yes | Must equal the current supported version, `1` |
| `policy.default` | Yes | Explicit `allow` or `deny` fallback |
| `rules` | Yes | Ordered array of policy rules; an empty array is allowed |

Unknown fields are rejected at the document, policy, and rule levels. This intentionally catches spelling mistakes rather than silently ignoring them.

## Rule selectors

Each rule has a required unique non-empty `id` and `action` (`allow` or `deny`). The following selectors are optional:

| Selector | Accepted values | Match semantics |
| --- | --- | --- |
| `direction` | `inbound`, `outbound` | Exact direction |
| `protocol` | `tcp`, `udp`, `icmp` | Exact normalized protocol |
| `source` | IPv4/IPv6 CIDR | Source address belongs to prefix |
| `destination` | IPv4/IPv6 CIDR | Destination address belongs to prefix |
| `source_port` | Integer 0–65535 | Exact source port |
| `destination_port` | Integer 0–65535 | Exact destination port |
| `interface` | Non-empty string | Exact interface-name match |

All configured selectors in a rule must match. A selector that is absent is a wildcard. An IPv4 prefix never matches an IPv6 address or vice versa.

## CIDR semantics

The `IpNetwork` type accepts IPv4 and IPv6 CIDR strings, for example:

- `192.0.2.0/24`
- `198.51.100.12/32`
- `2001:db8:1234::/48`
- `2001:db8::1/128`

Host bits are normalized to the network boundary. Prefix lengths greater than 32 for IPv4 or 128 for IPv6 are rejected.

## Evaluation and validation

1. Rules are evaluated in declaration order.
2. The first rule whose configured selectors all match supplies the verdict.
3. If no rule matches, the explicitly configured default policy supplies the verdict.
4. A decision records the matched rule identifier or that the default policy was used.
5. Duplicate/empty rule IDs, empty interface selectors, malformed prefixes, unsupported enum values, and unknown TOML fields are rejected.
6. Unsupported schema versions are rejected before the document can become a policy.

Canonical export uses TOML serialization and preserves rule order because ordering is semantically significant.

## CLI

```bash
# Validate a file without changing host networking
cargo run -p erebus-cli -- validate examples/policy.toml

# Print canonical TOML to stdout
cargo run -p erebus-cli -- export examples/policy.toml

# Write canonical TOML to another file
cargo run -p erebus-cli -- export examples/policy.toml --output build/policy.normalized.toml
```

The CLI is offline tooling. There is no install/apply command.

## Important limitations

- Port selectors are exact single-port matches; ranges are not implemented.
- Interface names use exact string matching; wildcard and alias semantics are not implemented.
- No DNS names, application identities, user identities, schedules, connection states, or packet-payload selectors are supported yet.
- The configuration is validated before conversion to the policy engine, but no live packet enforcement is implemented.
- A platform adapter must report enforcement outcomes separately; a policy verdict alone does not prove the OS applied it.
