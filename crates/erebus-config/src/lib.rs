//! Versioned TOML policy configuration for EREBUS.
//!
//! Parsing and validation are intentionally separate from packet enforcement.
//! A successfully parsed document is safe to hand to the portable policy
//! evaluator, but it does not apply rules to an operating system.

use erebus_policy::{DefaultPolicy, PolicyError, PolicySet, Rule};
use erebus_types::{Direction, IpNetwork, TransportProtocol, Verdict};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CURRENT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("TOML parse error: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("TOML serialization error: {0}")]
    Serialize(#[from] toml::ser::Error),
    #[error("unsupported schema version {found}; supported version is {supported}")]
    UnsupportedVersion { found: u32, supported: u32 },
    #[error("invalid {field} value '{value}' in rule '{rule_id}'")]
    InvalidField {
        rule_id: String,
        field: &'static str,
        value: String,
    },
    #[error("invalid {field} value '{value}' in policy section")]
    InvalidPolicyValue { field: &'static str, value: String },
    #[error("invalid {field} network prefix '{value}' in rule '{rule_id}': {source}")]
    InvalidNetwork {
        rule_id: String,
        field: &'static str,
        value: String,
        #[source]
        source: erebus_types::IpNetworkError,
    },
    #[error("policy validation failed: {0}")]
    Policy(#[from] PolicyError),
}

/// Top-level configuration document.
///
/// Unknown keys are rejected to catch misspellings instead of silently
/// ignoring security-relevant configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    pub schema_version: u32,
    pub policy: PolicyOptions,
    pub rules: Vec<RuleDocument>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyOptions {
    pub default: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleDocument {
    pub id: String,
    pub direction: Option<String>,
    pub protocol: Option<String>,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub interface: Option<String>,
    pub action: String,
}

impl PolicyDocument {
    /// Parse TOML and validate every field, selector, and rule identifier.
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let document: Self = toml::from_str(input)?;
        document.validate()?;
        Ok(document)
    }

    /// Validate the document and convert it to the portable policy evaluator.
    pub fn to_policy_set(&self) -> Result<PolicySet, ConfigError> {
        self.validate()?;

        let default = match self.policy.default.as_str() {
            "allow" => DefaultPolicy::Allow,
            "deny" => DefaultPolicy::Deny,
            value => {
                return Err(ConfigError::InvalidPolicyValue {
                    field: "default",
                    value: value.to_owned(),
                });
            }
        };

        let mut rules = Vec::with_capacity(self.rules.len());
        for item in &self.rules {
            let direction = parse_optional(
                &item.id,
                "direction",
                item.direction.as_deref(),
                |v| match v {
                    "inbound" => Some(Direction::Inbound),
                    "outbound" => Some(Direction::Outbound),
                    _ => None,
                },
            )?;

            let protocol =
                parse_optional(
                    &item.id,
                    "protocol",
                    item.protocol.as_deref(),
                    |v| match v {
                        "tcp" => Some(TransportProtocol::Tcp),
                        "udp" => Some(TransportProtocol::Udp),
                        "icmp" => Some(TransportProtocol::Icmp),
                        _ => None,
                    },
                )?;

            let source = parse_network(&item.id, "source", item.source.as_deref())?;
            let destination = parse_network(&item.id, "destination", item.destination.as_deref())?;

            let verdict = match item.action.as_str() {
                "allow" => Verdict::Allow,
                "deny" => Verdict::Deny,
                value => {
                    return Err(ConfigError::InvalidField {
                        rule_id: item.id.clone(),
                        field: "action",
                        value: value.to_owned(),
                    });
                }
            };

            rules.push(Rule {
                id: item.id.clone(),
                direction,
                protocol,
                source,
                destination,
                source_port: item.source_port,
                destination_port: item.destination_port,
                interface: item.interface.clone(),
                verdict,
            });
        }

        Ok(PolicySet::new(rules, default)?)
    }

    /// Validate schema and document fields without constructing a policy set.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != CURRENT_SCHEMA_VERSION {
            return Err(ConfigError::UnsupportedVersion {
                found: self.schema_version,
                supported: CURRENT_SCHEMA_VERSION,
            });
        }

        match self.policy.default.as_str() {
            "allow" | "deny" => {}
            value => {
                return Err(ConfigError::InvalidPolicyValue {
                    field: "default",
                    value: value.to_owned(),
                });
            }
        }

        // Full semantic validation is performed by conversion. Doing it here
        // makes parse() a validation boundary for consumers.
        self.to_policy_set_unchecked_schema()?;
        Ok(())
    }

    fn to_policy_set_unchecked_schema(&self) -> Result<PolicySet, ConfigError> {
        let mut rules = Vec::with_capacity(self.rules.len());

        for item in &self.rules {
            let direction = parse_optional(
                &item.id,
                "direction",
                item.direction.as_deref(),
                |v| match v {
                    "inbound" => Some(Direction::Inbound),
                    "outbound" => Some(Direction::Outbound),
                    _ => None,
                },
            )?;

            let protocol =
                parse_optional(
                    &item.id,
                    "protocol",
                    item.protocol.as_deref(),
                    |v| match v {
                        "tcp" => Some(TransportProtocol::Tcp),
                        "udp" => Some(TransportProtocol::Udp),
                        "icmp" => Some(TransportProtocol::Icmp),
                        _ => None,
                    },
                )?;

            let source = parse_network(&item.id, "source", item.source.as_deref())?;
            let destination = parse_network(&item.id, "destination", item.destination.as_deref())?;

            let verdict = match item.action.as_str() {
                "allow" => Verdict::Allow,
                "deny" => Verdict::Deny,
                value => {
                    return Err(ConfigError::InvalidField {
                        rule_id: item.id.clone(),
                        field: "action",
                        value: value.to_owned(),
                    });
                }
            };

            rules.push(Rule {
                id: item.id.clone(),
                direction,
                protocol,
                source,
                destination,
                source_port: item.source_port,
                destination_port: item.destination_port,
                interface: item.interface.clone(),
                verdict,
            });
        }

        let default = match self.policy.default.as_str() {
            "allow" => DefaultPolicy::Allow,
            "deny" => DefaultPolicy::Deny,
            value => {
                return Err(ConfigError::InvalidPolicyValue {
                    field: "default",
                    value: value.to_owned(),
                });
            }
        };

        Ok(PolicySet::new(rules, default)?)
    }

    /// Serialize a validated document using the canonical TOML pretty printer.
    /// Rule order is preserved because rule order affects evaluation.
    pub fn canonical_toml(&self) -> Result<String, ConfigError> {
        self.validate()?;
        Ok(toml::to_string_pretty(self)?)
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

fn parse_optional<T>(
    rule_id: &str,
    field: &'static str,
    value: Option<&str>,
    parser: impl FnOnce(&str) -> Option<T>,
) -> Result<Option<T>, ConfigError> {
    match value {
        Some(value) => parser(value)
            .map(Some)
            .ok_or_else(|| ConfigError::InvalidField {
                rule_id: rule_id.to_owned(),
                field,
                value: value.to_owned(),
            }),
        None => Ok(None),
    }
}

fn parse_network(
    rule_id: &str,
    field: &'static str,
    value: Option<&str>,
) -> Result<Option<IpNetwork>, ConfigError> {
    value
        .map(|value| {
            value.parse().map_err(|source| ConfigError::InvalidNetwork {
                rule_id: rule_id.to_owned(),
                value: value.to_owned(),
                source,
            })
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
schema_version = 1

[policy]
default = "deny"

[[rules]]
id = "allow-web"
direction = "outbound"
protocol = "tcp"
destination = "198.51.100.0/24"
destination_port = 443
action = "allow"

[[rules]]
id = "deny-ssh"
direction = "inbound"
protocol = "tcp"
destination_port = 22
interface = "eth0"
action = "deny"
"#;

    #[test]
    fn parses_and_converts_a_valid_policy() {
        let document = PolicyDocument::parse(VALID).unwrap();
        assert_eq!(document.rule_count(), 2);
        let policy = document.to_policy_set().unwrap();
        assert_eq!(policy.rules().len(), 2);
        assert_eq!(policy.default_policy(), DefaultPolicy::Deny);
    }

    #[test]
    fn rejects_unsupported_schema_versions() {
        let input = VALID.replace("schema_version = 1", "schema_version = 2");
        assert!(matches!(
            PolicyDocument::parse(&input),
            Err(ConfigError::UnsupportedVersion {
                found: 2,
                supported: 1
            })
        ));
    }

    #[test]
    fn rejects_unknown_top_level_and_rule_fields() {
        let input = VALID.replace("schema_version = 1", "schema_version = 1\nmode = \"fast\"");
        assert!(PolicyDocument::parse(&input).is_err());

        let input = VALID.replace("action = \"allow\"", "action = \"allow\"\nporrt = 443");
        assert!(PolicyDocument::parse(&input).is_err());
    }

    #[test]
    fn rejects_invalid_protocol_action_and_network() {
        let input = VALID.replace("protocol = \"tcp\"", "protocol = \"sctp\"");
        assert!(matches!(
            PolicyDocument::parse(&input),
            Err(ConfigError::InvalidField {
                field: "protocol",
                ..
            })
        ));

        let input = VALID.replace("action = \"allow\"", "action = \"permit\"");
        assert!(matches!(
            PolicyDocument::parse(&input),
            Err(ConfigError::InvalidField {
                field: "action",
                ..
            })
        ));

        let input = VALID.replace("198.51.100.0/24", "198.51.100.0/99");
        assert!(matches!(
            PolicyDocument::parse(&input),
            Err(ConfigError::InvalidNetwork { .. })
        ));
    }

    #[test]
    fn rejects_duplicate_rule_ids() {
        let input = VALID.replace("id = \"deny-ssh\"", "id = \"allow-web\"");
        assert!(matches!(
            PolicyDocument::parse(&input),
            Err(ConfigError::Policy(PolicyError::DuplicateRuleId(_)))
        ));
    }

    #[test]
    fn canonical_export_round_trips_and_preserves_rule_order() {
        let document = PolicyDocument::parse(VALID).unwrap();
        let canonical = document.canonical_toml().unwrap();
        let reparsed = PolicyDocument::parse(&canonical).unwrap();

        assert_eq!(document, reparsed);
        assert!(canonical.find("allow-web").unwrap() < canonical.find("deny-ssh").unwrap());
    }

    #[test]
    fn rejects_empty_interface_and_empty_rule_id() {
        let input = VALID.replace("interface = \"eth0\"", "interface = \" \"");
        assert!(matches!(
            PolicyDocument::parse(&input),
            Err(ConfigError::Policy(PolicyError::EmptyInterfaceSelector(_)))
        ));

        let input = VALID.replace("id = \"allow-web\"", "id = \"\"");
        assert!(matches!(
            PolicyDocument::parse(&input),
            Err(ConfigError::Policy(PolicyError::EmptyRuleId))
        ));
    }
}
