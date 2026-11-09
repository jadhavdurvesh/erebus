//! Versioned TOML configuration for DNS domain policy.

use crate::policy::{
    DomainAction, DomainMatchKind, DomainPolicy, DomainPolicyError, DomainPattern, DomainRule,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CURRENT_DNS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum DnsConfigError {
    #[error("TOML parse error: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("TOML serialization error: {0}")]
    Serialize(#[from] toml::ser::Error),
    #[error("unsupported DNS schema version {found}; supported version is {supported}")]
    UnsupportedVersion { found: u32, supported: u32 },
    #[error("invalid DNS policy value '{0}'")]
    InvalidDefault(String),
    #[error("invalid action '{action}' in rule '{rule_id}'")]
    InvalidAction { rule_id: String, action: String },
    #[error("invalid match kind '{kind}' in rule '{rule_id}'")]
    InvalidMatchKind { rule_id: String, kind: String },
    #[error("invalid domain in rule '{rule_id}': {source}")]
    InvalidDomain {
        rule_id: String,
        #[source]
        source: DomainPolicyError,
    },
    #[error("DNS policy validation failed: {0}")]
    Policy(#[from] DomainPolicyError),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsPolicyDocument {
    pub schema_version: u32,
    pub policy: DnsPolicyOptions,
    pub rules: Vec<DnsRuleDocument>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsPolicyOptions {
    pub default: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsRuleDocument {
    pub id: String,
    pub domain: String,
    #[serde(rename = "match")]
    pub match_kind: String,
    pub action: String,
}

impl DnsPolicyDocument {
    pub fn parse(input: &str) -> Result<Self, DnsConfigError> {
        let document: Self = toml::from_str(input)?;
        document.to_policy()?;
        Ok(document)
    }

    pub fn to_policy(&self) -> Result<DomainPolicy, DnsConfigError> {
        if self.schema_version != CURRENT_DNS_SCHEMA_VERSION {
            return Err(DnsConfigError::UnsupportedVersion {
                found: self.schema_version,
                supported: CURRENT_DNS_SCHEMA_VERSION,
            });
        }

        let default_action = parse_action(&self.policy.default)
            .ok_or_else(|| DnsConfigError::InvalidDefault(self.policy.default.clone()))?;

        let mut rules = Vec::with_capacity(self.rules.len());
        for rule in &self.rules {
            let match_kind = match rule.match_kind.as_str() {
                "exact" => DomainMatchKind::Exact,
                "suffix" => DomainMatchKind::Suffix,
                value => {
                    return Err(DnsConfigError::InvalidMatchKind {
                        rule_id: rule.id.clone(),
                        kind: value.to_owned(),
                    });
                }
            };
            let action =
                parse_action(&rule.action).ok_or_else(|| DnsConfigError::InvalidAction {
                    rule_id: rule.id.clone(),
                    action: rule.action.clone(),
                })?;
            let pattern = DomainPattern::new(&rule.domain, match_kind).map_err(|source| {
                DnsConfigError::InvalidDomain {
                    rule_id: rule.id.clone(),
                    source,
                }
            })?;

            rules.push(DomainRule {
                id: rule.id.clone(),
                pattern,
                action,
            });
        }

        Ok(DomainPolicy::new(default_action, rules)?)
    }

    pub fn canonical_toml(&self) -> Result<String, DnsConfigError> {
        self.to_policy()?;
        Ok(toml::to_string_pretty(self)?)
    }
}

fn parse_action(value: &str) -> Option<DomainAction> {
    match value {
        "allow" => Some(DomainAction::Allow),
        "block" => Some(DomainAction::Block),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
schema_version = 1

[policy]
default = "allow"

[[rules]]
id = "block-adware"
domain = "ads.example"
match = "suffix"
action = "block"

[[rules]]
id = "allow-admin"
domain = "admin.example"
match = "exact"
action = "allow"
"#;

    #[test]
    fn parses_and_converts_valid_document() {
        let document = DnsPolicyDocument::parse(VALID).unwrap();
        let policy = document.to_policy().unwrap();
        assert_eq!(policy.rules().len(), 2);
        assert_eq!(policy.evaluate("sub.ads.example").unwrap().action, DomainAction::Block);
    }

    #[test]
    fn rejects_unsupported_version_and_unknown_fields() {
        let input = VALID.replace("schema_version = 1", "schema_version = 2");
        assert!(matches!(
            DnsPolicyDocument::parse(&input),
            Err(DnsConfigError::UnsupportedVersion { found: 2, supported: 1 })
        ));

        let input = VALID.replace("schema_version = 1", "schema_version = 1\nmode = \"fast\"");
        assert!(DnsPolicyDocument::parse(&input).is_err());
    }

    #[test]
    fn rejects_invalid_action_match_kind_and_domain() {
        let input = VALID.replace("action = \"block\"", "action = \"deny\"");
        assert!(matches!(
            DnsPolicyDocument::parse(&input),
            Err(DnsConfigError::InvalidAction { .. })
        ));

        let input = VALID.replace("match = \"suffix\"", "match = \"wildcard\"");
        assert!(matches!(
            DnsPolicyDocument::parse(&input),
            Err(DnsConfigError::InvalidMatchKind { .. })
        ));

        let input = VALID.replace("ads.example", "bad..example");
        assert!(matches!(
            DnsPolicyDocument::parse(&input),
            Err(DnsConfigError::InvalidDomain { .. })
        ));
    }

    #[test]
    fn canonical_export_round_trips() {
        let document = DnsPolicyDocument::parse(VALID).unwrap();
        let canonical = document.canonical_toml().unwrap();
        assert_eq!(DnsPolicyDocument::parse(&canonical).unwrap(), document);
    }
}
