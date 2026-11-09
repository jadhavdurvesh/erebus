//! Reusable domain allow/block policy with deterministic specificity rules.

use std::collections::HashSet;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainAction {
    Allow,
    Block,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainMatchKind {
    Exact,
    Suffix,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainPattern {
    domain: String,
    kind: DomainMatchKind,
}

impl DomainPattern {
    pub fn new(domain: &str, kind: DomainMatchKind) -> Result<Self, DomainPolicyError> {
        Ok(Self {
            domain: normalize_domain(domain)?,
            kind,
        })
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn kind(&self) -> DomainMatchKind {
        self.kind
    }

    pub fn matches(&self, candidate: &str) -> Result<bool, DomainPolicyError> {
        let candidate = normalize_domain(candidate)?;
        Ok(self.matches_normalized(&candidate))
    }

    fn matches_normalized(&self, candidate: &str) -> bool {
        match self.kind {
            DomainMatchKind::Exact => candidate == self.domain,
            DomainMatchKind::Suffix => {
                candidate == self.domain
                    || candidate
                        .strip_suffix(&self.domain)
                        .is_some_and(|prefix| prefix.ends_with('.'))
            }
        }
    }

    fn specificity(&self) -> (usize, u8) {
        (
            self.domain.len(),
            if self.kind == DomainMatchKind::Exact { 1 } else { 0 },
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainRule {
    pub id: String,
    pub pattern: DomainPattern,
    pub action: DomainAction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainDecision {
    pub action: DomainAction,
    pub matched_rule_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct DomainPolicy {
    default_action: DomainAction,
    rules: Vec<DomainRule>,
}

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum DomainPolicyError {
    #[error("domain name is empty")]
    EmptyDomain,
    #[error("domain name contains an invalid ASCII label")]
    InvalidDomain,
    #[error("domain name exceeds 253 bytes")]
    DomainTooLong,
    #[error("domain rule identifier must not be empty")]
    EmptyRuleId,
    #[error("duplicate domain rule identifier: {0}")]
    DuplicateRuleId(String),
}

impl DomainPolicy {
    pub fn new(
        default_action: DomainAction,
        rules: Vec<DomainRule>,
    ) -> Result<Self, DomainPolicyError> {
        let mut ids = HashSet::new();
        for rule in &rules {
            if rule.id.trim().is_empty() {
                return Err(DomainPolicyError::EmptyRuleId);
            }
            if !ids.insert(rule.id.as_str()) {
                return Err(DomainPolicyError::DuplicateRuleId(rule.id.clone()));
            }
        }

        Ok(Self {
            default_action,
            rules,
        })
    }

    pub fn default_action(&self) -> DomainAction {
        self.default_action
    }

    pub fn rules(&self) -> &[DomainRule] {
        &self.rules
    }

    /// The longest matching suffix wins. Exact rules win a specificity tie.
    /// When multiple rules have identical specificity, the first declared rule wins.
    pub fn evaluate(&self, domain: &str) -> Result<DomainDecision, DomainPolicyError> {
        let domain = normalize_domain(domain)?;
        let mut best: Option<(usize, (usize, u8))> = None;

        for (index, rule) in self.rules.iter().enumerate() {
            if !rule.pattern.matches_normalized(&domain) {
                continue;
            }

            let specificity = rule.pattern.specificity();
            if best.map_or(true, |(_, previous)| specificity > previous) {
                best = Some((index, specificity));
            }
        }

        if let Some((index, _)) = best {
            let rule = &self.rules[index];
            Ok(DomainDecision {
                action: rule.action,
                matched_rule_id: Some(rule.id.clone()),
            })
        } else {
            Ok(DomainDecision {
                action: self.default_action,
                matched_rule_id: None,
            })
        }
    }
}

/// Normalize an ASCII DNS presentation name. A single trailing dot is accepted
/// and removed; the result is lowercase and suitable for policy/cache keys.
/// Internationalized names must be supplied in their ASCII A-label (punycode)
/// form. Underscores are accepted for service labels such as _sip._tcp.
pub fn normalize_domain(domain: &str) -> Result<String, DomainPolicyError> {
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    if domain.is_empty() {
        return Err(DomainPolicyError::EmptyDomain);
    }
    if domain.len() > 253 {
        return Err(DomainPolicyError::DomainTooLong);
    }

    for label in domain.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(DomainPolicyError::InvalidDomain);
        }
    }

    Ok(domain.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, domain: &str, kind: DomainMatchKind, action: DomainAction) -> DomainRule {
        DomainRule {
            id: id.into(),
            pattern: DomainPattern::new(domain, kind).unwrap(),
            action,
        }
    }

    #[test]
    fn normalizes_case_and_trailing_dot() {
        assert_eq!(normalize_domain("ExAmPle.COM.").unwrap(), "example.com");
        assert_eq!(normalize_domain("_sip._TCP.example.com").unwrap(), "_sip._tcp.example.com");
    }

    #[test]
    fn exact_rule_matches_only_exact_domain() {
        let pattern = DomainPattern::new("example.com", DomainMatchKind::Exact).unwrap();
        assert!(pattern.matches("EXAMPLE.COM.").unwrap());
        assert!(!pattern.matches("www.example.com").unwrap());
        assert!(!pattern.matches("notexample.com").unwrap());
    }

    #[test]
    fn suffix_rule_matches_apex_and_subdomains_on_label_boundary() {
        let pattern = DomainPattern::new("example.com", DomainMatchKind::Suffix).unwrap();
        assert!(pattern.matches("example.com").unwrap());
        assert!(pattern.matches("www.example.com").unwrap());
        assert!(!pattern.matches("notexample.com").unwrap());
        assert!(!pattern.matches("example.com.attacker.test").unwrap());
    }

    #[test]
    fn longest_and_exact_rules_win() {
        let policy = DomainPolicy::new(
            DomainAction::Allow,
            vec![
                rule("block-example", "example.com", DomainMatchKind::Suffix, DomainAction::Block),
                rule("allow-trusted", "trusted.example.com", DomainMatchKind::Suffix, DomainAction::Allow),
                rule("block-exact", "trusted.example.com", DomainMatchKind::Exact, DomainAction::Block),
            ],
        )
        .unwrap();

        let decision = policy.evaluate("trusted.example.com").unwrap();
        assert_eq!(decision.action, DomainAction::Block);
        assert_eq!(decision.matched_rule_id.as_deref(), Some("block-exact"));

        assert_eq!(
            policy.evaluate("api.trusted.example.com").unwrap().action,
            DomainAction::Allow
        );
        assert_eq!(
            policy.evaluate("other.example.com").unwrap().action,
            DomainAction::Block
        );
        assert_eq!(
            policy.evaluate("elsewhere.test").unwrap().action,
            DomainAction::Allow
        );
    }

    #[test]
    fn rejects_bad_names_and_duplicate_rule_ids() {
        assert_eq!(normalize_domain("bad..example"), Err(DomainPolicyError::InvalidDomain));
        assert_eq!(normalize_domain("-bad.example"), Ok("-bad.example".to_owned()));

        let duplicate = rule("same", "example.com", DomainMatchKind::Exact, DomainAction::Block);
        assert_eq!(
            DomainPolicy::new(DomainAction::Allow, vec![duplicate.clone(), duplicate]),
            Err(DomainPolicyError::DuplicateRuleId("same".into()))
        );
    }
}
