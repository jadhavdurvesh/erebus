//! Deterministic, platform-neutral policy evaluation.

use erebus_types::{
    DecisionReason, Direction, PolicyDecision, TrafficDescriptor, TransportProtocol, Verdict,
};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rule {
    pub id: String,
    pub direction: Option<Direction>,
    pub protocol: Option<TransportProtocol>,
    pub destination_port: Option<u16>,
    pub verdict: Verdict,
}

impl Rule {
    fn matches(&self, traffic: &TrafficDescriptor) -> bool {
        self.direction.map_or(true, |v| v == traffic.direction)
            && self.protocol.map_or(true, |v| v == traffic.protocol)
            && self
                .destination_port
                .map_or(true, |v| traffic.destination_port == Some(v))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DefaultPolicy {
    Allow,
    Deny,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PolicyError {
    #[error("rule identifier must not be empty")]
    EmptyRuleId,
    #[error("duplicate rule identifier: {0}")]
    DuplicateRuleId(String),
}

/// An immutable policy set. Rule order is significant: first matching rule wins.
#[derive(Clone, Debug)]
pub struct PolicySet {
    rules: Vec<Rule>,
    default: DefaultPolicy,
}

impl PolicySet {
    pub fn new(rules: Vec<Rule>, default: DefaultPolicy) -> Result<Self, PolicyError> {
        let mut seen = std::collections::HashSet::new();

        for rule in &rules {
            if rule.id.trim().is_empty() {
                return Err(PolicyError::EmptyRuleId);
            }
            if !seen.insert(rule.id.as_str()) {
                return Err(PolicyError::DuplicateRuleId(rule.id.clone()));
            }
        }

        Ok(Self { rules, default })
    }

    pub fn evaluate(&self, traffic: &TrafficDescriptor) -> PolicyDecision {
        if let Some(rule) = self.rules.iter().find(|rule| rule.matches(traffic)) {
            return PolicyDecision {
                verdict: rule.verdict,
                reason: DecisionReason::MatchedRule {
                    rule_id: rule.id.clone(),
                },
            };
        }

        PolicyDecision {
            verdict: match self.default {
                DefaultPolicy::Allow => Verdict::Allow,
                DefaultPolicy::Deny => Verdict::Deny,
            },
            reason: DecisionReason::DefaultPolicy,
        }
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn traffic(port: u16) -> TrafficDescriptor {
        TrafficDescriptor {
            direction: Direction::Inbound,
            protocol: TransportProtocol::Tcp,
            source: IpAddr::V4(Ipv4Addr::LOCALHOST),
            destination: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            source_port: Some(50_000),
            destination_port: Some(port),
            interface: None,
            flow_id: None,
        }
    }

    #[test]
    fn matching_rule_returns_its_verdict_and_id() {
        let policy = PolicySet::new(
            vec![Rule {
                id: "deny-ssh".into(),
                direction: Some(Direction::Inbound),
                protocol: Some(TransportProtocol::Tcp),
                destination_port: Some(22),
                verdict: Verdict::Deny,
            }],
            DefaultPolicy::Allow,
        )
        .expect("valid policy");

        let decision = policy.evaluate(&traffic(22));
        assert_eq!(decision.verdict, Verdict::Deny);
        assert_eq!(
            decision.reason,
            DecisionReason::MatchedRule {
                rule_id: "deny-ssh".into()
            }
        );
    }

    #[test]
    fn unmatched_traffic_uses_explicit_default() {
        let policy = PolicySet::new(vec![], DefaultPolicy::Deny).expect("valid policy");
        assert_eq!(policy.evaluate(&traffic(443)).verdict, Verdict::Deny);
    }

    #[test]
    fn first_matching_rule_wins() {
        let policy = PolicySet::new(
            vec![
                Rule {
                    id: "allow-https".into(),
                    direction: None,
                    protocol: Some(TransportProtocol::Tcp),
                    destination_port: Some(443),
                    verdict: Verdict::Allow,
                },
                Rule {
                    id: "deny-all".into(),
                    direction: None,
                    protocol: None,
                    destination_port: None,
                    verdict: Verdict::Deny,
                },
            ],
            DefaultPolicy::Deny,
        )
        .expect("valid policy");

        assert_eq!(policy.evaluate(&traffic(443)).verdict, Verdict::Allow);
        assert_eq!(policy.evaluate(&traffic(80)).verdict, Verdict::Deny);
    }

    #[test]
    fn duplicate_rule_ids_are_rejected() {
        let rule = Rule {
            id: "same".into(),
            direction: None,
            protocol: None,
            destination_port: None,
            verdict: Verdict::Deny,
        };
        let result = PolicySet::new(vec![rule.clone(), rule], DefaultPolicy::Deny);
        assert_eq!(result.unwrap_err(), PolicyError::DuplicateRuleId("same".into()));
    }
}
