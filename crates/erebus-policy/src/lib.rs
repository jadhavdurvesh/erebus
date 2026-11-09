//! Deterministic, platform-neutral policy evaluation.

use erebus_types::{
    DecisionReason, Direction, IpNetwork, PolicyDecision, TrafficDescriptor, TransportProtocol,
    Verdict,
};
use thiserror::Error;

/// A single first-match firewall rule.
///
/// Every populated selector must match. A selector set to None is a wildcard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rule {
    pub id: String,
    pub direction: Option<Direction>,
    pub protocol: Option<TransportProtocol>,
    pub source: Option<IpNetwork>,
    pub destination: Option<IpNetwork>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub interface: Option<String>,
    pub verdict: Verdict,
}

impl Rule {
    fn matches(&self, traffic: &TrafficDescriptor) -> bool {
        self.direction
            .map_or(true, |value| value == traffic.direction)
            && self
                .protocol
                .map_or(true, |value| value == traffic.protocol)
            && self
                .source
                .map_or(true, |network| network.contains(traffic.source))
            && self
                .destination
                .map_or(true, |network| network.contains(traffic.destination))
            && self
                .source_port
                .map_or(true, |port| traffic.source_port == Some(port))
            && self
                .destination_port
                .map_or(true, |port| traffic.destination_port == Some(port))
            && self
                .interface
                .as_deref()
                .map_or(true, |name| traffic.interface.as_deref() == Some(name))
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
    #[error("interface selector must not be empty in rule: {0}")]
    EmptyInterfaceSelector(String),
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
            if rule
                .interface
                .as_deref()
                .is_some_and(|interface| interface.trim().is_empty())
            {
                return Err(PolicyError::EmptyInterfaceSelector(rule.id.clone()));
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

    pub fn default_policy(&self) -> DefaultPolicy {
        self.default
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn traffic(destination_port: u16) -> TrafficDescriptor {
        TrafficDescriptor {
            direction: Direction::Inbound,
            protocol: TransportProtocol::Tcp,
            source: IpAddr::V4(Ipv4Addr::LOCALHOST),
            destination: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            source_port: Some(50_000),
            destination_port: Some(destination_port),
            interface: Some("eth0".into()),
            flow_id: None,
        }
    }

    fn rule(id: &str, verdict: Verdict) -> Rule {
        Rule {
            id: id.into(),
            direction: None,
            protocol: None,
            source: None,
            destination: None,
            source_port: None,
            destination_port: None,
            interface: None,
            verdict,
        }
    }

    #[test]
    fn matching_rule_returns_its_verdict_and_id() {
        let mut ssh_rule = rule("deny-ssh", Verdict::Deny);
        ssh_rule.direction = Some(Direction::Inbound);
        ssh_rule.protocol = Some(TransportProtocol::Tcp);
        ssh_rule.destination_port = Some(22);

        let policy = PolicySet::new(vec![ssh_rule], DefaultPolicy::Allow).expect("valid policy");
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
        let mut allow_https = rule("allow-https", Verdict::Allow);
        allow_https.protocol = Some(TransportProtocol::Tcp);
        allow_https.destination_port = Some(443);

        let policy = PolicySet::new(
            vec![allow_https, rule("deny-all", Verdict::Deny)],
            DefaultPolicy::Deny,
        )
        .expect("valid policy");

        assert_eq!(policy.evaluate(&traffic(443)).verdict, Verdict::Allow);
        assert_eq!(policy.evaluate(&traffic(80)).verdict, Verdict::Deny);
    }

    #[test]
    fn duplicate_rule_ids_are_rejected() {
        let duplicate = rule("same", Verdict::Deny);
        let result = PolicySet::new(vec![duplicate.clone(), duplicate], DefaultPolicy::Deny);

        assert_eq!(
            result.unwrap_err(),
            PolicyError::DuplicateRuleId("same".into())
        );
    }

    #[test]
    fn ipv4_source_and_destination_prefixes_are_matched() {
        let mut allow_trusted_subnet = rule("allow-trusted-subnet", Verdict::Allow);
        allow_trusted_subnet.source = Some("127.0.0.0/8".parse().unwrap());
        allow_trusted_subnet.destination = Some("192.0.2.0/24".parse().unwrap());

        let policy = PolicySet::new(vec![allow_trusted_subnet], DefaultPolicy::Deny).unwrap();

        assert_eq!(policy.evaluate(&traffic(443)).verdict, Verdict::Allow);

        let mut outside = traffic(443);
        outside.destination = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));
        assert_eq!(policy.evaluate(&outside).verdict, Verdict::Deny);
    }

    #[test]
    fn ipv6_prefix_rules_are_supported() {
        let mut allow_v6 = rule("allow-documentation-v6", Verdict::Allow);
        allow_v6.source = Some("2001:db8:1::/48".parse().unwrap());

        let policy = PolicySet::new(vec![allow_v6], DefaultPolicy::Deny).unwrap();
        let mut packet = traffic(443);
        packet.source = IpAddr::V6("2001:db8:1:2::99".parse::<Ipv6Addr>().unwrap());

        assert_eq!(policy.evaluate(&packet).verdict, Verdict::Allow);

        packet.source = IpAddr::V6("2001:db8:2::99".parse::<Ipv6Addr>().unwrap());
        assert_eq!(policy.evaluate(&packet).verdict, Verdict::Deny);
    }

    #[test]
    fn source_port_and_interface_selectors_are_enforced() {
        let mut specific_rule = rule("allow-management-interface", Verdict::Allow);
        specific_rule.source_port = Some(50_000);
        specific_rule.interface = Some("eth0".into());

        let policy = PolicySet::new(vec![specific_rule], DefaultPolicy::Deny).unwrap();
        assert_eq!(policy.evaluate(&traffic(443)).verdict, Verdict::Allow);

        let mut wrong_interface = traffic(443);
        wrong_interface.interface = Some("wlan0".into());
        assert_eq!(policy.evaluate(&wrong_interface).verdict, Verdict::Deny);

        let mut wrong_source_port = traffic(443);
        wrong_source_port.source_port = Some(12_345);
        assert_eq!(policy.evaluate(&wrong_source_port).verdict, Verdict::Deny);
    }

    #[test]
    fn empty_interface_selectors_are_rejected() {
        let mut invalid = rule("invalid-interface", Verdict::Deny);
        invalid.interface = Some("  ".into());

        assert_eq!(
            PolicySet::new(vec![invalid], DefaultPolicy::Deny).unwrap_err(),
            PolicyError::EmptyInterfaceSelector("invalid-interface".into())
        );
    }
}
