//! Reusable, platform-neutral DNS security components.
//!
//! This crate parses, validates, evaluates, caches, and correlates DNS data.
//! It does not open sockets, intercept traffic, or change host resolver settings.

pub mod cache;
pub mod config;
pub mod policy;
pub mod proxy;
pub mod tracker;
pub mod wire;

pub use cache::{CacheInsertOutcome, DnsCache, DnsCacheConfig, DnsCacheError};
pub use config::{DnsConfigError, DnsPolicyDocument, CURRENT_DNS_SCHEMA_VERSION};
pub use policy::{
    normalize_domain, DomainAction, DomainDecision, DomainMatchKind, DomainPattern, DomainPolicy,
    DomainPolicyError, DomainRule,
};
pub use proxy::{
    DnsExchange, DnsProxy, DnsProxyConfig, DnsProxyDecision, DnsProxyError, DnsProxyMetrics,
    DnsProxyPolicy, DnsProxyPolicyError, DnsUpstreamProtocol,
};
pub use tracker::{
    DnsRequestObservation, DnsRequestTracker, DnsResponseObservation, DnsTrackerConfig,
    DnsTrackerError, DnsTransport,
};
pub use wire::{
    DnsHeader, DnsMessage, DnsParseError, DnsQuestion, DnsRecord, DnsRecordData, ParseLimits,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_exports_the_independent_dns_surface() {
        let policy = DomainPolicy::new(
            DomainAction::Allow,
            vec![DomainRule {
                id: "block-test".into(),
                pattern: DomainPattern::new("test.example", DomainMatchKind::Suffix).unwrap(),
                action: DomainAction::Block,
            }],
        )
        .unwrap();

        assert_eq!(
            policy.evaluate("host.test.example").unwrap().action,
            DomainAction::Block
        );
        assert_eq!(CURRENT_DNS_SCHEMA_VERSION, 1);
    }
}
