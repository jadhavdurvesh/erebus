//! Engine-side integration for the reusable DNS security crate.
//!
//! This service evaluates already-parsed DNS messages. It does not open sockets,
//! receive packets, forward queries, or install DNS/network interception.

use erebus_dns::{
    normalize_domain, CacheInsertOutcome, DnsCache, DnsCacheConfig, DnsCacheError, DnsMessage,
    DnsPolicyDocument, DnsRequestObservation, DnsRequestTracker, DnsResponseObservation,
    DnsTrackerConfig, DnsTrackerError, DnsTransport, DomainAction, DomainPolicyError,
};
use std::net::IpAddr;
use thiserror::Error;

use crate::{
    events::{EventJournal, EventJournalError, SecurityEventKind},
    rate_limit::{KeyedRateLimiter, KeyedRateLimiterConfig, RateLimitError},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsSecurityConfig {
    pub tracker: DnsTrackerConfig,
    pub cache: DnsCacheConfig,
    pub per_client_rate_limit: KeyedRateLimiterConfig,
    pub event_capacity: usize,
}

impl Default for DnsSecurityConfig {
    fn default() -> Self {
        Self {
            tracker: DnsTrackerConfig::default(),
            cache: DnsCacheConfig::default(),
            per_client_rate_limit: KeyedRateLimiterConfig {
                bucket: crate::rate_limit::TokenBucketConfig {
                    capacity: 100,
                    refill_interval_ms: 100,
                },
                max_keys: 4096,
                idle_timeout_ms: 300_000,
            },
            event_capacity: 8192,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsQueryStatus {
    Allowed,
    Blocked,
    RateLimited,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsQueryInspection {
    pub domain: String,
    pub status: DnsQueryStatus,
    pub matched_rule_id: Option<String>,
    /// Present only when the query is permitted and tracked for a response.
    pub request: Option<DnsRequestObservation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsResponseInspection {
    pub response: DnsResponseObservation,
    pub cache_outcome: CacheInsertOutcome,
}

#[derive(Debug, Error)]
pub enum DnsSecurityError {
    #[error("DNS policy configuration failed: {0}")]
    Config(#[from] erebus_dns::DnsConfigError),
    #[error("DNS domain policy failed: {0}")]
    DomainPolicy(#[from] DomainPolicyError),
    #[error("DNS request tracking failed: {0}")]
    Tracker(#[from] DnsTrackerError),
    #[error("DNS cache failed: {0}")]
    Cache(#[from] DnsCacheError),
    #[error("DNS client rate limiter failed: {0}")]
    RateLimit(#[from] RateLimitError),
    #[error("security event journal failed: {0}")]
    Events(#[from] EventJournalError),
    #[error("message is not a supported standard DNS query with exactly one question")]
    InvalidQuery,
    #[error("message is not a DNS response with exactly one question")]
    InvalidResponse,
}

/// Reusable DNS service combining domain policy, client rate limits,
/// transaction correlation, positive caching, and bounded audit events.
///
/// Platform adapters remain responsible for receiving messages and enforcing
/// the returned Allowed/Blocked/RateLimited disposition.
pub struct DnsSecurityService {
    policy: erebus_dns::DomainPolicy,
    tracker: DnsRequestTracker,
    cache: DnsCache,
    client_limits: KeyedRateLimiter<IpAddr>,
    events: EventJournal,
}

impl DnsSecurityService {
    pub fn new(
        document: &DnsPolicyDocument,
        config: DnsSecurityConfig,
    ) -> Result<Self, DnsSecurityError> {
        Ok(Self {
            policy: document.to_policy()?,
            tracker: DnsRequestTracker::new(config.tracker)?,
            cache: DnsCache::new(config.cache)?,
            client_limits: KeyedRateLimiter::new(config.per_client_rate_limit)?,
            events: EventJournal::new(config.event_capacity)?,
        })
    }

    pub fn from_toml(input: &str, config: DnsSecurityConfig) -> Result<Self, DnsSecurityError> {
        let document = DnsPolicyDocument::parse(input)?;
        Self::new(&document, config)
    }

    /// Evaluate a DNS query and track it only when it passes both the
    /// per-client rate limit and domain policy.
    #[allow(clippy::too_many_arguments)]
    pub fn inspect_query(
        &mut self,
        client: IpAddr,
        client_port: u16,
        resolver: IpAddr,
        resolver_port: u16,
        transport: DnsTransport,
        message: &DnsMessage,
        now_ms: u64,
    ) -> Result<DnsQueryInspection, DnsSecurityError> {
        if message.is_response()
            || message.header.opcode() != 0
            || message.single_question().is_none()
        {
            return Err(DnsSecurityError::InvalidQuery);
        }

        let question = message.single_question().expect("validated above");
        let domain = normalize_domain(&question.name)?;
        let rate_allowed = self.client_limits.check(client, now_ms)?;

        if !rate_allowed {
            self.events.record(
                now_ms,
                None,
                SecurityEventKind::DnsRateLimitExceeded {
                    client: client.to_string(),
                },
            )?;
            self.events.record(
                now_ms,
                None,
                SecurityEventKind::DnsQueryDecision {
                    domain: domain.clone(),
                    action: "rate-limited".to_owned(),
                },
            )?;

            return Ok(DnsQueryInspection {
                domain,
                status: DnsQueryStatus::RateLimited,
                matched_rule_id: None,
                request: None,
            });
        }

        let decision = self.policy.evaluate(&domain)?;
        let status = match decision.action {
            DomainAction::Allow => DnsQueryStatus::Allowed,
            DomainAction::Block => DnsQueryStatus::Blocked,
        };
        let action = match status {
            DnsQueryStatus::Allowed => "allow",
            DnsQueryStatus::Blocked => "block",
            DnsQueryStatus::RateLimited => "rate-limited",
        };

        let request = if status == DnsQueryStatus::Allowed {
            Some(self.tracker.observe_query(
                client,
                client_port,
                resolver,
                resolver_port,
                transport,
                message,
                now_ms,
            )?)
        } else {
            None
        };

        self.events.record(
            now_ms,
            None,
            SecurityEventKind::DnsQueryDecision {
                domain: domain.clone(),
                action: action.to_owned(),
            },
        )?;

        Ok(DnsQueryInspection {
            domain,
            status,
            matched_rule_id: decision.matched_rule_id,
            request,
        })
    }

    /// Correlate a DNS response to an allowed request and cache it when it is
    /// a successful positive response. Cache admission never changes the DNS
    /// response decision; the caller still owns delivery.
    #[allow(clippy::too_many_arguments)]
    pub fn inspect_response(
        &mut self,
        resolver: IpAddr,
        resolver_port: u16,
        client: IpAddr,
        client_port: u16,
        transport: DnsTransport,
        message: &DnsMessage,
        now_ms: u64,
    ) -> Result<DnsResponseInspection, DnsSecurityError> {
        if !message.is_response() || message.single_question().is_none() {
            return Err(DnsSecurityError::InvalidResponse);
        }

        let domain = normalize_domain(&message.single_question().expect("validated above").name)?;
        let response = self.tracker.observe_response(
            resolver,
            resolver_port,
            client,
            client_port,
            transport,
            message,
            now_ms,
        )?;

        let cache_outcome = match self.cache.insert(message, now_ms) {
            Ok(outcome) => outcome,
            Err(DnsCacheError::CapacityReached { .. }) => CacheInsertOutcome::IgnoredNotCacheable,
            Err(error) => return Err(error.into()),
        };

        self.events.record(
            now_ms,
            None,
            SecurityEventKind::DnsResponseObserved {
                domain,
                latency_ms: response.latency_ms,
            },
        )?;

        Ok(DnsResponseInspection {
            response,
            cache_outcome,
        })
    }

    pub fn cached_response(
        &mut self,
        domain: &str,
        qtype: u16,
        qclass: u16,
        request_id: u16,
        now_ms: u64,
    ) -> Result<Option<DnsMessage>, DnsSecurityError> {
        Ok(self
            .cache
            .lookup(domain, qtype, qclass, request_id, now_ms)?)
    }

    pub fn expire(&mut self, now_ms: u64) -> Result<DnsExpiryReport, DnsSecurityError> {
        Ok(DnsExpiryReport {
            transactions: self.tracker.expire(now_ms)?,
            cache_entries: self.cache.expire(now_ms)?,
            rate_limit_clients: self.client_limits.prune_idle(now_ms)?,
        })
    }

    pub fn events(&self) -> Vec<crate::events::SecurityEvent> {
        self.events.snapshot()
    }

    pub fn outstanding_requests(&self) -> usize {
        self.tracker.len()
    }

    pub fn cached_entries(&self) -> usize {
        self.cache.len()
    }

    pub fn tracked_clients(&self) -> usize {
        self.client_limits.key_count()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsExpiryReport {
    pub transactions: usize,
    pub cache_entries: usize,
    pub rate_limit_clients: usize,
}

impl erebus_dns::DnsProxyPolicy for DnsSecurityService {
    fn inspect_query(
        &mut self,
        exchange: erebus_dns::DnsExchange,
        message: &DnsMessage,
        now_ms: u64,
    ) -> Result<erebus_dns::DnsProxyDecision, erebus_dns::DnsProxyPolicyError> {
        let inspection = DnsSecurityService::inspect_query(
            self,
            exchange.client.ip(),
            exchange.client.port(),
            exchange.resolver.ip(),
            exchange.resolver.port(),
            exchange.transport,
            message,
            now_ms,
        )
        .map_err(|_| erebus_dns::DnsProxyPolicyError)?;

        Ok(match inspection.status {
            DnsQueryStatus::Allowed => erebus_dns::DnsProxyDecision::Allowed,
            DnsQueryStatus::Blocked => erebus_dns::DnsProxyDecision::Blocked,
            DnsQueryStatus::RateLimited => erebus_dns::DnsProxyDecision::RateLimited,
        })
    }

    fn inspect_response(
        &mut self,
        exchange: erebus_dns::DnsExchange,
        message: &DnsMessage,
        now_ms: u64,
    ) -> Result<(), erebus_dns::DnsProxyPolicyError> {
        DnsSecurityService::inspect_response(
            self,
            exchange.resolver.ip(),
            exchange.resolver.port(),
            exchange.client.ip(),
            exchange.client.port(),
            exchange.transport,
            message,
            now_ms,
        )
        .map(|_| ())
        .map_err(|_| erebus_dns::DnsProxyPolicyError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rate_limit::TokenBucketConfig;
    use erebus_dns::{DnsHeader, DnsQuestion, DnsRecord, DnsRecordData};
    use std::net::{IpAddr, Ipv4Addr};

    const POLICY: &str = r#"
schema_version = 1

[policy]
default = "allow"

[[rules]]
id = "block-tracker"
domain = "tracker.example"
match = "suffix"
action = "block"
"#;

    fn config() -> DnsSecurityConfig {
        DnsSecurityConfig {
            tracker: DnsTrackerConfig {
                max_outstanding: 16,
                request_timeout_ms: 5_000,
            },
            cache: DnsCacheConfig {
                max_entries: 16,
                max_ttl_seconds: 300,
            },
            per_client_rate_limit: KeyedRateLimiterConfig {
                bucket: TokenBucketConfig {
                    capacity: 2,
                    refill_interval_ms: 100,
                },
                max_keys: 4,
                idle_timeout_ms: 1_000,
            },
            event_capacity: 32,
        }
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    fn query(id: u16, name: &str) -> DnsMessage {
        DnsMessage {
            header: DnsHeader {
                id,
                flags: 0x0100,
                question_count: 1,
                answer_count: 0,
                authority_count: 0,
                additional_count: 0,
            },
            questions: vec![DnsQuestion {
                name: name.into(),
                qtype: 1,
                qclass: 1,
            }],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        }
    }

    fn response(id: u16, name: &str) -> DnsMessage {
        DnsMessage {
            header: DnsHeader {
                id,
                flags: 0x8180,
                question_count: 1,
                answer_count: 1,
                authority_count: 0,
                additional_count: 0,
            },
            questions: vec![DnsQuestion {
                name: name.into(),
                qtype: 1,
                qclass: 1,
            }],
            answers: vec![DnsRecord {
                name: name.into(),
                rr_type: 1,
                class: 1,
                ttl: 60,
                data: DnsRecordData::A(Ipv4Addr::new(203, 0, 113, 10)),
            }],
            authorities: vec![],
            additionals: vec![],
        }
    }

    fn service() -> DnsSecurityService {
        DnsSecurityService::from_toml(POLICY, config()).unwrap()
    }

    #[test]
    fn blocks_domain_and_does_not_track_it() {
        let mut service = service();
        let result = service
            .inspect_query(
                ip("192.0.2.10"),
                53000,
                ip("192.0.2.53"),
                53,
                DnsTransport::Udp,
                &query(1, "ads.tracker.example"),
                1,
            )
            .unwrap();

        assert_eq!(result.status, DnsQueryStatus::Blocked);
        assert_eq!(result.matched_rule_id.as_deref(), Some("block-tracker"));
        assert!(result.request.is_none());
        assert_eq!(service.outstanding_requests(), 0);
    }

    #[test]
    fn allows_tracks_correlates_and_caches_response() {
        let mut service = service();
        let client = ip("192.0.2.10");
        let resolver = ip("192.0.2.53");

        let query_result = service
            .inspect_query(
                client,
                53000,
                resolver,
                53,
                DnsTransport::Udp,
                &query(9, "www.example.com"),
                100,
            )
            .unwrap();
        assert_eq!(query_result.status, DnsQueryStatus::Allowed);
        assert!(query_result.request.is_some());
        assert_eq!(service.outstanding_requests(), 1);

        let response_result = service
            .inspect_response(
                resolver,
                53,
                client,
                53000,
                DnsTransport::Udp,
                &response(9, "www.example.com"),
                120,
            )
            .unwrap();
        assert_eq!(response_result.response.latency_ms, 20);
        assert_eq!(response_result.cache_outcome, CacheInsertOutcome::Stored);
        assert_eq!(service.outstanding_requests(), 0);
        assert_eq!(service.cached_entries(), 1);

        let cached = service
            .cached_response("WWW.EXAMPLE.COM.", 1, 1, 10, 130)
            .unwrap()
            .unwrap();
        assert_eq!(cached.header.id, 10);
    }

    #[test]
    fn rate_limits_a_client_without_tracking_extra_queries() {
        let mut service = service();
        let client = ip("192.0.2.20");
        let resolver = ip("192.0.2.53");

        assert_eq!(
            service
                .inspect_query(
                    client,
                    53000,
                    resolver,
                    53,
                    DnsTransport::Udp,
                    &query(1, "one.example"),
                    0,
                )
                .unwrap()
                .status,
            DnsQueryStatus::Allowed
        );
        assert_eq!(
            service
                .inspect_query(
                    client,
                    53001,
                    resolver,
                    53,
                    DnsTransport::Udp,
                    &query(2, "two.example"),
                    0,
                )
                .unwrap()
                .status,
            DnsQueryStatus::Allowed
        );
        assert_eq!(
            service
                .inspect_query(
                    client,
                    53002,
                    resolver,
                    53,
                    DnsTransport::Udp,
                    &query(3, "three.example"),
                    0,
                )
                .unwrap()
                .status,
            DnsQueryStatus::RateLimited
        );
        assert_eq!(service.outstanding_requests(), 2);

        assert!(service
            .events()
            .iter()
            .any(|event| matches!(event.kind, SecurityEventKind::DnsRateLimitExceeded { .. })));
    }

    #[test]
    fn refuses_nonstandard_or_malformed_query_direction() {
        let mut service = service();
        let mut message = query(1, "example.com");
        message.header.flags |= 0x8000;

        assert!(matches!(
            service.inspect_query(
                ip("192.0.2.10"),
                53000,
                ip("192.0.2.53"),
                53,
                DnsTransport::Udp,
                &message,
                1,
            ),
            Err(DnsSecurityError::InvalidQuery)
        ));
    }
}
