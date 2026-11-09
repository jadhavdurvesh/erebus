//! Bounded DNS request/response correlation table.

use crate::{
    policy::{normalize_domain, DomainPolicyError},
    wire::DnsMessage,
};
use std::{collections::HashMap, net::IpAddr};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DnsTransport {
    Udp,
    Tcp,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct TransactionKey {
    client: IpAddr,
    client_port: u16,
    resolver: IpAddr,
    resolver_port: u16,
    transport: DnsTransport,
    transaction_id: u16,
    name: String,
    qtype: u16,
    qclass: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsRequestObservation {
    pub transaction_id: u16,
    pub started_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsResponseObservation {
    pub transaction_id: u16,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub latency_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsTrackerConfig {
    pub max_outstanding: usize,
    pub request_timeout_ms: u64,
}

impl Default for DnsTrackerConfig {
    fn default() -> Self {
        Self {
            max_outstanding: 8192,
            request_timeout_ms: 10_000,
        }
    }
}

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum DnsTrackerError {
    #[error("DNS request tracker capacity must be greater than zero")]
    ZeroCapacity,
    #[error("DNS request timeout must be greater than zero")]
    ZeroTimeout,
    #[error("DNS message must contain exactly one question")]
    InvalidQuestionCount,
    #[error("expected a DNS query message")]
    ExpectedQuery,
    #[error("expected a DNS response message")]
    ExpectedResponse,
    #[error("DNS request is already outstanding")]
    DuplicateRequest,
    #[error("DNS request tracker is full ({capacity} outstanding requests)")]
    CapacityReached { capacity: usize },
    #[error("DNS response does not match an outstanding request")]
    UnknownResponse,
    #[error("DNS tracker timestamp moved backwards: previous {previous_ms} ms, received {received_ms} ms")]
    ClockWentBackwards { previous_ms: u64, received_ms: u64 },
    #[error("invalid DNS domain: {0}")]
    InvalidDomain(#[from] DomainPolicyError),
}

/// Tracks DNS transactions using both endpoints, transport, transaction ID,
/// and question tuple to avoid matching unrelated responses.
pub struct DnsRequestTracker {
    config: DnsTrackerConfig,
    outstanding: HashMap<TransactionKey, DnsRequestObservation>,
    last_observed_ms: Option<u64>,
}

impl DnsRequestTracker {
    pub fn new(config: DnsTrackerConfig) -> Result<Self, DnsTrackerError> {
        if config.max_outstanding == 0 {
            return Err(DnsTrackerError::ZeroCapacity);
        }
        if config.request_timeout_ms == 0 {
            return Err(DnsTrackerError::ZeroTimeout);
        }

        Ok(Self {
            config,
            outstanding: HashMap::with_capacity(config.max_outstanding.min(4096)),
            last_observed_ms: None,
        })
    }

    pub fn len(&self) -> usize {
        self.outstanding.len()
    }

    pub fn is_empty(&self) -> bool {
        self.outstanding.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.config.max_outstanding
    }

    #[allow(clippy::too_many_arguments)]
    pub fn observe_query(
        &mut self,
        client: IpAddr,
        client_port: u16,
        resolver: IpAddr,
        resolver_port: u16,
        transport: DnsTransport,
        message: &DnsMessage,
        now_ms: u64,
    ) -> Result<DnsRequestObservation, DnsTrackerError> {
        self.check_time(now_ms)?;
        if message.is_response() {
            return Err(DnsTrackerError::ExpectedQuery);
        }
        let question = message
            .single_question()
            .ok_or(DnsTrackerError::InvalidQuestionCount)?;
        let key = TransactionKey {
            client,
            client_port,
            resolver,
            resolver_port,
            transport,
            transaction_id: message.header.id,
            name: normalize_domain(&question.name)?,
            qtype: question.qtype,
            qclass: question.qclass,
        };

        self.last_observed_ms = Some(now_ms);
        self.expire_internal(now_ms);

        if self.outstanding.contains_key(&key) {
            return Err(DnsTrackerError::DuplicateRequest);
        }
        if self.outstanding.len() >= self.config.max_outstanding {
            return Err(DnsTrackerError::CapacityReached {
                capacity: self.config.max_outstanding,
            });
        }

        let observation = DnsRequestObservation {
            transaction_id: message.header.id,
            started_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(self.config.request_timeout_ms),
        };
        self.outstanding.insert(key, observation);
        Ok(observation)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn observe_response(
        &mut self,
        resolver: IpAddr,
        resolver_port: u16,
        client: IpAddr,
        client_port: u16,
        transport: DnsTransport,
        message: &DnsMessage,
        now_ms: u64,
    ) -> Result<DnsResponseObservation, DnsTrackerError> {
        self.check_time(now_ms)?;
        if !message.is_response() {
            return Err(DnsTrackerError::ExpectedResponse);
        }
        let question = message
            .single_question()
            .ok_or(DnsTrackerError::InvalidQuestionCount)?;
        let key = TransactionKey {
            client,
            client_port,
            resolver,
            resolver_port,
            transport,
            transaction_id: message.header.id,
            name: normalize_domain(&question.name)?,
            qtype: question.qtype,
            qclass: question.qclass,
        };

        self.last_observed_ms = Some(now_ms);
        self.expire_internal(now_ms);

        let request = self
            .outstanding
            .remove(&key)
            .ok_or(DnsTrackerError::UnknownResponse)?;
        Ok(DnsResponseObservation {
            transaction_id: message.header.id,
            started_at_ms: request.started_at_ms,
            completed_at_ms: now_ms,
            latency_ms: now_ms.saturating_sub(request.started_at_ms),
        })
    }

    pub fn expire(&mut self, now_ms: u64) -> Result<usize, DnsTrackerError> {
        self.check_time(now_ms)?;
        self.last_observed_ms = Some(now_ms);
        Ok(self.expire_internal(now_ms))
    }

    fn expire_internal(&mut self, now_ms: u64) -> usize {
        let before = self.outstanding.len();
        self.outstanding
            .retain(|_, request| request.expires_at_ms > now_ms);
        before - self.outstanding.len()
    }

    fn check_time(&self, now_ms: u64) -> Result<(), DnsTrackerError> {
        if let Some(previous_ms) = self.last_observed_ms {
            if now_ms < previous_ms {
                return Err(DnsTrackerError::ClockWentBackwards {
                    previous_ms,
                    received_ms: now_ms,
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{DnsHeader, DnsMessage, DnsQuestion};
    use std::net::{IpAddr, Ipv4Addr};

    fn message(id: u16, response: bool, name: &str) -> DnsMessage {
        DnsMessage {
            header: DnsHeader {
                id,
                flags: if response { 0x8180 } else { 0x0100 },
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

    fn endpoints() -> (IpAddr, IpAddr) {
        (
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
        )
    }

    fn new_tracker() -> DnsRequestTracker {
        DnsRequestTracker::new(DnsTrackerConfig {
            max_outstanding: 4,
            request_timeout_ms: 100,
        })
        .unwrap()
    }

    #[test]
    fn correlates_response_using_reverse_endpoints_and_question() {
        let (client, resolver) = endpoints();
        let mut tracker = new_tracker();
        let query = message(0x1234, false, "Example.COM.");
        let response = message(0x1234, true, "example.com");

        tracker
            .observe_query(client, 53000, resolver, 53, DnsTransport::Udp, &query, 10)
            .unwrap();
        let matched = tracker
            .observe_response(
                resolver,
                53,
                client,
                53000,
                DnsTransport::Udp,
                &response,
                35,
            )
            .unwrap();

        assert_eq!(matched.transaction_id, 0x1234);
        assert_eq!(matched.latency_ms, 25);
        assert!(tracker.is_empty());
    }

    #[test]
    fn does_not_match_wrong_endpoint_transport_or_question() {
        let (client, resolver) = endpoints();
        let mut tracker = new_tracker();
        tracker
            .observe_query(
                client,
                53000,
                resolver,
                53,
                DnsTransport::Udp,
                &message(7, false, "example.com"),
                1,
            )
            .unwrap();

        assert_eq!(
            tracker.observe_response(
                resolver,
                53,
                client,
                53001,
                DnsTransport::Udp,
                &message(7, true, "example.com"),
                2,
            ),
            Err(DnsTrackerError::UnknownResponse)
        );
        assert_eq!(
            tracker.observe_response(
                resolver,
                53,
                client,
                53000,
                DnsTransport::Tcp,
                &message(7, true, "example.com"),
                2,
            ),
            Err(DnsTrackerError::UnknownResponse)
        );
        assert_eq!(
            tracker.observe_response(
                resolver,
                53,
                client,
                53000,
                DnsTransport::Udp,
                &message(7, true, "other.example"),
                2,
            ),
            Err(DnsTrackerError::UnknownResponse)
        );
    }

    #[test]
    fn expires_requests_and_enforces_capacity() {
        let (client, resolver) = endpoints();
        let mut tracker = DnsRequestTracker::new(DnsTrackerConfig {
            max_outstanding: 2,
            request_timeout_ms: 100,
        })
        .unwrap();
        tracker
            .observe_query(
                client,
                53000,
                resolver,
                53,
                DnsTransport::Udp,
                &message(1, false, "one.example"),
                0,
            )
            .unwrap();
        tracker
            .observe_query(
                client,
                53001,
                resolver,
                53,
                DnsTransport::Udp,
                &message(2, false, "two.example"),
                0,
            )
            .unwrap();

        assert_eq!(
            tracker.observe_query(
                client,
                53002,
                resolver,
                53,
                DnsTransport::Udp,
                &message(3, false, "three.example"),
                1,
            ),
            Err(DnsTrackerError::CapacityReached { capacity: 2 })
        );
        assert_eq!(tracker.expire(100).unwrap(), 2);
        assert!(tracker.is_empty());
    }

    #[test]
    fn rejects_duplicates_wrong_message_kind_and_clock_regression() {
        let (client, resolver) = endpoints();
        let mut tracker = new_tracker();
        let query = message(5, false, "example.com");
        tracker
            .observe_query(client, 53000, resolver, 53, DnsTransport::Udp, &query, 10)
            .unwrap();

        assert_eq!(
            tracker.observe_query(client, 53000, resolver, 53, DnsTransport::Udp, &query, 11,),
            Err(DnsTrackerError::DuplicateRequest)
        );
        assert_eq!(
            tracker.observe_query(
                client,
                53001,
                resolver,
                53,
                DnsTransport::Udp,
                &message(5, true, "example.com"),
                12,
            ),
            Err(DnsTrackerError::ExpectedQuery)
        );
        assert_eq!(
            tracker.observe_query(client, 53000, resolver, 53, DnsTransport::Udp, &query, 9,),
            Err(DnsTrackerError::ClockWentBackwards {
                previous_ms: 11,
                received_ms: 9
            })
        );
    }
}
