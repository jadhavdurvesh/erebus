//! Bounded cache for positive DNS responses.

use crate::{
    policy::{normalize_domain, DomainPolicyError},
    wire::{DnsMessage, DnsRecord},
};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct CacheKey {
    name_hash: u64,
    qtype: u16,
    qclass: u16,
}

#[derive(Clone, Debug)]
struct CacheEntry {
    name: String,
    qtype: u16,
    qclass: u16,
    response: DnsMessage,
    expires_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsCacheConfig {
    pub max_entries: usize,
    pub max_ttl_seconds: u32,
}

impl Default for DnsCacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 4096,
            max_ttl_seconds: 86_400,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheInsertOutcome {
    Stored,
    IgnoredNotCacheable,
}

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum DnsCacheError {
    #[error("DNS cache capacity must be greater than zero")]
    ZeroCapacity,
    #[error("DNS cache maximum TTL must be greater than zero")]
    ZeroMaxTtl,
    #[error("DNS cache is full ({capacity} entries); active entries are not evicted")]
    CapacityReached { capacity: usize },
    #[error("DNS cache timestamp moved backwards: previous {previous_ms} ms, received {received_ms} ms")]
    ClockWentBackwards {
        previous_ms: u64,
        received_ms: u64,
    },
    #[error("invalid DNS cache domain: {0}")]
    InvalidDomain(#[from] DomainPolicyError),
}

/// A bounded positive-response cache.
///
/// It intentionally does not cache NXDOMAIN, empty answers, truncated responses,
/// or non-NOERROR response codes. Entries expire at the earliest answer TTL.
pub struct DnsCache {
    config: DnsCacheConfig,
    entries: HashMap<CacheKey, CacheEntry>,
    last_observed_ms: Option<u64>,
}

impl DnsCache {
    pub fn new(config: DnsCacheConfig) -> Result<Self, DnsCacheError> {
        if config.max_entries == 0 {
            return Err(DnsCacheError::ZeroCapacity);
        }
        if config.max_ttl_seconds == 0 {
            return Err(DnsCacheError::ZeroMaxTtl);
        }

        Ok(Self {
            config,
            entries: HashMap::with_capacity(config.max_entries.min(4096)),
            last_observed_ms: None,
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.config.max_entries
    }

    pub fn insert(
        &mut self,
        response: &DnsMessage,
        now_ms: u64,
    ) -> Result<CacheInsertOutcome, DnsCacheError> {
        self.check_time(now_ms)?;
        self.last_observed_ms = Some(now_ms);
        self.expire_internal(now_ms);

        let Some(question) = response.single_question() else {
            return Ok(CacheInsertOutcome::IgnoredNotCacheable);
        };

        if !response.is_response()
            || response.header.truncated()
            || response.header.response_code() != 0
            || response.answers.is_empty()
        {
            return Ok(CacheInsertOutcome::IgnoredNotCacheable);
        }

        let name = normalize_domain(&question.name)?;
        let ttl = response
            .answers
            .iter()
            .filter(|record| !record.is_opt())
            .map(|record| record.ttl)
            .min()
            .unwrap_or(0)
            .min(self.config.max_ttl_seconds);

        if ttl == 0 {
            return Ok(CacheInsertOutcome::IgnoredNotCacheable);
        }

        let key = cache_key(&name, question.qtype, question.qclass);
        if !self.entries.contains_key(&key) && self.entries.len() >= self.config.max_entries {
            return Err(DnsCacheError::CapacityReached {
                capacity: self.config.max_entries,
            });
        }

        let expires_at_ms = now_ms.saturating_add(u64::from(ttl).saturating_mul(1000));
        self.entries.insert(
            key,
            CacheEntry {
                name,
                qtype: question.qtype,
                qclass: question.qclass,
                response: response.clone(),
                expires_at_ms,
            },
        );

        Ok(CacheInsertOutcome::Stored)
    }

    /// Return a cloned response with the request's ID and reduced remaining TTLs.
    pub fn lookup(
        &mut self,
        name: &str,
        qtype: u16,
        qclass: u16,
        request_id: u16,
        now_ms: u64,
    ) -> Result<Option<DnsMessage>, DnsCacheError> {
        self.check_time(now_ms)?;
        self.last_observed_ms = Some(now_ms);
        self.expire_internal(now_ms);

        let normalized = normalize_domain(name)?;
        let key = cache_key(&normalized, qtype, qclass);
        let Some(entry) = self.entries.get(&key) else {
            return Ok(None);
        };

        if entry.name != normalized || entry.qtype != qtype || entry.qclass != qclass {
            return Ok(None);
        }

        let remaining_ms = entry.expires_at_ms.saturating_sub(now_ms);
        let remaining_ttl = remaining_ms.saturating_add(999) / 1000;
        let mut response = entry.response.clone();
        response.header.id = request_id;
        update_ttls(&mut response.answers, remaining_ttl);
        update_ttls(&mut response.authorities, remaining_ttl);
        update_ttls(&mut response.additionals, remaining_ttl);
        Ok(Some(response))
    }

    pub fn expire(&mut self, now_ms: u64) -> Result<usize, DnsCacheError> {
        self.check_time(now_ms)?;
        self.last_observed_ms = Some(now_ms);
        Ok(self.expire_internal(now_ms))
    }

    fn expire_internal(&mut self, now_ms: u64) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| entry.expires_at_ms > now_ms);
        before - self.entries.len()
    }

    fn check_time(&self, now_ms: u64) -> Result<(), DnsCacheError> {
        if let Some(previous_ms) = self.last_observed_ms {
            if now_ms < previous_ms {
                return Err(DnsCacheError::ClockWentBackwards {
                    previous_ms,
                    received_ms: now_ms,
                });
            }
        }
        Ok(())
    }
}

fn cache_key(name: &str, qtype: u16, qclass: u16) -> CacheKey {
    // FNV-1a is used only as a compact internal lookup hash; the full normalized
    // name is also compared in the entry before a response is returned.
    let mut hash = 0xcbf29ce484222325u64;
    for byte in name.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    CacheKey {
        name_hash: hash,
        qtype,
        qclass,
    }
}

fn update_ttls(records: &mut [DnsRecord], remaining_ttl: u64) {
    for record in records {
        if !record.is_opt() {
            record.ttl = u64::from(record.ttl)
                .min(remaining_ttl)
                .min(u64::from(u32::MAX)) as u32;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{DnsHeader, DnsQuestion, DnsRecord, DnsRecordData};
    use std::net::Ipv4Addr;

    fn response(ttl: u32) -> DnsMessage {
        DnsMessage {
            header: DnsHeader {
                id: 0x1111,
                flags: 0x8180,
                question_count: 1,
                answer_count: 1,
                authority_count: 0,
                additional_count: 0,
            },
            questions: vec![DnsQuestion {
                name: "example.com".into(),
                qtype: 1,
                qclass: 1,
            }],
            answers: vec![DnsRecord {
                name: "example.com".into(),
                rr_type: 1,
                class: 1,
                ttl,
                data: DnsRecordData::A(Ipv4Addr::new(203, 0, 113, 8)),
            }],
            authorities: vec![],
            additionals: vec![],
        }
    }

    #[test]
    fn stores_and_retrieves_positive_response_with_new_id() {
        let mut cache = DnsCache::new(DnsCacheConfig::default()).unwrap();
        assert_eq!(cache.insert(&response(120), 100).unwrap(), CacheInsertOutcome::Stored);

        let result = cache.lookup("EXAMPLE.COM.", 1, 1, 0x2222, 1_100).unwrap().unwrap();
        assert_eq!(result.header.id, 0x2222);
        assert_eq!(result.answers[0].ttl, 119);
        assert_eq!(result.answers[0].data, response(120).answers[0].data);
    }

    #[test]
    fn expires_at_ttl_boundary_and_rejects_clock_regression() {
        let mut cache = DnsCache::new(DnsCacheConfig::default()).unwrap();
        cache.insert(&response(2), 100).unwrap();

        assert!(cache.lookup("example.com", 1, 1, 1, 2_099).unwrap().is_some());
        assert!(cache.lookup("example.com", 1, 1, 1, 2_100).unwrap().is_none());
        assert_eq!(
            cache.lookup("example.com", 1, 1, 1, 2_099),
            Err(DnsCacheError::ClockWentBackwards {
                previous_ms: 2_100,
                received_ms: 2_099
            })
        );
    }

    #[test]
    fn ignores_nxdomain_truncated_empty_and_zero_ttl_responses() {
        let mut cache = DnsCache::new(DnsCacheConfig::default()).unwrap();
        let mut message = response(10);
        message.header.flags = 0x8183;
        assert_eq!(
            cache.insert(&message, 1).unwrap(),
            CacheInsertOutcome::IgnoredNotCacheable
        );

        let mut message = response(10);
        message.header.flags |= 0x0200;
        assert_eq!(
            cache.insert(&message, 2).unwrap(),
            CacheInsertOutcome::IgnoredNotCacheable
        );

        let mut message = response(0);
        assert_eq!(
            cache.insert(&message, 3).unwrap(),
            CacheInsertOutcome::IgnoredNotCacheable
        );
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn respects_cache_capacity_without_evicting_active_entries() {
        let mut cache = DnsCache::new(DnsCacheConfig {
            max_entries: 1,
            max_ttl_seconds: 100,
        })
        .unwrap();

        cache.insert(&response(50), 1).unwrap();
        let mut other = response(50);
        other.questions[0].name = "other.example".into();
        other.answers[0].name = "other.example".into();

        assert_eq!(
            cache.insert(&other, 2),
            Err(DnsCacheError::CapacityReached { capacity: 1 })
        );
        assert_eq!(cache.len(), 1);
    }
}
