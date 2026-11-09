//! Bounded token-bucket rate limiting primitives.
//!
//! These are policy-side primitives only. They do not install OS rate limits
//! and must be called by an adapter or service that owns the relevant traffic.

use std::collections::HashMap;
use std::{
    hash::Hash,
    net::IpAddr,
};
use thiserror::Error;

pub const MAX_RATE_LIMIT_KEY_BYTES: usize = 128;

/// Implement this for a bounded identifier used to distinguish rate-limit buckets.
pub trait RateLimitKey {
    fn encoded_len(&self) -> usize;
}

impl RateLimitKey for IpAddr {
    fn encoded_len(&self) -> usize {
        match self {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 16,
        }
    }
}

impl RateLimitKey for String {
    fn encoded_len(&self) -> usize {
        self.len()
    }
}

impl RateLimitKey for &str {
    fn encoded_len(&self) -> usize {
        self.len()
    }
}

impl RateLimitKey for Vec<u8> {
    fn encoded_len(&self) -> usize {
        self.len()
    }
}

impl<const N: usize> RateLimitKey for [u8; N] {
    fn encoded_len(&self) -> usize {
        N
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenBucketConfig {
    /// Maximum burst size, measured in tokens.
    pub capacity: u32,
    /// One token is replenished for each complete interval.
    pub refill_interval_ms: u64,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RateLimitError {
    #[error("token bucket capacity must be greater than zero")]
    ZeroCapacity,
    #[error("token bucket refill interval must be greater than zero")]
    ZeroRefillInterval,
    #[error("token cost must be greater than zero")]
    ZeroCost,
    #[error("token cost {cost} exceeds bucket capacity {capacity}")]
    CostExceedsCapacity { cost: u32, capacity: u32 },
    #[error("rate limiter key capacity must be greater than zero")]
    ZeroKeyCapacity,
    #[error("idle timeout must be greater than zero")]
    ZeroIdleTimeout,
    #[error("rate limiter key table is full ({capacity} keys); active keys are not evicted")]
    KeyCapacityReached { capacity: usize },
    #[error("rate limiter key is too long: {actual_bytes} bytes; maximum is {max_bytes}")]
    KeyTooLong {
        actual_bytes: usize,
        max_bytes: usize,
    },
    #[error("timestamp moved backwards: previous {previous_ms} ms, received {received_ms} ms")]
    ClockWentBackwards { previous_ms: u64, received_ms: u64 },
}

#[derive(Clone, Debug)]
pub struct TokenBucket {
    config: TokenBucketConfig,
    available: u32,
    last_refill_ms: u64,
    fractional_ms: u64,
}

impl TokenBucket {
    pub fn new(config: TokenBucketConfig, now_ms: u64) -> Result<Self, RateLimitError> {
        validate_bucket_config(config)?;
        Ok(Self {
            config,
            available: config.capacity,
            last_refill_ms: now_ms,
            fractional_ms: 0,
        })
    }

    pub fn available(&self) -> u32 {
        self.available
    }

    pub fn capacity(&self) -> u32 {
        self.config.capacity
    }

    /// Attempt to spend tokens. Returns false when insufficient tokens remain.
    /// Time must be monotonic milliseconds.
    pub fn try_acquire(&mut self, now_ms: u64, cost: u32) -> Result<bool, RateLimitError> {
        validate_cost(cost, self.config.capacity)?;
        self.refill(now_ms)?;

        if self.available < cost {
            return Ok(false);
        }

        self.available -= cost;
        Ok(true)
    }

    fn refill(&mut self, now_ms: u64) -> Result<(), RateLimitError> {
        if now_ms < self.last_refill_ms {
            return Err(RateLimitError::ClockWentBackwards {
                previous_ms: self.last_refill_ms,
                received_ms: now_ms,
            });
        }

        let elapsed = now_ms - self.last_refill_ms;
        self.last_refill_ms = now_ms;

        let total_ms = u128::from(self.fractional_ms) + u128::from(elapsed);
        let interval = u128::from(self.config.refill_interval_ms);
        let replenished = total_ms / interval;
        self.fractional_ms = (total_ms % interval) as u64;

        if replenished > 0 {
            let total_tokens = u128::from(self.available) + replenished;
            self.available = total_tokens.min(u128::from(self.config.capacity)) as u32;
        }

        // A full bucket cannot accumulate credit beyond its capacity.
        if self.available == self.config.capacity {
            self.fractional_ms = 0;
        }

        Ok(())
    }
}

fn validate_bucket_config(config: TokenBucketConfig) -> Result<(), RateLimitError> {
    if config.capacity == 0 {
        return Err(RateLimitError::ZeroCapacity);
    }
    if config.refill_interval_ms == 0 {
        return Err(RateLimitError::ZeroRefillInterval);
    }
    Ok(())
}

fn validate_cost(cost: u32, capacity: u32) -> Result<(), RateLimitError> {
    if cost == 0 {
        return Err(RateLimitError::ZeroCost);
    }
    if cost > capacity {
        return Err(RateLimitError::CostExceedsCapacity { cost, capacity });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyedRateLimiterConfig {
    pub bucket: TokenBucketConfig,
    pub max_keys: usize,
    pub idle_timeout_ms: u64,
}

struct KeyedBucket {
    bucket: TokenBucket,
    last_seen_ms: u64,
}

/// Bounded per-key token buckets, for example one key per remote IP.
///
/// Keys are never evicted while active. Expired idle keys are pruned on access
/// and can also be removed explicitly with prune_idle.
pub struct KeyedRateLimiter<K> {
    config: KeyedRateLimiterConfig,
    buckets: HashMap<K, KeyedBucket>,
    last_observed_ms: Option<u64>,
}

impl<K> KeyedRateLimiter<K>
where
    K: Eq + Hash + RateLimitKey,
{
    pub fn new(config: KeyedRateLimiterConfig) -> Result<Self, RateLimitError> {
        validate_bucket_config(config.bucket)?;
        if config.max_keys == 0 {
            return Err(RateLimitError::ZeroKeyCapacity);
        }
        if config.idle_timeout_ms == 0 {
            return Err(RateLimitError::ZeroIdleTimeout);
        }

        Ok(Self {
            config,
            buckets: HashMap::with_capacity(config.max_keys.min(4096)),
            last_observed_ms: None,
        })
    }

    pub fn key_count(&self) -> usize {
        self.buckets.len()
    }

    pub fn max_keys(&self) -> usize {
        self.config.max_keys
    }

    pub fn check(&mut self, key: K, now_ms: u64) -> Result<bool, RateLimitError> {
        self.check_cost(key, now_ms, 1)
    }

    pub fn check_cost(&mut self, key: K, now_ms: u64, cost: u32) -> Result<bool, RateLimitError> {
        validate_cost(cost, self.config.bucket.capacity)?;
        let key_bytes = key.encoded_len();
        if key_bytes > MAX_RATE_LIMIT_KEY_BYTES {
            return Err(RateLimitError::KeyTooLong {
                actual_bytes: key_bytes,
                max_bytes: MAX_RATE_LIMIT_KEY_BYTES,
            });
        }
        self.check_time(now_ms)?;
        self.last_observed_ms = Some(now_ms);
        self.prune_idle_internal(now_ms);

        if !self.buckets.contains_key(&key) && self.buckets.len() >= self.config.max_keys {
            return Err(RateLimitError::KeyCapacityReached {
                capacity: self.config.max_keys,
            });
        }

        let entry = self.buckets.entry(key).or_insert_with(|| KeyedBucket {
            bucket: TokenBucket::new(self.config.bucket, now_ms)
                .expect("bucket configuration was validated at construction"),
            last_seen_ms: now_ms,
        });
        entry.last_seen_ms = now_ms;
        entry.bucket.try_acquire(now_ms, cost)
    }

    pub fn prune_idle(&mut self, now_ms: u64) -> Result<usize, RateLimitError> {
        self.check_time(now_ms)?;
        self.last_observed_ms = Some(now_ms);
        Ok(self.prune_idle_internal(now_ms))
    }

    fn prune_idle_internal(&mut self, now_ms: u64) -> usize {
        let before = self.buckets.len();
        self.buckets.retain(|_, entry| {
            now_ms.saturating_sub(entry.last_seen_ms) < self.config.idle_timeout_ms
        });
        before - self.buckets.len()
    }

    fn check_time(&self, now_ms: u64) -> Result<(), RateLimitError> {
        if let Some(previous_ms) = self.last_observed_ms {
            if now_ms < previous_ms {
                return Err(RateLimitError::ClockWentBackwards {
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

    fn bucket_config() -> TokenBucketConfig {
        TokenBucketConfig {
            capacity: 3,
            refill_interval_ms: 100,
        }
    }

    #[test]
    fn token_bucket_allows_burst_then_refills_at_exact_intervals() {
        let mut bucket = TokenBucket::new(bucket_config(), 0).unwrap();

        assert!(bucket.try_acquire(0, 1).unwrap());
        assert!(bucket.try_acquire(0, 1).unwrap());
        assert!(bucket.try_acquire(0, 1).unwrap());
        assert!(!bucket.try_acquire(99, 1).unwrap());
        assert!(bucket.try_acquire(100, 1).unwrap());
        assert_eq!(bucket.available(), 0);
    }

    #[test]
    fn bucket_does_not_bank_tokens_above_capacity() {
        let mut bucket = TokenBucket::new(bucket_config(), 0).unwrap();
        assert!(bucket.try_acquire(0, 3).unwrap());
        assert!(bucket.try_acquire(10_000, 3).unwrap());
        assert_eq!(bucket.available(), 0);
        assert!(!bucket.try_acquire(10_099, 1).unwrap());
        assert!(bucket.try_acquire(10_100, 1).unwrap());
    }

    #[test]
    fn bucket_rejects_invalid_costs_and_clock_regression() {
        let mut bucket = TokenBucket::new(bucket_config(), 10).unwrap();

        assert_eq!(bucket.try_acquire(10, 0), Err(RateLimitError::ZeroCost));
        assert_eq!(
            bucket.try_acquire(10, 4),
            Err(RateLimitError::CostExceedsCapacity {
                cost: 4,
                capacity: 3
            })
        );
        assert_eq!(
            bucket.try_acquire(9, 1),
            Err(RateLimitError::ClockWentBackwards {
                previous_ms: 10,
                received_ms: 9
            })
        );
    }

    #[test]
    fn keyed_buckets_are_isolated_by_key() {
        let mut limiter = KeyedRateLimiter::new(KeyedRateLimiterConfig {
            bucket: bucket_config(),
            max_keys: 4,
            idle_timeout_ms: 1_000,
        })
        .unwrap();

        assert!(limiter.check("192.0.2.1", 1).unwrap());
        assert!(limiter.check("192.0.2.1", 1).unwrap());
        assert!(limiter.check("192.0.2.1", 1).unwrap());
        assert!(!limiter.check("192.0.2.1", 1).unwrap());
        assert!(limiter.check("192.0.2.2", 1).unwrap());
        assert_eq!(limiter.key_count(), 2);
    }

    #[test]
    fn keyed_limiter_is_bounded_and_prunes_idle_keys() {
        let mut limiter = KeyedRateLimiter::new(KeyedRateLimiterConfig {
            bucket: bucket_config(),
            max_keys: 1,
            idle_timeout_ms: 100,
        })
        .unwrap();

        assert!(limiter.check("client-a", 0).unwrap());
        assert_eq!(
            limiter.check("client-b", 10),
            Err(RateLimitError::KeyCapacityReached { capacity: 1 })
        );
        assert_eq!(limiter.prune_idle(100).unwrap(), 1);
        assert!(limiter.check("client-b", 101).unwrap());
    }

    #[test]
    fn keyed_limiter_rejects_oversized_keys() {
        let mut limiter = KeyedRateLimiter::new(KeyedRateLimiterConfig {
            bucket: bucket_config(),
            max_keys: 2,
            idle_timeout_ms: 100,
        })
        .unwrap();
        let oversized = "k".repeat(MAX_RATE_LIMIT_KEY_BYTES + 1);

        assert_eq!(
            limiter.check(oversized, 1),
            Err(RateLimitError::KeyTooLong {
                actual_bytes: MAX_RATE_LIMIT_KEY_BYTES + 1,
                max_bytes: MAX_RATE_LIMIT_KEY_BYTES
            })
        );
        assert_eq!(limiter.key_count(), 0);
    }

    #[test]
    fn keyed_limiter_rejects_clock_regression() {
        let mut limiter = KeyedRateLimiter::new(KeyedRateLimiterConfig {
            bucket: bucket_config(),
            max_keys: 2,
            idle_timeout_ms: 100,
        })
        .unwrap();

        limiter.check("client-a", 10).unwrap();
        assert_eq!(
            limiter.check("client-a", 9),
            Err(RateLimitError::ClockWentBackwards {
                previous_ms: 10,
                received_ms: 9
            })
        );
    }

    #[test]
    fn zero_configuration_values_are_rejected() {
        assert_eq!(
            TokenBucket::new(
                TokenBucketConfig {
                    capacity: 0,
                    refill_interval_ms: 100
                },
                0
            )
            .unwrap_err(),
            RateLimitError::ZeroCapacity
        );
        assert_eq!(
            TokenBucket::new(
                TokenBucketConfig {
                    capacity: 1,
                    refill_interval_ms: 0
                },
                0
            )
            .unwrap_err(),
            RateLimitError::ZeroRefillInterval
        );
    }
}
