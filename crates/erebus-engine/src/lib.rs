//! Portable orchestration layer between adapters and policy evaluation.
//!
//! Policy reload is transactional: parse and validate a replacement completely
//! before atomically publishing the new immutable policy snapshot.

use erebus_config::{ConfigError, PolicyDocument};
use erebus_policy::PolicySet;
use erebus_types::{PolicyDecision, TrafficDescriptor};
use std::sync::{Arc, RwLock};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyStoreError {
    #[error("invalid replacement policy: {0}")]
    Config(#[from] ConfigError),
    #[error("policy snapshot lock was poisoned")]
    LockPoisoned,
    #[error("policy generation counter is exhausted")]
    GenerationExhausted,
}

/// Immutable view of one committed policy generation.
#[derive(Clone)]
pub struct PolicySnapshot {
    generation: u64,
    policy: Arc<PolicySet>,
}

impl PolicySnapshot {
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn policy(&self) -> &PolicySet {
        &self.policy
    }

    pub fn decide(&self, traffic: &TrafficDescriptor) -> PolicyDecision {
        self.policy.evaluate(traffic)
    }
}

/// Thread-safe store for immutable policy generations.
///
/// A replacement policy is parsed and validated before taking the write lock.
/// Readers therefore observe either the complete old policy or the complete
/// new policy, never a partially updated rule list.
pub struct PolicyStore {
    current: RwLock<PolicySnapshot>,
}

impl PolicyStore {
    pub fn new(initial: PolicySet) -> Self {
        Self {
            current: RwLock::new(PolicySnapshot {
                generation: 1,
                policy: Arc::new(initial),
            }),
        }
    }

    pub fn from_toml(input: &str) -> Result<Self, PolicyStoreError> {
        let document = PolicyDocument::parse(input)?;
        let policy = document.to_policy_set()?;
        Ok(Self::new(policy))
    }

    pub fn snapshot(&self) -> Result<PolicySnapshot, PolicyStoreError> {
        self.current
            .read()
            .map(|snapshot| snapshot.clone())
            .map_err(|_| PolicyStoreError::LockPoisoned)
    }

    /// Atomically replace the current policy from a TOML document.
    ///
    /// Parsing and semantic validation occur before the active snapshot is
    /// changed. An invalid document leaves the active generation untouched.
    pub fn reload_toml(&self, input: &str) -> Result<u64, PolicyStoreError> {
        let document = PolicyDocument::parse(input)?;
        let replacement = Arc::new(document.to_policy_set()?);

        let mut current = self
            .current
            .write()
            .map_err(|_| PolicyStoreError::LockPoisoned)?;
        let next_generation = current
            .generation
            .checked_add(1)
            .ok_or(PolicyStoreError::GenerationExhausted)?;

        *current = PolicySnapshot {
            generation: next_generation,
            policy: replacement,
        };

        Ok(next_generation)
    }
}

/// Engine facade deliberately free of operating-system APIs.
pub struct Engine {
    policies: PolicyStore,
}

impl Engine {
    pub fn new(policy: PolicySet) -> Self {
        Self {
            policies: PolicyStore::new(policy),
        }
    }

    pub fn from_toml(input: &str) -> Result<Self, PolicyStoreError> {
        Ok(Self {
            policies: PolicyStore::from_toml(input)?,
        })
    }

    pub fn reload_toml(&self, input: &str) -> Result<u64, PolicyStoreError> {
        self.policies.reload_toml(input)
    }

    pub fn snapshot(&self) -> Result<PolicySnapshot, PolicyStoreError> {
        self.policies.snapshot()
    }

    pub fn decide(
        &self,
        traffic: &TrafficDescriptor,
    ) -> Result<PolicyDecision, PolicyStoreError> {
        Ok(self.policies.snapshot()?.decide(traffic))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use erebus_types::{Direction, TransportProtocol, Verdict};
    use std::net::{IpAddr, Ipv4Addr};

    const DENY_ALL: &str = r#"
schema_version = 1
rules = []

[policy]
default = "deny"
"#;

    const ALLOW_ALL: &str = r#"
schema_version = 1
rules = []

[policy]
default = "allow"
"#;

    fn traffic() -> TrafficDescriptor {
        TrafficDescriptor {
            direction: Direction::Outbound,
            protocol: TransportProtocol::Tcp,
            source: IpAddr::V4(Ipv4Addr::LOCALHOST),
            destination: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            source_port: Some(50_000),
            destination_port: Some(443),
            interface: Some("test0".into()),
            flow_id: None,
        }
    }

    #[test]
    fn reload_publishes_new_generation_and_policy() {
        let engine = Engine::from_toml(DENY_ALL).unwrap();
        let original = engine.snapshot().unwrap();
        assert_eq!(original.generation(), 1);
        assert_eq!(original.decide(&traffic()).verdict, Verdict::Deny);

        let generation = engine.reload_toml(ALLOW_ALL).unwrap();
        assert_eq!(generation, 2);

        let replacement = engine.snapshot().unwrap();
        assert_eq!(replacement.generation(), 2);
        assert_eq!(replacement.decide(&traffic()).verdict, Verdict::Allow);

        // Snapshots are immutable and remain usable after a replacement.
        assert_eq!(original.generation(), 1);
        assert_eq!(original.decide(&traffic()).verdict, Verdict::Deny);
    }

    #[test]
    fn invalid_reload_does_not_change_active_policy() {
        let engine = Engine::from_toml(DENY_ALL).unwrap();
        let invalid = DENY_ALL.replace("default = \"deny\"", "default = \"sometimes\"");

        assert!(engine.reload_toml(&invalid).is_err());

        let snapshot = engine.snapshot().unwrap();
        assert_eq!(snapshot.generation(), 1);
        assert_eq!(snapshot.decide(&traffic()).verdict, Verdict::Deny);
    }

    #[test]
    fn engine_decide_uses_the_current_snapshot() {
        let engine = Engine::from_toml(DENY_ALL).unwrap();
        assert_eq!(engine.decide(&traffic()).unwrap().verdict, Verdict::Deny);

        engine.reload_toml(ALLOW_ALL).unwrap();
        assert_eq!(engine.decide(&traffic()).unwrap().verdict, Verdict::Allow);
    }
}
