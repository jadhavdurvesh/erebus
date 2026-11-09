//! Portable orchestration layer between adapters and policy evaluation.

use erebus_policy::PolicySet;
use erebus_types::{PolicyDecision, TrafficDescriptor};

/// A small facade deliberately free of operating-system APIs.
pub struct Engine {
    policy: PolicySet,
}

impl Engine {
    pub fn new(policy: PolicySet) -> Self {
        Self { policy }
    }

    pub fn decide(&self, traffic: &TrafficDescriptor) -> PolicyDecision {
        self.policy.evaluate(traffic)
    }
}
