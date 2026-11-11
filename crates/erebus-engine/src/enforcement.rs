//! Portable enforcement orchestration.
//!
//! This runtime owns policy evaluation, decision auditing, lifecycle, and
//! adapter-failure handling. Platform adapters own packet acquisition and the
//! operating-system-specific act of applying a verdict.

use crate::{Engine, EventJournal, EventJournalError, SecurityEvent, SecurityEventKind};
use erebus_adapter_api::{AdapterState, PlatformAdapter};
use erebus_types::{DecisionReason, FlowId, PolicyDecision, TrafficDescriptor, Verdict};
use std::error::Error;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EnforcementMetrics {
    pub decisions: u64,
    pub allowed: u64,
    pub denied: u64,
    pub enforcement_failures: u64,
    pub audit_write_failures: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnforcementResult {
    pub policy_generation: u64,
    pub decision: PolicyDecision,
    pub audit_sequence: Option<u64>,
}

#[derive(Debug, Error)]
pub enum EnforcementRuntimeError<E: Error + 'static> {
    #[error("policy store failed: {0}")]
    Policy(#[from] crate::PolicyStoreError),
    #[error("event journal initialization failed: {0}")]
    JournalInit(#[from] EventJournalError),
    #[error("platform adapter initialization failed: {0}")]
    AdapterInitialize(#[source] E),
    #[error("platform adapter enforcement failed: {0}")]
    AdapterEnforcement(#[source] E),
    #[error("platform adapter shutdown failed: {0}")]
    AdapterShutdown(#[source] E),
    #[error("enforcement runtime has not been initialized")]
    NotInitialized,
    #[error("enforcement runtime is faulted; successful shutdown and reinitialization are required")]
    Faulted,
    #[error("adapter reported state {actual:?} when Ready was required")]
    AdapterNotReady { actual: AdapterState },
}

/// Portable coordinator shared by platform implementations.
///
/// Adapters must validate raw OS input and construct a TrafficDescriptor
/// before calling this runtime. A failed enforcement operation faults the
/// runtime. Further traffic is refused until shutdown and reinitialization.
pub struct EnforcementRuntime<A: PlatformAdapter> {
    engine: Engine,
    adapter: A,
    journal: EventJournal,
    metrics: EnforcementMetrics,
    initialized: bool,
    faulted: bool,
}

impl<A: PlatformAdapter> EnforcementRuntime<A>
where
    A::Error: Error + 'static,
{
    pub fn new(
        engine: Engine,
        adapter: A,
        event_capacity: usize,
    ) -> Result<Self, EnforcementRuntimeError<A::Error>> {
        Ok(Self {
            engine,
            adapter,
            journal: EventJournal::new(event_capacity)?,
            metrics: EnforcementMetrics::default(),
            initialized: false,
            faulted: false,
        })
    }

    pub fn initialize(&mut self) -> Result<(), EnforcementRuntimeError<A::Error>> {
        if self.initialized && !self.faulted && self.adapter.state() == AdapterState::Ready {
            return Ok(());
        }
        if self.faulted {
            return Err(EnforcementRuntimeError::Faulted);
        }

        if let Err(error) = self.adapter.initialize() {
            self.faulted = true;
            return Err(EnforcementRuntimeError::AdapterInitialize(error));
        }

        // Mark initialized even when the adapter reports a bad state, so the
        // caller can explicitly invoke shutdown to recover partial resources.
        self.initialized = true;
        let state = self.adapter.state();
        if state != AdapterState::Ready {
            self.faulted = true;
            return Err(EnforcementRuntimeError::AdapterNotReady { actual: state });
        }

        Ok(())
    }

    /// Evaluate and apply one normalized packet/flow descriptor.
    ///
    /// The decision event is attempted before enforcement. A journal error
    /// does not change the selected verdict. Adapter failure faults the runtime
    /// and records a bounded failure event when possible.
    pub fn evaluate_and_enforce(
        &mut self,
        traffic: &TrafficDescriptor,
        now_ms: u64,
    ) -> Result<EnforcementResult, EnforcementRuntimeError<A::Error>> {
        self.ensure_ready()?;

        let snapshot = self.engine.snapshot()?;
        let decision = snapshot.decide(traffic);
        let flow_id = traffic.flow_id;

        let rule_id = match &decision.reason {
            DecisionReason::MatchedRule { rule_id } => Some(rule_id.clone()),
            DecisionReason::DefaultPolicy => None,
        };
        let audit_sequence = self.record_event(
            now_ms,
            flow_id,
            SecurityEventKind::PolicyDecision {
                verdict: decision.verdict,
                rule_id,
            },
        );

        self.metrics.decisions = self.metrics.decisions.saturating_add(1);
        match decision.verdict {
            Verdict::Allow => self.metrics.allowed = self.metrics.allowed.saturating_add(1),
            Verdict::Deny => self.metrics.denied = self.metrics.denied.saturating_add(1),
        }

        if let Err(error) = self.adapter.enforce(traffic, &decision) {
            self.metrics.enforcement_failures =
                self.metrics.enforcement_failures.saturating_add(1);
            self.faulted = true;
            let _ = self.record_event(
                now_ms,
                flow_id,
                SecurityEventKind::EnforcementFailure {
                    adapter: self.adapter.name().to_owned(),
                    error_code: "adapter-enforce-failed".to_owned(),
                },
            );
            return Err(EnforcementRuntimeError::AdapterEnforcement(error));
        }

        Ok(EnforcementResult {
            policy_generation: snapshot.generation(),
            decision,
            audit_sequence,
        })
    }

    /// Replace policy atomically, then audit the committed generation.
    pub fn reload_policy(
        &mut self,
        toml: &str,
        now_ms: u64,
    ) -> Result<u64, EnforcementRuntimeError<A::Error>> {
        let generation = self.engine.reload_toml(toml)?;
        let _ = self.record_event(
            now_ms,
            None,
            SecurityEventKind::PolicyReloaded { generation },
        );
        Ok(generation)
    }

    pub fn shutdown(&mut self) -> Result<(), EnforcementRuntimeError<A::Error>> {
        if !self.initialized {
            return Ok(());
        }

        match self.adapter.shutdown() {
            Ok(()) => {
                self.initialized = false;
                self.faulted = false;
                Ok(())
            }
            Err(error) => {
                self.faulted = true;
                Err(EnforcementRuntimeError::AdapterShutdown(error))
            }
        }
    }

    pub fn adapter_state(&self) -> AdapterState {
        self.adapter.state()
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    pub fn is_faulted(&self) -> bool {
        self.faulted
    }

    pub fn metrics(&self) -> EnforcementMetrics {
        self.metrics
    }

    pub fn events(&self) -> Vec<SecurityEvent> {
        self.journal.snapshot()
    }

    pub fn adapter(&self) -> &A {
        &self.adapter
    }

    fn ensure_ready(&mut self) -> Result<(), EnforcementRuntimeError<A::Error>> {
        if self.faulted {
            return Err(EnforcementRuntimeError::Faulted);
        }
        if !self.initialized {
            return Err(EnforcementRuntimeError::NotInitialized);
        }

        let state = self.adapter.state();
        if state != AdapterState::Ready {
            self.faulted = true;
            return Err(EnforcementRuntimeError::AdapterNotReady { actual: state });
        }
        Ok(())
    }

    fn record_event(
        &mut self,
        timestamp_ms: u64,
        flow_id: Option<FlowId>,
        kind: SecurityEventKind,
    ) -> Option<u64> {
        match self.journal.record(timestamp_ms, flow_id, kind) {
            Ok(outcome) => Some(outcome.sequence),
            Err(_) => {
                self.metrics.audit_write_failures =
                    self.metrics.audit_write_failures.saturating_add(1);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use erebus_types::{Direction, TransportProtocol};
    use std::net::{IpAddr, Ipv4Addr};

    const DENY_SSH: &str = r#"
schema_version = 1
[policy]
default = "allow"
[[rules]]
id = "deny-inbound-ssh"
direction = "inbound"
protocol = "tcp"
destination_port = 22
action = "deny"
"#;

    const DENY_ALL: &str = r#"
schema_version = 1
[policy]
default = "deny"
"#;

    const ALLOW_ALL: &str = r#"
schema_version = 1
[policy]
default = "allow"
"#;

    #[derive(Debug, Eq, PartialEq)]
    enum MockError {
        Initialize,
        Enforce,
        Shutdown,
    }

    impl std::fmt::Display for MockError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{self:?}")
        }
    }

    impl Error for MockError {}

    #[derive(Default)]
    struct MockAdapter {
        state: AdapterState,
        applied: Vec<Verdict>,
        fail_initialize: bool,
        fail_enforcement: bool,
        fail_shutdown: bool,
    }

    impl PlatformAdapter for MockAdapter {
        type Error = MockError;

        fn name(&self) -> &'static str {
            "mock"
        }

        fn state(&self) -> AdapterState {
            self.state
        }

        fn initialize(&mut self) -> Result<(), Self::Error> {
            if self.fail_initialize {
                return Err(MockError::Initialize);
            }
            self.state = AdapterState::Ready;
            Ok(())
        }

        fn enforce(
            &mut self,
            _traffic: &TrafficDescriptor,
            decision: &PolicyDecision,
        ) -> Result<(), Self::Error> {
            if self.state != AdapterState::Ready || self.fail_enforcement {
                self.state = AdapterState::Degraded;
                return Err(MockError::Enforce);
            }
            self.applied.push(decision.verdict);
            Ok(())
        }

        fn shutdown(&mut self) -> Result<(), Self::Error> {
            if self.fail_shutdown {
                self.state = AdapterState::Degraded;
                return Err(MockError::Shutdown);
            }
            self.state = AdapterState::Stopped;
            Ok(())
        }
    }

    fn descriptor(destination_port: u16) -> TrafficDescriptor {
        TrafficDescriptor {
            direction: Direction::Inbound,
            protocol: TransportProtocol::Tcp,
            source: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
            destination: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            source_port: Some(51_000),
            destination_port: Some(destination_port),
            interface: Some("mock0".into()),
            flow_id: Some(FlowId(42)),
        }
    }

    fn make_runtime(policy: &str, adapter: MockAdapter) -> EnforcementRuntime<MockAdapter> {
        EnforcementRuntime::new(Engine::from_toml(policy).unwrap(), adapter, 16).unwrap()
    }

    #[test]
    fn refuses_traffic_before_initialization() {
        let mut runtime = make_runtime(DENY_ALL, MockAdapter::default());
        assert!(matches!(
            runtime.evaluate_and_enforce(&descriptor(443), 1),
            Err(EnforcementRuntimeError::NotInitialized)
        ));
        assert!(runtime.adapter().applied.is_empty());
    }

    #[test]
    fn forwards_allow_and_deny_verdicts_and_audits_them() {
        let mut runtime = make_runtime(DENY_SSH, MockAdapter::default());
        runtime.initialize().unwrap();

        let denied = runtime.evaluate_and_enforce(&descriptor(22), 10).unwrap();
        assert_eq!(denied.policy_generation, 1);
        assert_eq!(denied.decision.verdict, Verdict::Deny);
        assert_eq!(
            denied.decision.reason,
            DecisionReason::MatchedRule {
                rule_id: "deny-inbound-ssh".into()
            }
        );

        let allowed = runtime.evaluate_and_enforce(&descriptor(443), 11).unwrap();
        assert_eq!(allowed.decision.verdict, Verdict::Allow);
        assert_eq!(runtime.adapter().applied, vec![Verdict::Deny, Verdict::Allow]);
        assert_eq!(runtime.events().len(), 2);
        assert_eq!(runtime.metrics().decisions, 2);
        assert_eq!(runtime.metrics().denied, 1);
        assert_eq!(runtime.metrics().allowed, 1);
    }

    #[test]
    fn enforcement_failure_faults_runtime_until_shutdown() {
        let mut runtime = make_runtime(
            DENY_ALL,
            MockAdapter {
                fail_enforcement: true,
                ..MockAdapter::default()
            },
        );
        runtime.initialize().unwrap();

        assert!(matches!(
            runtime.evaluate_and_enforce(&descriptor(443), 10),
            Err(EnforcementRuntimeError::AdapterEnforcement(MockError::Enforce))
        ));
        assert!(runtime.is_faulted());
        assert!(matches!(
            runtime.evaluate_and_enforce(&descriptor(443), 11),
            Err(EnforcementRuntimeError::Faulted)
        ));
        assert!(runtime.events().iter().any(|event| matches!(
            event.kind,
            SecurityEventKind::EnforcementFailure { .. }
        )));
        assert_eq!(runtime.metrics().enforcement_failures, 1);
    }

    #[test]
    fn policy_reload_is_atomic_and_generation_is_audited() {
        let mut runtime = make_runtime(DENY_ALL, MockAdapter::default());
        runtime.initialize().unwrap();
        assert_eq!(runtime.reload_policy(ALLOW_ALL, 10).unwrap(), 2);
        assert_eq!(
            runtime
                .evaluate_and_enforce(&descriptor(443), 11)
                .unwrap()
                .decision
                .verdict,
            Verdict::Allow
        );

        let invalid = ALLOW_ALL.replace("allow", "sometimes");
        assert!(runtime.reload_policy(&invalid, 12).is_err());
        assert_eq!(
            runtime
                .evaluate_and_enforce(&descriptor(443), 13)
                .unwrap()
                .policy_generation,
            2
        );
        assert!(runtime.events().iter().any(|event| matches!(
            event.kind,
            SecurityEventKind::PolicyReloaded { generation: 2 }
        )));
    }

    #[test]
    fn adapter_that_does_not_enter_ready_state_is_rejected_and_can_be_shutdown() {
        struct UnreadyAdapter;

        impl PlatformAdapter for UnreadyAdapter {
            type Error = MockError;

            fn name(&self) -> &'static str {
                "unready"
            }

            fn state(&self) -> AdapterState {
                AdapterState::Uninitialized
            }

            fn initialize(&mut self) -> Result<(), Self::Error> {
                Ok(())
            }

            fn enforce(
                &mut self,
                _: &TrafficDescriptor,
                _: &PolicyDecision,
            ) -> Result<(), Self::Error> {
                Ok(())
            }

            fn shutdown(&mut self) -> Result<(), Self::Error> {
                Ok(())
            }
        }

        let mut runtime = EnforcementRuntime::new(
            Engine::from_toml(DENY_ALL).unwrap(),
            UnreadyAdapter,
            4,
        )
        .unwrap();
        assert!(matches!(
            runtime.initialize(),
            Err(EnforcementRuntimeError::AdapterNotReady {
                actual: AdapterState::Uninitialized
            })
        ));
        assert!(runtime.is_faulted());
        runtime.shutdown().unwrap();
        assert!(!runtime.is_faulted());
    }

    #[test]
    fn audit_clock_failure_does_not_change_selected_verdict_or_skip_enforcement() {
        let mut runtime = make_runtime(ALLOW_ALL, MockAdapter::default());
        runtime.initialize().unwrap();
        runtime.evaluate_and_enforce(&descriptor(443), 20).unwrap();
        let result = runtime.evaluate_and_enforce(&descriptor(443), 19).unwrap();

        assert_eq!(result.decision.verdict, Verdict::Allow);
        assert_eq!(runtime.metrics().audit_write_failures, 1);
        assert_eq!(runtime.adapter().applied, vec![Verdict::Allow, Verdict::Allow]);
    }

    #[test]
    fn initialization_and_shutdown_failures_are_reported() {
        let mut init_failure = make_runtime(
            DENY_ALL,
            MockAdapter {
                fail_initialize: true,
                ..MockAdapter::default()
            },
        );
        assert!(matches!(
            init_failure.initialize(),
            Err(EnforcementRuntimeError::AdapterInitialize(MockError::Initialize))
        ));
        assert!(init_failure.is_faulted());

        let mut shutdown_failure = make_runtime(
            DENY_ALL,
            MockAdapter {
                fail_shutdown: true,
                ..MockAdapter::default()
            },
        );
        shutdown_failure.initialize().unwrap();
        assert!(matches!(
            shutdown_failure.shutdown(),
            Err(EnforcementRuntimeError::AdapterShutdown(MockError::Shutdown))
        ));
        assert!(shutdown_failure.is_faulted());
    }
}
