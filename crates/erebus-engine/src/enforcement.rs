//! Portable enforcement orchestration.
//!
//! This runtime owns policy evaluation, decision auditing, lifecycle, and
//! adapter-failure handling. Platform adapters own packet acquisition and the
//! operating-system-specific act of applying a verdict.

use crate::{
    ConnectionTracker, Engine, EventJournal, EventJournalError, KeyedRateLimiter,
    KeyedRateLimiterConfig, RateLimitError, SecurityEvent, SecurityEventKind, TcpFlags,
    TrackerConfig, TrackerError,
};
use erebus_adapter_api::{AdapterState, PlatformAdapter};
use erebus_types::{DecisionReason, Direction, FlowId, PolicyDecision, TrafficDescriptor, Verdict};
use std::error::Error;
use std::net::IpAddr;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EnforcementMetrics {
    pub decisions: u64,
    pub allowed: u64,
    pub denied: u64,
    pub enforcement_failures: u64,
    pub audit_write_failures: u64,
    pub rate_limited: u64,
    pub tracking_failures: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnforcementRuntimeConfig {
    pub event_capacity: usize,
    pub tracker: TrackerConfig,
    pub client_rate_limit: KeyedRateLimiterConfig,
}

impl Default for EnforcementRuntimeConfig {
    fn default() -> Self {
        Self {
            event_capacity: 8192,
            tracker: TrackerConfig::default(),
            client_rate_limit: KeyedRateLimiterConfig {
                bucket: crate::TokenBucketConfig {
                    capacity: 100,
                    refill_interval_ms: 100,
                },
                max_keys: 4096,
                idle_timeout_ms: 300_000,
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnforcementMaintenanceReport {
    pub expired_flows: Vec<FlowId>,
    pub pruned_rate_limit_clients: usize,
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
    #[error("connection tracker initialization failed: {0}")]
    TrackerInit(#[source] TrackerError),
    #[error("client rate limiter initialization failed: {0}")]
    RateLimitInit(#[source] RateLimitError),
    #[error("connection tracker maintenance failed: {0}")]
    TrackerMaintenance(#[source] TrackerError),
    #[error("client rate limiter maintenance failed: {0}")]
    RateLimitMaintenance(#[source] RateLimitError),
    #[error("platform adapter initialization failed: {0}")]
    AdapterInitialize(#[source] E),
    #[error("platform adapter enforcement failed: {0}")]
    AdapterEnforcement(#[source] E),
    #[error("platform adapter shutdown failed: {0}")]
    AdapterShutdown(#[source] E),
    #[error("enforcement runtime has not been initialized")]
    NotInitialized,
    #[error(
        "enforcement runtime is faulted; successful shutdown and reinitialization are required"
    )]
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
    tracker: ConnectionTracker,
    client_limits: KeyedRateLimiter<IpAddr>,
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
        Self::with_config(
            engine,
            adapter,
            EnforcementRuntimeConfig {
                event_capacity,
                ..EnforcementRuntimeConfig::default()
            },
        )
    }

    pub fn with_config(
        engine: Engine,
        adapter: A,
        config: EnforcementRuntimeConfig,
    ) -> Result<Self, EnforcementRuntimeError<A::Error>> {
        let tracker =
            ConnectionTracker::new(config.tracker).map_err(EnforcementRuntimeError::TrackerInit)?;
        let client_limits = KeyedRateLimiter::new(config.client_rate_limit)
            .map_err(EnforcementRuntimeError::RateLimitInit)?;

        Ok(Self {
            engine,
            adapter,
            journal: EventJournal::new(config.event_capacity)?,
            tracker,
            client_limits,
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

        // Mark the adapter as requiring shutdown before initialization starts:
        // initialize may partially acquire OS resources before returning an error.
        self.initialized = true;
        if let Err(error) = self.adapter.initialize() {
            self.faulted = true;
            return Err(EnforcementRuntimeError::AdapterInitialize(error));
        }

        // The caller can now explicitly shut down even if the adapter reports
        // an unexpected state after a nominally successful initialization.
        let state = self.adapter.state();
        if state != AdapterState::Ready {
            self.faulted = true;
            return Err(EnforcementRuntimeError::AdapterNotReady { actual: state });
        }

        Ok(())
    }

    /// Compatibility entry point for callers that already aggregate traffic
    /// into descriptors. TCP flow-state tracking requires raw TCP flags; use
    /// `evaluate_packet` for native packet callbacks.
    pub fn evaluate_and_enforce(
        &mut self,
        traffic: &TrafficDescriptor,
        now_ms: u64,
    ) -> Result<EnforcementResult, EnforcementRuntimeError<A::Error>> {
        self.evaluate_internal(traffic, None, now_ms, false)
    }

    /// Process one validated packet observation. Native adapters must pass TCP
    /// flags for TCP packets so the portable connection tracker can maintain
    /// handshake/closing state. Rate limits and tracking failures fail closed.
    pub fn evaluate_packet(
        &mut self,
        traffic: &TrafficDescriptor,
        tcp_flags: Option<TcpFlags>,
        now_ms: u64,
    ) -> Result<EnforcementResult, EnforcementRuntimeError<A::Error>> {
        self.evaluate_internal(traffic, tcp_flags, now_ms, true)
    }

    fn evaluate_internal(
        &mut self,
        traffic: &TrafficDescriptor,
        tcp_flags: Option<TcpFlags>,
        now_ms: u64,
        track_packet: bool,
    ) -> Result<EnforcementResult, EnforcementRuntimeError<A::Error>> {
        self.ensure_ready()?;

        let snapshot = self.engine.snapshot()?;
        let mut enriched_traffic = traffic.clone();
        let mut decision = snapshot.decide(&enriched_traffic);

        // A policy Deny is final. Only policy-allowed traffic reaches the
        // limiter or tracker, so those subsystems can never override a Deny.
        if decision.verdict == Verdict::Allow {
            let peer = match traffic.direction {
                Direction::Inbound => traffic.source,
                Direction::Outbound => traffic.destination,
            };

            match self.client_limits.check(peer, now_ms) {
                Ok(true) => {}
                Ok(false) => {
                    self.metrics.rate_limited = self.metrics.rate_limited.saturating_add(1);
                    decision = PolicyDecision {
                        verdict: Verdict::Deny,
                        reason: DecisionReason::RateLimited {
                            peer,
                            reason: "per-client token bucket exhausted".to_owned(),
                        },
                    };
                    let _ = self.record_event(
                        now_ms,
                        traffic.flow_id,
                        SecurityEventKind::ClientRateLimitExceeded { peer },
                    );
                }
                Err(error) => {
                    self.metrics.rate_limited = self.metrics.rate_limited.saturating_add(1);
                    decision = PolicyDecision {
                        verdict: Verdict::Deny,
                        reason: DecisionReason::RateLimited {
                            peer,
                            reason: error.to_string(),
                        },
                    };
                    let _ = self.record_event(
                        now_ms,
                        traffic.flow_id,
                        SecurityEventKind::ClientRateLimitExceeded { peer },
                    );
                }
            }
        }

        if decision.verdict == Verdict::Allow && track_packet {
            match self.tracker.observe(&enriched_traffic, tcp_flags, now_ms) {
                Ok(observation) => {
                    enriched_traffic.flow_id = Some(observation.flow_id);
                    if observation.is_new {
                        let _ = self.record_event(
                            now_ms,
                            Some(observation.flow_id),
                            SecurityEventKind::ConnectionCreated,
                        );
                    } else if observation
                        .previous_state
                        .is_some_and(|previous| previous != observation.state)
                    {
                        let _ = self.record_event(
                            now_ms,
                            Some(observation.flow_id),
                            SecurityEventKind::ConnectionStateChanged {
                                state: format!("{:?}", observation.state),
                            },
                        );
                    }
                }
                Err(error) => {
                    self.metrics.tracking_failures =
                        self.metrics.tracking_failures.saturating_add(1);
                    let error_code = error.to_string();
                    let _ = self.record_event(
                        now_ms,
                        enriched_traffic.flow_id.or(traffic.flow_id),
                        SecurityEventKind::ConnectionTrackingFailure {
                            error_code: error_code.clone(),
                        },
                    );
                    decision = PolicyDecision {
                        verdict: Verdict::Deny,
                        reason: DecisionReason::ConnectionTrackingUnavailable {
                            reason: error_code,
                        },
                    };
                }
            }
        }

        let flow_id = enriched_traffic.flow_id.or(traffic.flow_id);
        let rule_id = match &decision.reason {
            DecisionReason::MatchedRule { rule_id } => Some(rule_id.clone()),
            _ => None,
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

        if let Err(error) = self.adapter.enforce(&enriched_traffic, &decision) {
            self.metrics.enforcement_failures = self.metrics.enforcement_failures.saturating_add(1);
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

    /// Expire idle flows and client buckets. Call this periodically from the
    /// host service's monotonic timer. If either state table reports a clock or
    /// maintenance error, the runtime faults and refuses further traffic.
    pub fn maintain(
        &mut self,
        now_ms: u64,
    ) -> Result<EnforcementMaintenanceReport, EnforcementRuntimeError<A::Error>> {
        self.ensure_ready()?;

        let expired_flows = match self.tracker.expire_with_flow_ids(now_ms) {
            Ok(flows) => flows,
            Err(error) => {
                self.faulted = true;
                return Err(EnforcementRuntimeError::TrackerMaintenance(error));
            }
        };
        let pruned_rate_limit_clients = match self.client_limits.prune_idle(now_ms) {
            Ok(count) => count,
            Err(error) => {
                self.faulted = true;
                return Err(EnforcementRuntimeError::RateLimitMaintenance(error));
            }
        };

        for flow_id in &expired_flows {
            let _ = self.record_event(now_ms, Some(*flow_id), SecurityEventKind::ConnectionExpired);
        }

        Ok(EnforcementMaintenanceReport {
            expired_flows,
            pruned_rate_limit_clients,
        })
    }

    pub fn active_flows(&self) -> usize {
        self.tracker.len()
    }

    pub fn tracked_clients(&self) -> usize {
        self.client_limits.key_count()
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
                self.tracker.clear();
                self.client_limits.clear();
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
    use crate::{KeyedRateLimiterConfig, TokenBucketConfig};
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

    fn udp_descriptor(
        source: &str,
        source_port: u16,
        destination: &str,
        destination_port: u16,
        direction: Direction,
    ) -> TrafficDescriptor {
        TrafficDescriptor {
            direction,
            protocol: TransportProtocol::Udp,
            source: source.parse().unwrap(),
            destination: destination.parse().unwrap(),
            source_port: Some(source_port),
            destination_port: Some(destination_port),
            interface: Some("mock0".into()),
            flow_id: None,
        }
    }

    fn small_config(
        tracker_capacity: usize,
        rate_capacity: u32,
        idle_timeout_ms: u64,
    ) -> EnforcementRuntimeConfig {
        EnforcementRuntimeConfig {
            event_capacity: 64,
            tracker: TrackerConfig {
                max_entries: tracker_capacity,
                tcp_syn_timeout_ms: 10,
                tcp_established_timeout_ms: 100,
                tcp_closing_timeout_ms: 10,
                tcp_reset_timeout_ms: 5,
                udp_timeout_ms: 10,
                other_timeout_ms: 10,
            },
            client_rate_limit: KeyedRateLimiterConfig {
                bucket: TokenBucketConfig {
                    capacity: rate_capacity,
                    refill_interval_ms: 100,
                },
                max_keys: 8,
                idle_timeout_ms,
            },
        }
    }

    fn make_runtime(policy: &str, adapter: MockAdapter) -> EnforcementRuntime<MockAdapter> {
        EnforcementRuntime::new(Engine::from_toml(policy).unwrap(), adapter, 16).unwrap()
    }

    #[test]
    fn packet_pipeline_tracks_tcp_handshake_and_emits_state_events() {
        let mut runtime = make_runtime(ALLOW_ALL, MockAdapter::default());
        runtime.initialize().unwrap();

        let syn = descriptor(22);
        let first = runtime
            .evaluate_packet(&syn, Some(TcpFlags::syn()), 10)
            .unwrap();
        assert_eq!(first.decision.verdict, Verdict::Allow);
        assert_eq!(runtime.active_flows(), 1);

        let syn_ack = TrafficDescriptor {
            direction: Direction::Outbound,
            source: syn.destination,
            destination: syn.source,
            source_port: syn.destination_port,
            destination_port: syn.source_port,
            ..syn.clone()
        };
        runtime
            .evaluate_packet(&syn_ack, Some(TcpFlags::syn_ack()), 20)
            .unwrap();

        let ack = syn.clone();
        runtime
            .evaluate_packet(&ack, Some(TcpFlags::ack()), 30)
            .unwrap();

        let events = runtime.events();
        assert!(events
            .iter()
            .any(|event| matches!(event.kind, SecurityEventKind::ConnectionCreated)));
        let transitions = events
            .iter()
            .filter_map(|event| match &event.kind {
                SecurityEventKind::ConnectionStateChanged { state } => Some(state.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(transitions, vec!["Tcp(SynReceived)", "Tcp(Established)"]);
        assert!(events
            .iter()
            .filter(|event| matches!(
                event.kind,
                SecurityEventKind::ConnectionCreated
                    | SecurityEventKind::ConnectionStateChanged { .. }
            ))
            .all(|event| event.flow_id == Some(FlowId(1))));
    }

    #[test]
    fn per_client_rate_limit_denies_excess_packets_without_adapter_bypass() {
        let mut runtime = EnforcementRuntime::with_config(
            Engine::from_toml(ALLOW_ALL).unwrap(),
            MockAdapter::default(),
            small_config(8, 1, 1_000),
        )
        .unwrap();
        runtime.initialize().unwrap();

        let packet = udp_descriptor(
            "198.51.100.20",
            51_000,
            "192.0.2.10",
            5353,
            Direction::Inbound,
        );
        let first = runtime.evaluate_packet(&packet, None, 0).unwrap();
        let second = runtime.evaluate_packet(&packet, None, 0).unwrap();

        assert_eq!(first.decision.verdict, Verdict::Allow);
        assert_eq!(second.decision.verdict, Verdict::Deny);
        assert!(matches!(
            second.decision.reason,
            DecisionReason::RateLimited { peer, .. } if peer == "198.51.100.20".parse::<IpAddr>().unwrap()
        ));
        assert_eq!(runtime.metrics().rate_limited, 1);
        assert_eq!(
            runtime.adapter().applied,
            vec![Verdict::Allow, Verdict::Deny]
        );
        assert!(runtime
            .events()
            .iter()
            .any(|event| matches!(event.kind, SecurityEventKind::RateLimitExceeded { .. })));
    }

    #[test]
    fn tracker_capacity_exhaustion_is_a_deny_not_an_untracked_allow() {
        let mut runtime = EnforcementRuntime::with_config(
            Engine::from_toml(ALLOW_ALL).unwrap(),
            MockAdapter::default(),
            small_config(1, 10, 1_000),
        )
        .unwrap();
        runtime.initialize().unwrap();

        let first = udp_descriptor(
            "198.51.100.30",
            51_000,
            "192.0.2.10",
            5353,
            Direction::Inbound,
        );
        let second = udp_descriptor(
            "198.51.100.30",
            51_001,
            "192.0.2.11",
            5353,
            Direction::Inbound,
        );

        assert_eq!(
            runtime
                .evaluate_packet(&first, None, 0)
                .unwrap()
                .decision
                .verdict,
            Verdict::Allow
        );
        let blocked = runtime.evaluate_packet(&second, None, 1).unwrap();
        assert_eq!(blocked.decision.verdict, Verdict::Deny);
        assert!(matches!(
            blocked.decision.reason,
            DecisionReason::ConnectionTrackingUnavailable { .. }
        ));
        assert_eq!(runtime.metrics().tracking_failures, 1);
        assert_eq!(runtime.active_flows(), 1);
        assert_eq!(
            runtime.adapter().applied,
            vec![Verdict::Allow, Verdict::Deny]
        );
    }

    #[test]
    fn maintenance_expires_connections_and_prunes_idle_client_buckets() {
        let mut runtime = EnforcementRuntime::with_config(
            Engine::from_toml(ALLOW_ALL).unwrap(),
            MockAdapter::default(),
            small_config(8, 10, 15),
        )
        .unwrap();
        runtime.initialize().unwrap();

        let packet = udp_descriptor(
            "198.51.100.40",
            51_000,
            "192.0.2.10",
            5353,
            Direction::Inbound,
        );
        runtime.evaluate_packet(&packet, None, 0).unwrap();
        assert_eq!(runtime.active_flows(), 1);
        assert_eq!(runtime.tracked_clients(), 1);

        let first = runtime.maintain(10).unwrap();
        assert_eq!(first.expired_flows, vec![FlowId(1)]);
        assert_eq!(runtime.active_flows(), 0);
        assert_eq!(first.pruned_rate_limit_clients, 0);

        let second = runtime.maintain(15).unwrap();
        assert_eq!(second.pruned_rate_limit_clients, 1);
        assert_eq!(runtime.tracked_clients(), 0);
        assert!(runtime
            .events()
            .iter()
            .any(|event| matches!(event.kind, SecurityEventKind::ConnectionExpired)));
    }

    #[test]
    fn shutdown_clears_flow_and_rate_limit_state_before_reinitialize() {
        let mut runtime = EnforcementRuntime::with_config(
            Engine::from_toml(ALLOW_ALL).unwrap(),
            MockAdapter::default(),
            small_config(8, 10, 1_000),
        )
        .unwrap();
        runtime.initialize().unwrap();

        let packet = udp_descriptor(
            "198.51.100.50",
            51_000,
            "192.0.2.10",
            5353,
            Direction::Inbound,
        );
        runtime.evaluate_packet(&packet, None, 0).unwrap();
        assert_eq!(runtime.active_flows(), 1);
        assert_eq!(runtime.tracked_clients(), 1);

        runtime.shutdown().unwrap();
        assert_eq!(runtime.active_flows(), 0);
        assert_eq!(runtime.tracked_clients(), 0);

        runtime.initialize().unwrap();
        assert_eq!(
            runtime
                .evaluate_packet(&packet, None, 1)
                .unwrap()
                .decision
                .verdict,
            Verdict::Allow
        );
        let created_flow_ids = runtime
            .events()
            .iter()
            .filter(|event| matches!(event.kind, SecurityEventKind::ConnectionCreated))
            .filter_map(|event| event.flow_id)
            .collect::<Vec<_>>();
        assert_eq!(created_flow_ids, vec![FlowId(1), FlowId(2)]);
    }

    #[test]
    fn tcp_packet_without_flags_fails_closed_in_packet_api() {
        let mut runtime = make_runtime(ALLOW_ALL, MockAdapter::default());
        runtime.initialize().unwrap();
        let result = runtime.evaluate_packet(&descriptor(443), None, 1).unwrap();

        assert_eq!(result.decision.verdict, Verdict::Deny);
        assert!(matches!(
            result.decision.reason,
            DecisionReason::ConnectionTrackingUnavailable { .. }
        ));
        assert_eq!(runtime.active_flows(), 0);
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
        assert_eq!(
            runtime.adapter().applied,
            vec![Verdict::Deny, Verdict::Allow]
        );
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
            Err(EnforcementRuntimeError::AdapterEnforcement(
                MockError::Enforce
            ))
        ));
        assert!(runtime.is_faulted());
        assert!(matches!(
            runtime.evaluate_and_enforce(&descriptor(443), 11),
            Err(EnforcementRuntimeError::Faulted)
        ));
        assert!(runtime
            .events()
            .iter()
            .any(|event| matches!(event.kind, SecurityEventKind::EnforcementFailure { .. })));
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

        let mut runtime =
            EnforcementRuntime::new(Engine::from_toml(DENY_ALL).unwrap(), UnreadyAdapter, 4)
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
        assert_eq!(
            runtime.adapter().applied,
            vec![Verdict::Allow, Verdict::Allow]
        );
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
            Err(EnforcementRuntimeError::AdapterInitialize(
                MockError::Initialize
            ))
        ));
        assert!(init_failure.is_faulted());
        init_failure.shutdown().unwrap();
        assert!(!init_failure.is_faulted());

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
            Err(EnforcementRuntimeError::AdapterShutdown(
                MockError::Shutdown
            ))
        ));
        assert!(shutdown_failure.is_faulted());
    }
}
