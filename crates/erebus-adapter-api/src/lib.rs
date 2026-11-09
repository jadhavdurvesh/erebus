//! Contract for operating-system-specific enforcement adapters.
//!
//! This crate intentionally does not implement packet capture or enforcement.

use erebus_types::{PolicyDecision, TrafficDescriptor};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AdapterState {
    #[default]
    Uninitialized,
    Ready,
    Degraded,
    Stopped,
}

/// Platform-specific code implements this contract. Implementations must
/// document their enforcement semantics and failure behaviour.
pub trait PlatformAdapter {
    type Error;

    fn name(&self) -> &'static str;
    fn state(&self) -> AdapterState;

    /// Start or attach to the platform's supported filtering mechanism.
    fn initialize(&mut self) -> Result<(), Self::Error>;

    /// Apply a decision to the platform traffic item represented by descriptor.
    ///
    /// The adapter must not reinterpret an explicit Deny as Allow. If applying
    /// a decision fails, it must report the error and follow its documented
    /// fail-safe behaviour.
    fn enforce(
        &mut self,
        traffic: &TrafficDescriptor,
        decision: &PolicyDecision,
    ) -> Result<(), Self::Error>;

    fn shutdown(&mut self) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use erebus_types::{
        DecisionReason, Direction, PolicyDecision, TransportProtocol, Verdict,
    };
    use std::net::{IpAddr, Ipv4Addr};

    #[derive(Debug, Eq, PartialEq)]
    enum MockError {
        NotReady,
        InjectedEnforcementFailure,
    }

    #[derive(Default)]
    struct MockAdapter {
        state: AdapterState,
        applied: Vec<Verdict>,
        fail_enforcement: bool,
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
            self.state = AdapterState::Ready;
            Ok(())
        }

        fn enforce(
            &mut self,
            _traffic: &TrafficDescriptor,
            decision: &PolicyDecision,
        ) -> Result<(), Self::Error> {
            if self.state != AdapterState::Ready {
                return Err(MockError::NotReady);
            }
            if self.fail_enforcement {
                self.state = AdapterState::Degraded;
                return Err(MockError::InjectedEnforcementFailure);
            }

            self.applied.push(decision.verdict);
            Ok(())
        }

        fn shutdown(&mut self) -> Result<(), Self::Error> {
            self.state = AdapterState::Stopped;
            Ok(())
        }
    }

    fn descriptor() -> TrafficDescriptor {
        TrafficDescriptor {
            direction: Direction::Inbound,
            protocol: TransportProtocol::Tcp,
            source: IpAddr::V4(Ipv4Addr::LOCALHOST),
            destination: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            source_port: Some(50_000),
            destination_port: Some(443),
            interface: Some("mock0".into()),
            flow_id: None,
        }
    }

    fn deny_decision() -> PolicyDecision {
        PolicyDecision {
            verdict: Verdict::Deny,
            reason: DecisionReason::DefaultPolicy,
        }
    }

    #[test]
    fn adapter_lifecycle_and_verdict_forwarding_work() {
        let mut adapter = MockAdapter::default();
        assert_eq!(adapter.name(), "mock");
        assert_eq!(adapter.state(), AdapterState::Uninitialized);

        adapter.initialize().unwrap();
        assert_eq!(adapter.state(), AdapterState::Ready);

        adapter.enforce(&descriptor(), &deny_decision()).unwrap();
        assert_eq!(adapter.applied, vec![Verdict::Deny]);

        adapter.shutdown().unwrap();
        assert_eq!(adapter.state(), AdapterState::Stopped);
    }

    #[test]
    fn adapter_refuses_enforcement_before_initialization() {
        let mut adapter = MockAdapter::default();
        assert_eq!(
            adapter.enforce(&descriptor(), &deny_decision()),
            Err(MockError::NotReady)
        );
    }

    #[test]
    fn adapter_reports_enforcement_failure_and_enters_degraded_state() {
        let mut adapter = MockAdapter {
            fail_enforcement: true,
            ..MockAdapter::default()
        };
        adapter.initialize().unwrap();

        assert_eq!(
            adapter.enforce(&descriptor(), &deny_decision()),
            Err(MockError::InjectedEnforcementFailure)
        );
        assert_eq!(adapter.state(), AdapterState::Degraded);
        assert!(adapter.applied.is_empty());
    }
}
