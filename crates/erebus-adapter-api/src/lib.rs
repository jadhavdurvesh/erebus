//! Contract for operating-system-specific enforcement adapters.
//!
//! This crate intentionally does not implement packet capture or enforcement.

use erebus_types::{PolicyDecision, TrafficDescriptor};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterState {
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
