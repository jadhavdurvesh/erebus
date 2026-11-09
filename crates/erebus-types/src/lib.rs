//! Platform-neutral types shared by EREBUS components.
//!
//! These are metadata structures, not raw packet parsers. Platform adapters
//! are responsible for safely obtaining and normalizing this information.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Stable identifier assigned to a flow by an adapter or connection tracker.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct FlowId(pub u64);

/// Network transport protocol relevant to a policy decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

/// Direction relative to the protected host or interface.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// A normalized description of a packet or flow.
///
/// Adapters must validate all fields before constructing this value. Ports are
/// optional because not every IP protocol has transport ports.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrafficDescriptor {
    pub direction: Direction,
    pub protocol: TransportProtocol,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub interface: Option<String>,
    pub flow_id: Option<FlowId>,
}

/// The decision produced by the portable policy engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Verdict {
    Allow,
    Deny,
}

/// Why a verdict was produced. Useful for audit logs and diagnostics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DecisionReason {
    MatchedRule { rule_id: String },
    DefaultPolicy,
}

/// A complete, explainable policy decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub verdict: Verdict,
    pub reason: DecisionReason,
}
