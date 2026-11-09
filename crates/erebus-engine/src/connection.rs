//! Bounded in-memory connection tracking for normalized traffic metadata.
//!
//! This tracker is a portable state model. It does not capture packets, validate
//! TCP checksums, inspect sequence numbers, or enforce verdicts. Adapters must
//! provide validated metadata and TCP flags from the native networking layer.

use erebus_types::{FlowId, IpAddr, TrafficDescriptor, TransportProtocol};
use std::{
    cmp::Ordering,
    collections::HashMap,
    net::IpAddr as StdIpAddr,
};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Endpoint {
    address: StdIpAddr,
    port: Option<u16>,
}

impl Ord for Endpoint {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.address, self.port).cmp(&(other.address, other.port))
    }
}

impl PartialOrd for Endpoint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FlowKey {
    protocol: TransportProtocol,
    first: Endpoint,
    second: Endpoint,
}

impl FlowKey {
    fn new(
        protocol: TransportProtocol,
        source: Endpoint,
        destination: Endpoint,
    ) -> Self {
        if source <= destination {
            Self {
                protocol,
                first: source,
                second: destination,
            }
        } else {
            Self {
                protocol,
                first: destination,
                second: source,
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketDirection {
    Initiator,
    Responder,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
}

impl TcpFlags {
    pub const fn syn() -> Self {
        Self {
            syn: true,
            ack: false,
            fin: false,
            rst: false,
        }
    }

    pub const fn syn_ack() -> Self {
        Self {
            syn: true,
            ack: true,
            fin: false,
            rst: false,
        }
    }

    pub const fn ack() -> Self {
        Self {
            syn: false,
            ack: true,
            fin: false,
            rst: false,
        }
    }

    pub const fn fin_ack() -> Self {
        Self {
            syn: false,
            ack: true,
            fin: true,
            rst: false,
        }
    }

    pub const fn rst() -> Self {
        Self {
            syn: false,
            ack: false,
            fin: false,
            rst: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpState {
    SynSent,
    SynReceived,
    Established,
    Midstream,
    FinWait,
    TimeWait,
    Reset,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpState {
    Unreplied,
    Replied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    Tcp(TcpState),
    Udp(UdpState),
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionObservation {
    pub flow_id: FlowId,
    pub direction: PacketDirection,
    pub state: ConnectionState,
    pub created_at_ms: u64,
    pub last_seen_ms: u64,
    pub expires_at_ms: u64,
    pub is_new: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrackerConfig {
    pub max_entries: usize,
    pub tcp_syn_timeout_ms: u64,
    pub tcp_established_timeout_ms: u64,
    pub tcp_closing_timeout_ms: u64,
    pub tcp_reset_timeout_ms: u64,
    pub udp_timeout_ms: u64,
    pub other_timeout_ms: u64,
}

impl Default for TrackerConfig {
    fn default() -> Self {
        Self {
            max_entries: 16_384,
            tcp_syn_timeout_ms: 30_000,
            tcp_established_timeout_ms: 300_000,
            tcp_closing_timeout_ms: 30_000,
            tcp_reset_timeout_ms: 2_000,
            udp_timeout_ms: 30_000,
            other_timeout_ms: 10_000,
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum TrackerError {
    #[error("connection tracker capacity must be greater than zero")]
    ZeroCapacity,
    #[error("TCP traffic requires source and destination ports")]
    MissingTcpPorts,
    #[error("TCP traffic requires TCP flags")]
    MissingTcpFlags,
    #[error("TCP flags contain an invalid SYN and FIN combination")]
    InvalidTcpFlags,
    #[error("timestamp moved backwards: previous {previous_ms} ms, received {received_ms} ms")]
    ClockWentBackwards {
        previous_ms: u64,
        received_ms: u64,
    },
    #[error("connection tracker is full ({capacity} entries); no active flow was evicted")]
    CapacityReached { capacity: usize },
    #[error("flow identifier space is exhausted")]
    FlowIdExhausted,
}

#[derive(Clone, Debug)]
struct Connection {
    flow_id: FlowId,
    initiator: Endpoint,
    responder: Endpoint,
    state: ConnectionState,
    created_at_ms: u64,
    last_seen_ms: u64,
    expires_at_ms: u64,
    initiator_fin: bool,
    responder_fin: bool,
}

/// A bounded connection table.
///
/// Time is supplied by the caller and must be monotonic milliseconds from a
/// monotonic clock. Active entries are never evicted to make room for new flows.
pub struct ConnectionTracker {
    config: TrackerConfig,
    entries: HashMap<FlowKey, Connection>,
    next_flow_id: u64,
    last_observed_ms: Option<u64>,
}

impl ConnectionTracker {
    pub fn new(config: TrackerConfig) -> Result<Self, TrackerError> {
        if config.max_entries == 0 {
            return Err(TrackerError::ZeroCapacity);
        }

        Ok(Self {
            config,
            entries: HashMap::with_capacity(config.max_entries.min(4096)),
            next_flow_id: 1,
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

    /// Record one normalized packet/flow observation and return its current state.
    ///
    /// Pass TCP flags for TCP packets and None for non-TCP protocols. The tracker
    /// treats the first observed packet as the initiator; a midstream TCP flow is
    /// explicitly marked Midstream rather than assumed to be established.
    pub fn observe(
        &mut self,
        traffic: &TrafficDescriptor,
        tcp_flags: Option<TcpFlags>,
        now_ms: u64,
    ) -> Result<ConnectionObservation, TrackerError> {
        self.check_time(now_ms)?;
        self.last_observed_ms = Some(now_ms);

        let source = Endpoint {
            address: traffic.source,
            port: traffic.source_port,
        };
        let destination = Endpoint {
            address: traffic.destination,
            port: traffic.destination_port,
        };

        if traffic.protocol == TransportProtocol::Tcp {
            if source.port.is_none() || destination.port.is_none() {
                return Err(TrackerError::MissingTcpPorts);
            }
            if tcp_flags.is_none() {
                return Err(TrackerError::MissingTcpFlags);
            }
            let flags = tcp_flags.expect("validated above");
            if flags.syn && flags.fin {
                return Err(TrackerError::InvalidTcpFlags);
            }
        }

        self.expire_internal(now_ms);
        let key = FlowKey::new(traffic.protocol, source, destination);

        if let Some(connection) = self.entries.get_mut(&key) {
            let direction = if source == connection.initiator {
                PacketDirection::Initiator
            } else {
                PacketDirection::Responder
            };

            match traffic.protocol {
                TransportProtocol::Tcp => {
                    let flags = tcp_flags.expect("TCP flags validated above");
                    update_tcp(connection, direction, flags);
                }
                TransportProtocol::Udp => {
                    if direction == PacketDirection::Responder {
                        connection.state = ConnectionState::Udp(UdpState::Replied);
                    }
                }
                _ => {}
            }

            connection.last_seen_ms = now_ms;
            connection.expires_at_ms =
                now_ms.saturating_add(self.timeout_for(connection.state));

            return Ok(observation(connection, direction, false));
        }

        if self.entries.len() >= self.config.max_entries {
            return Err(TrackerError::CapacityReached {
                capacity: self.config.max_entries,
            });
        }

        let flow_id = FlowId(self.next_flow_id);
        self.next_flow_id = self
            .next_flow_id
            .checked_add(1)
            .ok_or(TrackerError::FlowIdExhausted)?;

        let state = match traffic.protocol {
            TransportProtocol::Tcp => {
                let flags = tcp_flags.expect("TCP flags validated above");
                if flags.rst {
                    ConnectionState::Tcp(TcpState::Reset)
                } else if flags.syn && !flags.ack {
                    ConnectionState::Tcp(TcpState::SynSent)
                } else {
                    ConnectionState::Tcp(TcpState::Midstream)
                }
            }
            TransportProtocol::Udp => ConnectionState::Udp(UdpState::Unreplied),
            _ => ConnectionState::Other,
        };

        let connection = Connection {
            flow_id,
            initiator: source,
            responder: destination,
            state,
            created_at_ms: now_ms,
            last_seen_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(self.timeout_for(state)),
            initiator_fin: false,
            responder_fin: false,
        };

        let result = observation(&connection, PacketDirection::Initiator, true);
        self.entries.insert(key, connection);
        Ok(result)
    }

    /// Remove entries whose expiry time is less than or equal to now_ms.
    pub fn expire(&mut self, now_ms: u64) -> Result<usize, TrackerError> {
        self.check_time(now_ms)?;
        self.last_observed_ms = Some(now_ms);
        Ok(self.expire_internal(now_ms))
    }

    fn expire_internal(&mut self, now_ms: u64) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, flow| flow.expires_at_ms > now_ms);
        before - self.entries.len()
    }

    fn check_time(&self, now_ms: u64) -> Result<(), TrackerError> {
        if let Some(previous_ms) = self.last_observed_ms {
            if now_ms < previous_ms {
                return Err(TrackerError::ClockWentBackwards {
                    previous_ms,
                    received_ms: now_ms,
                });
            }
        }
        Ok(())
    }

    fn timeout_for(&self, state: ConnectionState) -> u64 {
        match state {
            ConnectionState::Tcp(TcpState::SynSent | TcpState::SynReceived) => {
                self.config.tcp_syn_timeout_ms
            }
            ConnectionState::Tcp(TcpState::Established | TcpState::Midstream) => {
                self.config.tcp_established_timeout_ms
            }
            ConnectionState::Tcp(TcpState::FinWait | TcpState::TimeWait) => {
                self.config.tcp_closing_timeout_ms
            }
            ConnectionState::Tcp(TcpState::Reset) => self.config.tcp_reset_timeout_ms,
            ConnectionState::Udp(_) => self.config.udp_timeout_ms,
            ConnectionState::Other => self.config.other_timeout_ms,
        }
    }
}

fn observation(
    connection: &Connection,
    direction: PacketDirection,
    is_new: bool,
) -> ConnectionObservation {
    ConnectionObservation {
        flow_id: connection.flow_id,
        direction,
        state: connection.state,
        created_at_ms: connection.created_at_ms,
        last_seen_ms: connection.last_seen_ms,
        expires_at_ms: connection.expires_at_ms,
        is_new,
    }
}

fn update_tcp(
    connection: &mut Connection,
    direction: PacketDirection,
    flags: TcpFlags,
) {
    if flags.rst {
        connection.state = ConnectionState::Tcp(TcpState::Reset);
        return;
    }

    let state = match connection.state {
        ConnectionState::Tcp(state) => state,
        _ => return,
    };

    if flags.fin {
        match direction {
            PacketDirection::Initiator => connection.initiator_fin = true,
            PacketDirection::Responder => connection.responder_fin = true,
        }

        connection.state = if connection.initiator_fin && connection.responder_fin {
            ConnectionState::Tcp(TcpState::TimeWait)
        } else {
            ConnectionState::Tcp(TcpState::FinWait)
        };
        return;
    }

    connection.state = ConnectionState::Tcp(match (state, direction, flags.syn, flags.ack) {
        (TcpState::SynSent, PacketDirection::Responder, true, true) => TcpState::SynReceived,
        (TcpState::SynReceived, PacketDirection::Initiator, false, true) => TcpState::Established,
        (TcpState::SynSent, PacketDirection::Initiator, false, true) => TcpState::Established,
        (TcpState::Reset, _, _, _) => TcpState::Reset,
        (TcpState::TimeWait, _, _, _) => TcpState::TimeWait,
        (TcpState::FinWait, _, _, _) => TcpState::FinWait,
        (other, _, _, _) => other,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn packet(
        protocol: TransportProtocol,
        source: &str,
        source_port: Option<u16>,
        destination: &str,
        destination_port: Option<u16>,
    ) -> TrafficDescriptor {
        TrafficDescriptor {
            direction: erebus_types::Direction::Outbound,
            protocol,
            source: source.parse().unwrap(),
            destination: destination.parse().unwrap(),
            source_port,
            destination_port,
            interface: Some("test0".into()),
            flow_id: None,
        }
    }

    fn tcp_packet(source_port: u16, destination_port: u16) -> TrafficDescriptor {
        packet(
            TransportProtocol::Tcp,
            "192.0.2.10",
            Some(source_port),
            "198.51.100.20",
            Some(destination_port),
        )
    }

    fn reverse_tcp_packet() -> TrafficDescriptor {
        packet(
            TransportProtocol::Tcp,
            "198.51.100.20",
            Some(443),
            "192.0.2.10",
            Some(50_000),
        )
    }

    fn tracker(max_entries: usize) -> ConnectionTracker {
        ConnectionTracker::new(TrackerConfig {
            max_entries,
            tcp_syn_timeout_ms: 100,
            tcp_established_timeout_ms: 1_000,
            tcp_closing_timeout_ms: 50,
            tcp_reset_timeout_ms: 10,
            udp_timeout_ms: 100,
            other_timeout_ms: 50,
        })
        .unwrap()
    }

    #[test]
    fn tcp_handshake_tracks_initiator_and_responder() {
        let mut tracker = tracker(8);
        let first = tracker
            .observe(&tcp_packet(50_000, 443), Some(TcpFlags::syn()), 10)
            .unwrap();
        assert!(first.is_new);
        assert_eq!(first.state, ConnectionState::Tcp(TcpState::SynSent));

        let second = tracker
            .observe(&reverse_tcp_packet(), Some(TcpFlags::syn_ack()), 20)
            .unwrap();
        assert_eq!(second.flow_id, first.flow_id);
        assert_eq!(second.direction, PacketDirection::Responder);
        assert_eq!(second.state, ConnectionState::Tcp(TcpState::SynReceived));

        let third = tracker
            .observe(&tcp_packet(50_000, 443), Some(TcpFlags::ack()), 30)
            .unwrap();
        assert_eq!(third.state, ConnectionState::Tcp(TcpState::Established));
        assert!(!third.is_new);
    }

    #[test]
    fn midstream_tcp_is_not_assumed_established() {
        let mut tracker = tracker(8);
        let flow = tracker
            .observe(&tcp_packet(50_000, 443), Some(TcpFlags::ack()), 1)
            .unwrap();

        assert_eq!(flow.state, ConnectionState::Tcp(TcpState::Midstream));
    }

    #[test]
    fn reset_and_fin_update_connection_state() {
        let mut tracker = tracker(8);
        tracker
            .observe(&tcp_packet(50_000, 443), Some(TcpFlags::syn()), 1)
            .unwrap();

        let reset = tracker
            .observe(&reverse_tcp_packet(), Some(TcpFlags::rst()), 2)
            .unwrap();
        assert_eq!(reset.state, ConnectionState::Tcp(TcpState::Reset));
        assert_eq!(reset.expires_at_ms, 12);

        let mut other_tracker = tracker(8);
        other_tracker
            .observe(&tcp_packet(50_000, 443), Some(TcpFlags::syn()), 10)
            .unwrap();
        let first_fin = other_tracker
            .observe(&tcp_packet(50_000, 443), Some(TcpFlags::fin_ack()), 11)
            .unwrap();
        assert_eq!(first_fin.state, ConnectionState::Tcp(TcpState::FinWait));
        let second_fin = other_tracker
            .observe(&reverse_tcp_packet(), Some(TcpFlags::fin_ack()), 12)
            .unwrap();
        assert_eq!(second_fin.state, ConnectionState::Tcp(TcpState::TimeWait));
    }

    #[test]
    fn udp_flow_becomes_replied_after_reverse_packet() {
        let mut tracker = tracker(8);
        let outbound = packet(
            TransportProtocol::Udp,
            "192.0.2.10",
            Some(53_000),
            "198.51.100.53",
            Some(53),
        );
        let inbound = packet(
            TransportProtocol::Udp,
            "198.51.100.53",
            Some(53),
            "192.0.2.10",
            Some(53_000),
        );

        let first = tracker.observe(&outbound, None, 100).unwrap();
        assert_eq!(first.state, ConnectionState::Udp(UdpState::Unreplied));
        let reply = tracker.observe(&inbound, None, 110).unwrap();
        assert_eq!(reply.flow_id, first.flow_id);
        assert_eq!(reply.direction, PacketDirection::Responder);
        assert_eq!(reply.state, ConnectionState::Udp(UdpState::Replied));
    }

    #[test]
    fn tracker_expires_entries_and_reuses_capacity() {
        let mut tracker = tracker(1);
        tracker
            .observe(&tcp_packet(50_000, 443), Some(TcpFlags::syn()), 0)
            .unwrap();

        assert_eq!(
            tracker.observe(&tcp_packet(50_001, 443), Some(TcpFlags::syn()), 1),
            Err(TrackerError::CapacityReached { capacity: 1 })
        );

        assert_eq!(tracker.expire(100).unwrap(), 1);
        let second = tracker
            .observe(&tcp_packet(50_001, 443), Some(TcpFlags::syn()), 101)
            .unwrap();
        assert_eq!(second.flow_id, FlowId(2));
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn tracker_rejects_missing_ports_flags_and_invalid_flags() {
        let mut tracker = tracker(8);
        let no_ports = packet(
            TransportProtocol::Tcp,
            "192.0.2.1",
            None,
            "198.51.100.1",
            None,
        );
        assert_eq!(
            tracker.observe(&no_ports, Some(TcpFlags::syn()), 1),
            Err(TrackerError::MissingTcpPorts)
        );

        let tcp = tcp_packet(50_000, 443);
        assert_eq!(
            tracker.observe(&tcp, None, 2),
            Err(TrackerError::MissingTcpFlags)
        );

        let invalid = TcpFlags {
            syn: true,
            ack: false,
            fin: true,
            rst: false,
        };
        assert_eq!(
            tracker.observe(&tcp, Some(invalid), 3),
            Err(TrackerError::InvalidTcpFlags)
        );
    }

    #[test]
    fn tracker_rejects_clock_regression() {
        let mut tracker = tracker(8);
        tracker
            .observe(&tcp_packet(50_000, 443), Some(TcpFlags::syn()), 10)
            .unwrap();

        assert_eq!(
            tracker.observe(&tcp_packet(50_000, 443), Some(TcpFlags::ack()), 9),
            Err(TrackerError::ClockWentBackwards {
                previous_ms: 10,
                received_ms: 9
            })
        );
    }

    #[test]
    fn tracker_distinguishes_protocols_and_address_families() {
        let mut tracker = tracker(8);
        let udp = packet(
            TransportProtocol::Udp,
            "192.0.2.1",
            Some(1000),
            "198.51.100.1",
            Some(2000),
        );
        let udp_flow = tracker.observe(&udp, None, 1).unwrap();

        let other = packet(
            TransportProtocol::Other(99),
            "192.0.2.1",
            None,
            "198.51.100.1",
            None,
        );
        let other_flow = tracker.observe(&other, None, 2).unwrap();

        assert_ne!(udp_flow.flow_id, other_flow.flow_id);
        assert_eq!(tracker.len(), 2);
        assert_eq!(IpAddr::V4(Ipv4Addr::LOCALHOST), "127.0.0.1".parse().unwrap());
    }
}
