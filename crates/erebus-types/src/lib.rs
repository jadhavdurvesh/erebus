//! Platform-neutral types shared by EREBUS components.
//!
//! These are metadata structures, not raw packet parsers. Platform adapters
//! are responsible for safely obtaining and normalizing this information.

use serde::{Deserialize, Serialize};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

/// Errors returned while constructing or parsing an IP network prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpNetworkError {
    MissingPrefix,
    InvalidAddress,
    InvalidPrefix,
    PrefixTooLong { maximum: u8, supplied: u8 },
}

impl fmt::Display for IpNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPrefix => write!(f, "network prefix is missing '/' and a prefix length"),
            Self::InvalidAddress => write!(f, "invalid IP address"),
            Self::InvalidPrefix => write!(f, "invalid network prefix length"),
            Self::PrefixTooLong { maximum, supplied } => {
                write!(f, "prefix length {supplied} exceeds maximum {maximum}")
            }
        }
    }
}

impl std::error::Error for IpNetworkError {}

/// A canonical IPv4 or IPv6 network prefix.
///
/// The stored address is normalized to the network boundary. For example,
/// 192.0.2.42/24 is stored and displayed as 192.0.2.0/24.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct IpNetwork {
    network: IpAddr,
    prefix_len: u8,
}

impl IpNetwork {
    pub fn new(address: IpAddr, prefix_len: u8) -> Result<Self, IpNetworkError> {
        let network = match address {
            IpAddr::V4(address) => {
                if prefix_len > 32 {
                    return Err(IpNetworkError::PrefixTooLong {
                        maximum: 32,
                        supplied: prefix_len,
                    });
                }
                let mask = if prefix_len == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix_len)
                };
                IpAddr::V4(Ipv4Addr::from(u32::from(address) & mask))
            }
            IpAddr::V6(address) => {
                if prefix_len > 128 {
                    return Err(IpNetworkError::PrefixTooLong {
                        maximum: 128,
                        supplied: prefix_len,
                    });
                }
                let mask = if prefix_len == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix_len)
                };
                IpAddr::V6(Ipv6Addr::from(u128::from(address) & mask))
            }
        };

        Ok(Self {
            network,
            prefix_len,
        })
    }

    pub fn network_address(self) -> IpAddr {
        self.network
    }

    pub fn prefix_len(self) -> u8 {
        self.prefix_len
    }

    /// Returns true only when the candidate belongs to this prefix and uses
    /// the same address family.
    pub fn contains(self, candidate: IpAddr) -> bool {
        match (self.network, candidate) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                let mask = if self.prefix_len == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix_len)
                };
                (u32::from(candidate) & mask) == u32::from(network)
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                let mask = if self.prefix_len == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix_len)
                };
                (u128::from(candidate) & mask) == u128::from(network)
            }
            _ => false,
        }
    }
}

impl FromStr for IpNetwork {
    type Err = IpNetworkError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = value.split_once('/').ok_or(IpNetworkError::MissingPrefix)?;
        let address = IpAddr::from_str(address).map_err(|_| IpNetworkError::InvalidAddress)?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| IpNetworkError::InvalidPrefix)?;
        Self::new(address, prefix)
    }
}

impl fmt::Display for IpNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

/// Stable identifier assigned to a flow by an adapter or connection tracker.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct FlowId(pub u64);

/// Network transport protocol relevant to a policy decision.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
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

#[cfg(test)]
mod network_tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn ipv4_prefix_normalizes_host_bits_and_matches_members() {
        let network: IpNetwork = "192.0.2.42/24".parse().expect("valid IPv4 prefix");

        assert_eq!(network.to_string(), "192.0.2.0/24");
        assert!(network.contains(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        assert!(network.contains(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254))));
        assert!(!network.contains(IpAddr::V4(Ipv4Addr::new(192, 0, 3, 1))));
    }

    #[test]
    fn ipv6_prefix_matches_members_and_rejects_neighbours() {
        let network: IpNetwork = "2001:db8:abcd::1/48".parse().expect("valid IPv6 prefix");

        assert_eq!(network.to_string(), "2001:db8:abcd::/48");
        assert!(network.contains(IpAddr::V6("2001:db8:abcd:1::10".parse().unwrap())));
        assert!(!network.contains(IpAddr::V6("2001:db8:abce::1".parse().unwrap())));
    }

    #[test]
    fn zero_length_prefix_matches_entire_address_family() {
        let network: IpNetwork = "0.0.0.0/0".parse().expect("valid IPv4 default prefix");
        assert!(network.contains(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!network.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn invalid_prefix_lengths_are_rejected() {
        assert_eq!(
            IpNetwork::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33),
            Err(IpNetworkError::PrefixTooLong {
                maximum: 32,
                supplied: 33
            })
        );
        assert_eq!(
            IpNetwork::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 129),
            Err(IpNetworkError::PrefixTooLong {
                maximum: 128,
                supplied: 129
            })
        );
    }

    #[test]
    fn malformed_network_strings_are_rejected() {
        assert_eq!(
            "192.0.2.0".parse::<IpNetwork>(),
            Err(IpNetworkError::MissingPrefix)
        );
        assert_eq!(
            "not-an-ip/24".parse::<IpNetwork>(),
            Err(IpNetworkError::InvalidAddress)
        );
        assert_eq!(
            "192.0.2.0/nope".parse::<IpNetwork>(),
            Err(IpNetworkError::InvalidPrefix)
        );
    }
}
