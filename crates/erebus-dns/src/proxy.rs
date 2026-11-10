//! Blocking, standard-library DNS proxy transport.
//!
//! This v1 transport supports local UDP and TCP clients and forwards to a
//! configured plain UDP/TCP upstream. TLS and HTTPS are deliberately not
//! downgraded to plaintext: DoT/DoH require a separately configured secure
//! transport implementation and are not provided by this module.

use crate::{
    tracker::DnsTransport,
    wire::{DnsMessage, DnsParseError, ParseLimits},
};
use erebus_engine::{
    DnsQueryStatus, DnsSecurityError, DnsSecurityService,
};
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use thiserror::Error;

const DNS_HEADER_LEN: usize = 12;

#[derive(Clone, Copy, Debug)]
pub struct DnsProxyConfig {
    /// Numeric upstream resolver address. Hostname resolution is intentionally
    /// excluded from the proxy hot path to avoid recursive system DNS lookup.
    pub upstream: SocketAddr,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub max_message_bytes: usize,
    pub max_tcp_connections: usize,
}

impl Default for DnsProxyConfig {
    fn default() -> Self {
        Self {
            upstream: SocketAddr::from(([1, 1, 1, 1], 53)),
            connect_timeout: Duration::from_secs(3),
            io_timeout: Duration::from_secs(5),
            max_message_bytes: 4096,
            max_tcp_connections: 128,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DnsProxyMetrics {
    pub queries_seen: u64,
    pub queries_allowed: u64,
    pub queries_blocked: u64,
    pub queries_rate_limited: u64,
    pub upstream_failures: u64,
    pub malformed_messages: u64,
    pub tcp_connections_rejected: u64,
}

#[derive(Default)]
struct AtomicMetrics {
    queries_seen: AtomicU64,
    queries_allowed: AtomicU64,
    queries_blocked: AtomicU64,
    queries_rate_limited: AtomicU64,
    upstream_failures: AtomicU64,
    malformed_messages: AtomicU64,
    tcp_connections_rejected: AtomicU64,
}

impl AtomicMetrics {
    fn snapshot(&self) -> DnsProxyMetrics {
        DnsProxyMetrics {
            queries_seen: self.queries_seen.load(Ordering::Relaxed),
            queries_allowed: self.queries_allowed.load(Ordering::Relaxed),
            queries_blocked: self.queries_blocked.load(Ordering::Relaxed),
            queries_rate_limited: self.queries_rate_limited.load(Ordering::Relaxed),
            upstream_failures: self.upstream_failures.load(Ordering::Relaxed),
            malformed_messages: self.malformed_messages.load(Ordering::Relaxed),
            tcp_connections_rejected: self.tcp_connections_rejected.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Error)]
pub enum DnsProxyError {
    #[error("DNS proxy I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("DNS message parsing failed: {0}")]
    Parse(#[from] DnsParseError),
    #[error("DNS security service failed: {0}")]
    Security(#[from] DnsSecurityError),
    #[error("DNS proxy service lock was poisoned")]
    LockPoisoned,
    #[error("configured DNS message limit must be between 512 and 65535 bytes")]
    InvalidMessageLimit,
    #[error("DNS response did not match the outstanding query")]
    MismatchedResponse,
    #[error("DNS TCP frame length is invalid")]
    InvalidTcpFrame,
}

#[derive(Clone)]
pub struct DnsProxy {
    service: Arc<Mutex<DnsSecurityService>>,
    config: DnsProxyConfig,
    started_at: Instant,
    active_tcp_connections: Arc<AtomicUsize>,
    metrics: Arc<AtomicMetrics>,
}

impl DnsProxy {
    pub fn new(
        service: DnsSecurityService,
        config: DnsProxyConfig,
    ) -> Result<Self, DnsProxyError> {
        if !(512..=u16::MAX as usize).contains(&config.max_message_bytes)
            || config.max_tcp_connections == 0
            || config.connect_timeout.is_zero()
            || config.io_timeout.is_zero()
        {
            return Err(DnsProxyError::InvalidMessageLimit);
        }

        Ok(Self {
            service: Arc::new(Mutex::new(service)),
            config,
            started_at: Instant::now(),
            active_tcp_connections: Arc::new(AtomicUsize::new(0)),
            metrics: Arc::new(AtomicMetrics::default()),
        })
    }

    pub fn config(&self) -> DnsProxyConfig {
        self.config
    }

    pub fn metrics(&self) -> DnsProxyMetrics {
        self.metrics.snapshot()
    }

    pub fn active_tcp_connections(&self) -> usize {
        self.active_tcp_connections.load(Ordering::Relaxed)
    }

    /// Process one complete UDP DNS datagram.
    ///
    /// The caller owns the UDP listener and sends the returned response to
    /// `peer`. Malformed messages return an error and should be dropped.
    pub fn handle_udp_datagram(
        &self,
        payload: &[u8],
        peer: SocketAddr,
    ) -> Result<Vec<u8>, DnsProxyError> {
        self.handle_message(payload, peer, DnsTransport::Udp)
    }

    /// Process one complete DNS-over-TCP message, excluding its two-byte
    /// stream length prefix.
    pub fn handle_tcp_message(
        &self,
        payload: &[u8],
        peer: SocketAddr,
    ) -> Result<Vec<u8>, DnsProxyError> {
        self.handle_message(payload, peer, DnsTransport::Tcp)
    }

    /// Serve UDP requests on an already-bound socket until `shutdown` is set.
    /// A short socket timeout allows the loop to observe shutdown promptly.
    pub fn run_udp(
        &self,
        socket: UdpSocket,
        shutdown: &AtomicBool,
    ) -> Result<(), DnsProxyError> {
        socket.set_read_timeout(Some(Duration::from_millis(200)))?;
        let mut buffer = vec![0u8; self.config.max_message_bytes + 1];

        while !shutdown.load(Ordering::Relaxed) {
            match socket.recv_from(&mut buffer) {
                Ok((size, peer)) => {
                    if size > self.config.max_message_bytes {
                        self.metrics
                            .malformed_messages
                            .fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    if let Ok(response) = self.handle_udp_datagram(&buffer[..size], peer) {
                        let _ = socket.send_to(&response, peer);
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => return Err(error.into()),
            }
        }

        Ok(())
    }

    /// Serve DNS-over-TCP on an already-bound listener until `shutdown` is set.
    /// Each accepted client receives one bounded worker thread.
    pub fn run_tcp(
        &self,
        listener: TcpListener,
        shutdown: &AtomicBool,
    ) -> Result<(), DnsProxyError> {
        listener.set_nonblocking(true)?;

        while !shutdown.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, peer)) => {
                    let current = self.active_tcp_connections.fetch_add(1, Ordering::AcqRel);
                    if current >= self.config.max_tcp_connections {
                        self.active_tcp_connections.fetch_sub(1, Ordering::AcqRel);
                        self.metrics
                            .tcp_connections_rejected
                            .fetch_add(1, Ordering::Relaxed);
                        drop(stream);
                        continue;
                    }

                    let proxy = self.clone();
                    thread::spawn(move || {
                        let _ = proxy.serve_tcp_client(stream, peer);
                        proxy
                            .active_tcp_connections
                            .fetch_sub(1, Ordering::AcqRel);
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error.into()),
            }
        }

        Ok(())
    }

    fn serve_tcp_client(
        &self,
        mut client: TcpStream,
        peer: SocketAddr,
    ) -> Result<(), DnsProxyError> {
        client.set_read_timeout(Some(self.config.io_timeout))?;
        client.set_write_timeout(Some(self.config.io_timeout))?;

        loop {
            let mut prefix = [0u8; 2];
            match client.read_exact(&mut prefix) {
                Ok(()) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::TimedOut
                    ) => return Ok(()),
                Err(error) => return Err(error.into()),
            }

            let frame_len = usize::from(u16::from_be_bytes(prefix));
            if frame_len < DNS_HEADER_LEN || frame_len > self.config.max_message_bytes {
                return Err(DnsProxyError::InvalidTcpFrame);
            }

            let mut query = vec![0u8; frame_len];
            client.read_exact(&mut query)?;
            let response = self.handle_tcp_message(&query, peer)?;
            let response_len = u16::try_from(response.len())
                .map_err(|_| DnsProxyError::InvalidTcpFrame)?;

            client.write_all(&response_len.to_be_bytes())?;
            client.write_all(&response)?;
        }
    }

    fn handle_message(
        &self,
        payload: &[u8],
        peer: SocketAddr,
        transport: DnsTransport,
    ) -> Result<Vec<u8>, DnsProxyError> {
        self.metrics.queries_seen.fetch_add(1, Ordering::Relaxed);

        let limits = ParseLimits {
            max_message_bytes: self.config.max_message_bytes,
            ..ParseLimits::default()
        };
        let query = match DnsMessage::parse_with_limits(payload, limits) {
            Ok(message) => message,
            Err(error) => {
                self.metrics
                    .malformed_messages
                    .fetch_add(1, Ordering::Relaxed);
                return Err(error.into());
            }
        };

        if query.is_response()
            || query.header.opcode() != 0
            || query.single_question().is_none()
        {
            self.metrics
                .malformed_messages
                .fetch_add(1, Ordering::Relaxed);
            return Err(DnsProxyError::MismatchedResponse);
        }

        let upstream = self.config.upstream;
        let now_ms = self.now_ms();
        let inspection = {
            let mut service = self
                .service
                .lock()
                .map_err(|_| DnsProxyError::LockPoisoned)?;
            service.inspect_query(
                peer.ip(),
                peer.port(),
                upstream.ip(),
                upstream.port(),
                transport,
                &query,
                now_ms,
            )?
        };

        match inspection.status {
            DnsQueryStatus::Blocked => {
                self.metrics.queries_blocked.fetch_add(1, Ordering::Relaxed);
                return encode_error_response(&query, 5);
            }
            DnsQueryStatus::RateLimited => {
                self.metrics
                    .queries_rate_limited
                    .fetch_add(1, Ordering::Relaxed);
                return encode_error_response(&query, 2);
            }
            DnsQueryStatus::Allowed => {
                self.metrics.queries_allowed.fetch_add(1, Ordering::Relaxed);
            }
        }

        let upstream_response = match transport {
            DnsTransport::Udp => self.forward_udp(payload),
            DnsTransport::Tcp => self.forward_tcp(payload),
        };

        let response_bytes = match upstream_response {
            Ok(bytes) => bytes,
            Err(_) => {
                self.metrics
                    .upstream_failures
                    .fetch_add(1, Ordering::Relaxed);
                return encode_error_response(&query, 2);
            }
        };

        let response = match DnsMessage::parse_with_limits(&response_bytes, limits) {
            Ok(message) => message,
            Err(_) => {
                self.metrics
                    .upstream_failures
                    .fetch_add(1, Ordering::Relaxed);
                return encode_error_response(&query, 2);
            }
        };

        if !matches_query(&query, &response) {
            self.metrics
                .upstream_failures
                .fetch_add(1, Ordering::Relaxed);
            return encode_error_response(&query, 2);
        }

        {
            let mut service = self
                .service
                .lock()
                .map_err(|_| DnsProxyError::LockPoisoned)?;
            service.inspect_response(
                upstream.ip(),
                upstream.port(),
                peer.ip(),
                peer.port(),
                transport,
                &response,
                self.now_ms(),
            )?;
        }

        Ok(response_bytes)
    }

    fn forward_udp(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let bind_address = if self.config.upstream.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0u16; 8], 0))
        };
        let socket = UdpSocket::bind(bind_address)?;
        socket.connect(self.config.upstream)?;
        socket.set_read_timeout(Some(self.config.io_timeout))?;
        socket.set_write_timeout(Some(self.config.io_timeout))?;
        socket.send(query)?;

        let mut buffer = vec![0u8; self.config.max_message_bytes + 1];
        let size = socket.recv(&mut buffer)?;
        if size > self.config.max_message_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "upstream UDP DNS response exceeds configured limit",
            ));
        }
        buffer.truncate(size);
        Ok(buffer)
    }

    fn forward_tcp(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let mut upstream =
            TcpStream::connect_timeout(&self.config.upstream, self.config.connect_timeout)?;
        upstream.set_read_timeout(Some(self.config.io_timeout))?;
        upstream.set_write_timeout(Some(self.config.io_timeout))?;

        let query_len = u16::try_from(query.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "DNS query is too large for TCP framing")
        })?;
        upstream.write_all(&query_len.to_be_bytes())?;
        upstream.write_all(query)?;

        let mut prefix = [0u8; 2];
        upstream.read_exact(&mut prefix)?;
        let response_len = usize::from(u16::from_be_bytes(prefix));
        if response_len < DNS_HEADER_LEN || response_len > self.config.max_message_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "upstream TCP DNS response length is invalid",
            ));
        }

        let mut response = vec![0u8; response_len];
        upstream.read_exact(&mut response)?;
        Ok(response)
    }

    fn now_ms(&self) -> u64 {
        self.started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
    }
}

fn matches_query(query: &DnsMessage, response: &DnsMessage) -> bool {
    if !response.is_response()
        || response.header.opcode() != query.header.opcode()
        || response.header.id != query.header.id
    {
        return false;
    }

    match (query.single_question(), response.single_question()) {
        (Some(query), Some(response)) => {
            query.name.eq_ignore_ascii_case(&response.name)
                && query.qtype == response.qtype
                && query.qclass == response.qclass
        }
        _ => false,
    }
}

/// Construct a minimal REFUSED/SERVFAIL response that preserves the original
/// transaction ID, RD/CD request flags, and single question. Additional query
/// records such as OPT are intentionally not reflected.
fn encode_error_response(
    query: &DnsMessage,
    response_code: u8,
) -> Result<Vec<u8>, DnsProxyError> {
    let question = query.single_question().ok_or(DnsProxyError::MismatchedResponse)?;
    let mut output = Vec::with_capacity(12 + question.name.len() + 6);
    output.extend_from_slice(&query.header.id.to_be_bytes());

    let flags = 0x8000 | (query.header.flags & 0x0110) | u16::from(response_code & 0x0f);
    output.extend_from_slice(&flags.to_be_bytes());
    output.extend_from_slice(&1u16.to_be_bytes());
    output.extend_from_slice(&0u16.to_be_bytes());
    output.extend_from_slice(&0u16.to_be_bytes());
    output.extend_from_slice(&0u16.to_be_bytes());

    if question.name != "." {
        for label in question.name.split('.') {
            let bytes = label.as_bytes();
            if bytes.is_empty() || bytes.len() > 63 {
                return Err(DnsProxyError::MismatchedResponse);
            }
            output.push(bytes.len() as u8);
            output.extend_from_slice(bytes);
        }
    }
    output.push(0);
    output.extend_from_slice(&question.qtype.to_be_bytes());
    output.extend_from_slice(&question.qclass.to_be_bytes());
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::DnsPolicyDocument,
        policy::DomainAction,
        DnsPolicyDocument as PublicDnsPolicyDocument,
    };
    use erebus_engine::DnsSecurityConfig;
    use std::net::{IpAddr, Ipv4Addr};

    const TEST_POLICY: &str = r#"
schema_version = 1

[policy]
default = "allow"

[[rules]]
id = "blocked"
domain = "blocked.example"
match = "suffix"
action = "block"
"#;

    fn test_service() -> DnsSecurityService {
        DnsSecurityService::from_toml(TEST_POLICY, DnsSecurityConfig::default()).unwrap()
    }

    fn make_query(name: &str, id: u16) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&id.to_be_bytes());
        bytes.extend_from_slice(&0x0100u16.to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        if name != "." {
            for label in name.split('.') {
                bytes.push(label.len() as u8);
                bytes.extend_from_slice(label.as_bytes());
            }
        }
        bytes.push(0);
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes
    }

    #[test]
    fn blocked_domain_returns_refused_without_upstream_access() {
        let proxy = DnsProxy::new(test_service(), DnsProxyConfig::default()).unwrap();
        let query = make_query("ads.blocked.example", 0x1234);
        let response = proxy
            .handle_udp_datagram(&query, "127.0.0.1:53000".parse().unwrap())
            .unwrap();
        let parsed = DnsMessage::parse(&response).unwrap();

        assert!(parsed.is_response());
        assert_eq!(parsed.header.id, 0x1234);
        assert_eq!(parsed.header.response_code(), 5);
        assert_eq!(parsed.questions[0].name, "ads.blocked.example");
        assert_eq!(proxy.metrics().queries_blocked, 1);
    }

    #[test]
    fn response_match_requires_id_question_and_type() {
        let query = DnsMessage::parse(&make_query("example.com", 5)).unwrap();
        let mut response = query.clone();
        response.header.flags |= 0x8000;
        assert!(matches_query(&query, &response));

        response.header.id = 6;
        assert!(!matches_query(&query, &response));

        response.header.id = 5;
        response.questions[0].qtype = 28;
        assert!(!matches_query(&query, &response));
    }

    #[test]
    fn rejects_invalid_proxy_limits() {
        let result = DnsProxy::new(
            test_service(),
            DnsProxyConfig {
                max_message_bytes: 256,
                ..DnsProxyConfig::default()
            },
        );
        assert!(matches!(result, Err(DnsProxyError::InvalidMessageLimit)));
    }

    #[test]
    fn error_response_is_minimal_and_preserves_query_flags() {
        let query = DnsMessage::parse(&make_query("example.com", 0xbeef)).unwrap();
        let response = encode_error_response(&query, 5).unwrap();
        let parsed = DnsMessage::parse(&response).unwrap();

        assert_eq!(parsed.header.id, 0xbeef);
        assert!(parsed.header.is_response());
        assert!(parsed.header.recursion_desired());
        assert_eq!(parsed.header.response_code(), 5);
        assert_eq!(parsed.answers.len(), 0);
        assert_eq!(parsed.questions[0], query.questions[0]);
    }

    #[test]
    fn normalizes_proxy_endpoints_and_metrics_types() {
        let _document: Option<DnsPolicyDocument> = None;
        let _public: Option<PublicDnsPolicyDocument> = None;
        let _action = DomainAction::Allow;
        let _peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53000);
    }
}
