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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsUpstreamProtocol {
    Udp,
    Tcp,
    Dot,
    Doh,
}

#[derive(Clone, Debug)]
pub struct DnsProxyConfig {
    /// Numeric upstream resolver address. Hostname resolution is intentionally
    /// excluded from the proxy hot path to avoid recursive system DNS lookup.
    pub upstream: SocketAddr,
    pub upstream_protocol: DnsUpstreamProtocol,
    /// Required for DoT; this is verified against the upstream certificate.
    pub tls_server_name: Option<String>,
    /// Required for DoH; only HTTPS URLs are accepted.
    pub https_url: Option<String>,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub max_message_bytes: usize,
    pub max_tcp_connections: usize,
}

impl Default for DnsProxyConfig {
    fn default() -> Self {
        Self {
            upstream: SocketAddr::from(([1, 1, 1, 1], 53)),
            upstream_protocol: DnsUpstreamProtocol::Udp,
            tls_server_name: None,
            https_url: None,
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
    #[error("DNS proxy service lock was poisoned")]
    LockPoisoned,
    #[error("DNS security policy inspection failed")]
    PolicyInspectionFailed,
    #[error("configured DNS message limit must be between 512 and 65535 bytes")]
    InvalidMessageLimit,
    #[error("DNS response did not match the outstanding query")]
    MismatchedResponse,
    #[error("DNS TCP frame length is invalid")]
    InvalidTcpFrame,
    #[error("DoT requires a valid TLS server name for certificate verification")]
    MissingTlsServerName,
    #[error("DoH requires a valid HTTPS URL with a hostname and no user-info or fragment")]
    InvalidHttpsUrl,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsExchange {
    pub client: SocketAddr,
    pub resolver: SocketAddr,
    pub transport: DnsTransport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsProxyDecision {
    Allowed,
    Blocked,
    RateLimited,
}

#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
#[error("DNS proxy policy inspection failed")]
pub struct DnsProxyPolicyError;

/// Adapter contract between the independent DNS transport and a policy engine.
/// Implementations receive already-parsed messages and must not perform I/O.
pub trait DnsProxyPolicy: Send {
    fn inspect_query(
        &mut self,
        exchange: DnsExchange,
        message: &DnsMessage,
        now_ms: u64,
    ) -> Result<DnsProxyDecision, DnsProxyPolicyError>;

    fn inspect_response(
        &mut self,
        exchange: DnsExchange,
        message: &DnsMessage,
        now_ms: u64,
    ) -> Result<(), DnsProxyPolicyError>;
}

pub struct DnsProxy<P: DnsProxyPolicy> {
    service: Arc<Mutex<P>>,
    config: DnsProxyConfig,
    doh_client: Option<reqwest::blocking::Client>,
    started_at: Instant,
    active_tcp_connections: Arc<AtomicUsize>,
    metrics: Arc<AtomicMetrics>,
}

impl<P: DnsProxyPolicy> Clone for DnsProxy<P> {
    fn clone(&self) -> Self {
        Self {
            service: Arc::clone(&self.service),
            config: self.config.clone(),
            doh_client: self.doh_client.clone(),
            started_at: self.started_at,
            active_tcp_connections: Arc::clone(&self.active_tcp_connections),
            metrics: Arc::clone(&self.metrics),
        }
    }
}

impl<P: DnsProxyPolicy + 'static> DnsProxy<P> {
    pub fn new(service: P, config: DnsProxyConfig) -> Result<Self, DnsProxyError> {
        if !(512..=u16::MAX as usize).contains(&config.max_message_bytes)
            || config.max_tcp_connections == 0
            || config.connect_timeout.is_zero()
            || config.io_timeout.is_zero()
        {
            return Err(DnsProxyError::InvalidMessageLimit);
        }

        match config.upstream_protocol {
            DnsUpstreamProtocol::Dot => {
                let server_name = config
                    .tls_server_name
                    .as_deref()
                    .ok_or(DnsProxyError::MissingTlsServerName)?;
                rustls::pki_types::ServerName::try_from(server_name.to_owned())
                    .map_err(|_| DnsProxyError::MissingTlsServerName)?;
            }
            DnsUpstreamProtocol::Doh => {
                let raw_url = config
                    .https_url
                    .as_deref()
                    .ok_or(DnsProxyError::InvalidHttpsUrl)?;
                let url = url::Url::parse(raw_url).map_err(|_| DnsProxyError::InvalidHttpsUrl)?;
                if url.scheme() != "https"
                    || url.host_str().is_none()
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.fragment().is_some()
                {
                    return Err(DnsProxyError::InvalidHttpsUrl);
                }
            }
            DnsUpstreamProtocol::Udp | DnsUpstreamProtocol::Tcp => {}
        }

        let doh_client = if config.upstream_protocol == DnsUpstreamProtocol::Doh {
            let url = url::Url::parse(config.https_url.as_deref().expect("validated above"))
                .map_err(|_| DnsProxyError::InvalidHttpsUrl)?;
            let host = url.host_str().expect("validated HTTPS host");
            Some(
                reqwest::blocking::Client::builder()
                    .https_only(true)
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .connect_timeout(config.connect_timeout)
                    .timeout(config.io_timeout)
                    // Bootstrap the HTTPS hostname using the configured numeric
                    // resolver address to avoid recursive system DNS lookups.
                    .resolve_to_addrs(host, &[config.upstream])
                    .build()
                    .map_err(|_| DnsProxyError::InvalidHttpsUrl)?,
            )
        } else {
            None
        };

        Ok(Self {
            service: Arc::new(Mutex::new(service)),
            config,
            doh_client,
            started_at: Instant::now(),
            active_tcp_connections: Arc::new(AtomicUsize::new(0)),
            metrics: Arc::new(AtomicMetrics::default()),
        })
    }

    pub fn config(&self) -> DnsProxyConfig {
        self.config.clone()
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
    pub fn run_udp(&self, socket: UdpSocket, shutdown: &AtomicBool) -> Result<(), DnsProxyError> {
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
                        proxy.active_tcp_connections.fetch_sub(1, Ordering::AcqRel);
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
                    ) =>
                {
                    return Ok(());
                }
                Err(error) => return Err(error.into()),
            }

            let frame_len = usize::from(u16::from_be_bytes(prefix));
            if frame_len < DNS_HEADER_LEN || frame_len > self.config.max_message_bytes {
                return Err(DnsProxyError::InvalidTcpFrame);
            }

            let mut query = vec![0u8; frame_len];
            client.read_exact(&mut query)?;
            let response = self.handle_tcp_message(&query, peer)?;
            let response_len =
                u16::try_from(response.len()).map_err(|_| DnsProxyError::InvalidTcpFrame)?;

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

        if query.is_response() || query.header.opcode() != 0 || query.single_question().is_none() {
            self.metrics
                .malformed_messages
                .fetch_add(1, Ordering::Relaxed);
            return Err(DnsProxyError::MismatchedResponse);
        }

        let upstream = self.config.upstream;
        let now_ms = self.now_ms();
        let exchange = DnsExchange {
            client: peer,
            resolver: upstream,
            transport,
        };
        let decision = {
            let mut service = self
                .service
                .lock()
                .map_err(|_| DnsProxyError::LockPoisoned)?;
            service
                .inspect_query(exchange, &query, now_ms)
                .map_err(|_| DnsProxyError::PolicyInspectionFailed)?
        };

        match decision {
            DnsProxyDecision::Blocked => {
                self.metrics.queries_blocked.fetch_add(1, Ordering::Relaxed);
                return encode_error_response(&query, 5);
            }
            DnsProxyDecision::RateLimited => {
                self.metrics
                    .queries_rate_limited
                    .fetch_add(1, Ordering::Relaxed);
                return encode_error_response(&query, 2);
            }
            DnsProxyDecision::Allowed => {
                self.metrics.queries_allowed.fetch_add(1, Ordering::Relaxed);
            }
        }

        let upstream_response = self.forward_upstream(payload);

        let response_bytes = match upstream_response {
            Ok(bytes) => bytes,
            Err(_) => {
                self.metrics
                    .upstream_failures
                    .fetch_add(1, Ordering::Relaxed);
                return self.local_servfail(exchange, &query);
            }
        };

        let response = match DnsMessage::parse_with_limits(&response_bytes, limits) {
            Ok(message) => message,
            Err(_) => {
                self.metrics
                    .upstream_failures
                    .fetch_add(1, Ordering::Relaxed);
                return self.local_servfail(exchange, &query);
            }
        };

        if !matches_query(&query, &response) {
            self.metrics
                .upstream_failures
                .fetch_add(1, Ordering::Relaxed);
            return self.local_servfail(exchange, &query);
        }

        {
            let mut service = self
                .service
                .lock()
                .map_err(|_| DnsProxyError::LockPoisoned)?;
            service
                .inspect_response(exchange, &response, self.now_ms())
                .map_err(|_| DnsProxyError::PolicyInspectionFailed)?;
        }

        Ok(response_bytes)
    }

    fn forward_upstream(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        match self.config.upstream_protocol {
            DnsUpstreamProtocol::Udp => self.forward_udp(query),
            DnsUpstreamProtocol::Tcp => self.forward_tcp(query),
            DnsUpstreamProtocol::Dot => self.forward_dot(query),
            DnsUpstreamProtocol::Doh => self.forward_doh(query),
        }
    }

    fn forward_dot(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let server_name = self.config.tls_server_name.as_deref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing DoT TLS server name")
        })?;
        let server_name =
            rustls::pki_types::ServerName::try_from(server_name.to_owned()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid DoT TLS server name")
            })?;

        let tcp = TcpStream::connect_timeout(&self.config.upstream, self.config.connect_timeout)?;
        tcp.set_read_timeout(Some(self.config.io_timeout))?;
        tcp.set_write_timeout(Some(self.config.io_timeout))?;

        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connection = rustls::ClientConnection::new(Arc::new(tls_config), server_name)
            .map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, error))?;
        let mut stream = rustls::StreamOwned::new(connection, tcp);

        let query_len = u16::try_from(query.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS query exceeds TCP frame size",
            )
        })?;
        stream.write_all(&query_len.to_be_bytes())?;
        stream.write_all(query)?;
        stream.flush()?;

        let mut prefix = [0u8; 2];
        stream.read_exact(&mut prefix)?;
        let response_len = usize::from(u16::from_be_bytes(prefix));
        if response_len < DNS_HEADER_LEN || response_len > self.config.max_message_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DoT response frame length is invalid",
            ));
        }

        let mut response = vec![0u8; response_len];
        stream.read_exact(&mut response)?;
        Ok(response)
    }

    fn forward_doh(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let client = self.doh_client.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "DoH client is not configured")
        })?;
        let endpoint = self.config.https_url.as_deref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "DoH URL is not configured")
        })?;

        let response = client
            .post(endpoint)
            .header(reqwest::header::CONTENT_TYPE, "application/dns-message")
            .header(reqwest::header::ACCEPT, "application/dns-message")
            .body(query.to_vec())
            .send()
            .map_err(io::Error::other)?;

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("DoH upstream returned HTTP {}", response.status()),
            ));
        }

        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim);
        if content_type != Some("application/dns-message") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DoH upstream returned an unexpected content type",
            ));
        }

        if response
            .content_length()
            .is_some_and(|length| length > self.config.max_message_bytes as u64)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DoH response exceeds configured message limit",
            ));
        }

        let mut body = Vec::with_capacity(self.config.max_message_bytes.min(4096));
        response
            .take(self.config.max_message_bytes as u64 + 1)
            .read_to_end(&mut body)?;
        if body.len() > self.config.max_message_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DoH response exceeds configured message limit",
            ));
        }
        Ok(body)
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
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS query is too large for TCP framing",
            )
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

    /// Generate SERVFAIL after an upstream fault and retire the matching
    /// request from the security tracker. Audit/cache errors must not suppress
    /// the local failure reply.
    fn local_servfail(
        &self,
        exchange: DnsExchange,
        query: &DnsMessage,
    ) -> Result<Vec<u8>, DnsProxyError> {
        let bytes = encode_error_response(query, 2)?;
        if let Ok(message) = DnsMessage::parse_with_limits(
            &bytes,
            ParseLimits {
                max_message_bytes: self.config.max_message_bytes,
                ..ParseLimits::default()
            },
        ) {
            if let Ok(mut service) = self.service.lock() {
                let _ = service.inspect_response(exchange, &message, self.now_ms());
            }
        }
        Ok(bytes)
    }

    fn now_ms(&self) -> u64 {
        self.started_at
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64
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
fn encode_error_response(query: &DnsMessage, response_code: u8) -> Result<Vec<u8>, DnsProxyError> {
    let question = query
        .single_question()
        .ok_or(DnsProxyError::MismatchedResponse)?;
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
    use crate::policy::{
        normalize_domain, DomainAction, DomainMatchKind, DomainPattern, DomainPolicy, DomainRule,
    };

    struct TestPolicy {
        policy: DomainPolicy,
    }

    impl DnsProxyPolicy for TestPolicy {
        fn inspect_query(
            &mut self,
            _exchange: DnsExchange,
            message: &DnsMessage,
            _now_ms: u64,
        ) -> Result<DnsProxyDecision, DnsProxyPolicyError> {
            let Some(question) = message.single_question() else {
                return Err(DnsProxyPolicyError);
            };
            let domain = normalize_domain(&question.name).map_err(|_| DnsProxyPolicyError)?;
            let decision = self
                .policy
                .evaluate(&domain)
                .map_err(|_| DnsProxyPolicyError)?;
            Ok(match decision.action {
                DomainAction::Allow => DnsProxyDecision::Allowed,
                DomainAction::Block => DnsProxyDecision::Blocked,
            })
        }

        fn inspect_response(
            &mut self,
            _exchange: DnsExchange,
            _message: &DnsMessage,
            _now_ms: u64,
        ) -> Result<(), DnsProxyPolicyError> {
            Ok(())
        }
    }

    fn test_service() -> TestPolicy {
        TestPolicy {
            policy: DomainPolicy::new(
                DomainAction::Allow,
                vec![DomainRule {
                    id: "blocked".into(),
                    pattern: DomainPattern::new("blocked.example", DomainMatchKind::Suffix)
                        .unwrap(),
                    action: DomainAction::Block,
                }],
            )
            .unwrap(),
        }
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
    fn forwards_udp_queries_to_configured_upstream() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_address = upstream.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut buffer = [0u8; 512];
            let (size, peer) = upstream.recv_from(&mut buffer).unwrap();
            buffer[2] |= 0x80;
            buffer[3] |= 0x80;
            upstream.send_to(&buffer[..size], peer).unwrap();
        });

        let proxy = DnsProxy::new(
            test_service(),
            DnsProxyConfig {
                upstream: upstream_address,
                io_timeout: Duration::from_secs(2),
                ..DnsProxyConfig::default()
            },
        )
        .unwrap();
        let query = make_query("safe.example", 0x4321);
        let response = proxy
            .handle_udp_datagram(&query, "127.0.0.1:53001".parse().unwrap())
            .unwrap();
        worker.join().unwrap();

        let parsed = DnsMessage::parse(&response).unwrap();
        assert!(parsed.is_response());
        assert_eq!(parsed.header.id, 0x4321);
        assert_eq!(proxy.metrics().queries_allowed, 1);
    }

    #[test]
    fn forwards_tcp_queries_with_dns_length_framing() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_address = upstream.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut prefix = [0u8; 2];
            stream.read_exact(&mut prefix).unwrap();
            let size = usize::from(u16::from_be_bytes(prefix));
            let mut query = vec![0u8; size];
            stream.read_exact(&mut query).unwrap();
            query[2] |= 0x80;
            query[3] |= 0x80;
            stream
                .write_all(&(query.len() as u16).to_be_bytes())
                .unwrap();
            stream.write_all(&query).unwrap();
        });

        let proxy = DnsProxy::new(
            test_service(),
            DnsProxyConfig {
                upstream: upstream_address,
                io_timeout: Duration::from_secs(2),
                ..DnsProxyConfig::default()
            },
        )
        .unwrap();
        let query = make_query("safe.example", 0x9876);
        let response = proxy
            .handle_tcp_message(&query, "127.0.0.1:53002".parse().unwrap())
            .unwrap();
        worker.join().unwrap();

        let parsed = DnsMessage::parse(&response).unwrap();
        assert!(parsed.is_response());
        assert_eq!(parsed.header.id, 0x9876);
        assert_eq!(proxy.metrics().queries_allowed, 1);
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
    fn secure_upstreams_require_explicit_server_identity_and_endpoint() {
        let dot = DnsProxy::new(
            test_service(),
            DnsProxyConfig {
                upstream_protocol: DnsUpstreamProtocol::Dot,
                ..DnsProxyConfig::default()
            },
        );
        assert!(matches!(dot, Err(DnsProxyError::MissingTlsServerName)));

        let bad_dot = DnsProxy::new(
            test_service(),
            DnsProxyConfig {
                upstream_protocol: DnsUpstreamProtocol::Dot,
                tls_server_name: Some("not a valid name".into()),
                ..DnsProxyConfig::default()
            },
        );
        assert!(matches!(bad_dot, Err(DnsProxyError::MissingTlsServerName)));

        let doh = DnsProxy::new(
            test_service(),
            DnsProxyConfig {
                upstream_protocol: DnsUpstreamProtocol::Doh,
                ..DnsProxyConfig::default()
            },
        );
        assert!(matches!(doh, Err(DnsProxyError::InvalidHttpsUrl)));

        let plaintext_url = DnsProxy::new(
            test_service(),
            DnsProxyConfig {
                upstream_protocol: DnsUpstreamProtocol::Doh,
                https_url: Some("http://resolver.example/dns-query".into()),
                ..DnsProxyConfig::default()
            },
        );
        assert!(matches!(plaintext_url, Err(DnsProxyError::InvalidHttpsUrl)));

        let credential_url = DnsProxy::new(
            test_service(),
            DnsProxyConfig {
                upstream_protocol: DnsUpstreamProtocol::Doh,
                https_url: Some("https://user:password@resolver.example/dns-query".into()),
                ..DnsProxyConfig::default()
            },
        );
        assert!(matches!(
            credential_url,
            Err(DnsProxyError::InvalidHttpsUrl)
        ));

        let fragment_url = DnsProxy::new(
            test_service(),
            DnsProxyConfig {
                upstream_protocol: DnsUpstreamProtocol::Doh,
                https_url: Some("https://resolver.example/dns-query#fragment".into()),
                ..DnsProxyConfig::default()
            },
        );
        assert!(matches!(fragment_url, Err(DnsProxyError::InvalidHttpsUrl)));
    }

    #[test]
    fn valid_dot_and_doh_configuration_is_accepted_without_plaintext_fallback() {
        let dot = DnsProxy::new(
            test_service(),
            DnsProxyConfig {
                upstream: "1.1.1.1:853".parse().unwrap(),
                upstream_protocol: DnsUpstreamProtocol::Dot,
                tls_server_name: Some("cloudflare-dns.com".into()),
                ..DnsProxyConfig::default()
            },
        )
        .unwrap();
        assert_eq!(dot.config().upstream_protocol, DnsUpstreamProtocol::Dot);

        let doh = DnsProxy::new(
            test_service(),
            DnsProxyConfig {
                upstream: "1.1.1.1:443".parse().unwrap(),
                upstream_protocol: DnsUpstreamProtocol::Doh,
                https_url: Some("https://cloudflare-dns.com/dns-query".into()),
                ..DnsProxyConfig::default()
            },
        )
        .unwrap();
        assert_eq!(doh.config().upstream_protocol, DnsUpstreamProtocol::Doh);
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
}
