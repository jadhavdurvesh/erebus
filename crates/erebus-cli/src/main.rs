//! EREBUS offline policy tooling.
//!
//! This CLI validates and exports policy documents. It does not install
//! firewall rules or modify the host network configuration.

use clap::{Parser, Subcommand, ValueEnum};
use erebus_config::PolicyDocument;
use erebus_dns::{DnsPolicyDocument, DnsProxy, DnsProxyConfig, DnsUpstreamProtocol};
use erebus_engine::{DnsSecurityConfig, DnsSecurityService};
use std::{
    fs,
    net::{SocketAddr, TcpListener, UdpSocket},
    path::PathBuf,
    process::ExitCode,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
};

#[derive(Debug, Parser)]
#[command(name = "erebus", version, about = "EREBUS network policy tooling")]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum UpstreamProtocolArg {
    Udp,
    Tcp,
    Dot,
    Doh,
}

impl From<UpstreamProtocolArg> for DnsUpstreamProtocol {
    fn from(value: UpstreamProtocolArg) -> Self {
        match value {
            UpstreamProtocolArg::Udp => Self::Udp,
            UpstreamProtocolArg::Tcp => Self::Tcp,
            UpstreamProtocolArg::Dot => Self::Dot,
            UpstreamProtocolArg::Doh => Self::Doh,
        }
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Parse and validate a policy file without applying it.
    Validate {
        /// Path to a versioned EREBUS TOML policy.
        file: PathBuf,
    },
    /// Emit canonical TOML for a validated policy.
    Export {
        /// Input policy file.
        file: PathBuf,
        /// Optional output path. Without this option, output goes to stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Parse and validate a DNS domain policy without applying it.
    DnsValidate {
        /// Path to a versioned EREBUS DNS TOML policy.
        file: PathBuf,
    },
    /// Emit canonical TOML for a validated DNS domain policy.
    DnsExport {
        /// Input DNS policy file.
        file: PathBuf,
        /// Optional output path. Without this option, output goes to stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Run the local UDP/TCP DNS proxy using a DNS policy document.
    DnsServe {
        /// Input DNS policy file.
        file: PathBuf,
        /// UDP client listener (loopback by default).
        #[arg(long, default_value = "127.0.0.1:5300")]
        listen_udp: SocketAddr,
        /// TCP client listener (loopback by default).
        #[arg(long, default_value = "127.0.0.1:5300")]
        listen_tcp: SocketAddr,
        /// Numeric upstream resolver/bootstrap address (port 53 UDP/TCP, 853 DoT, 443 DoH).
        #[arg(long, default_value = "1.1.1.1:53")]
        upstream: SocketAddr,
        /// Upstream transport. Encrypted modes never fall back to plaintext.
        #[arg(long, value_enum, default_value_t = UpstreamProtocolArg::Udp)]
        upstream_protocol: UpstreamProtocolArg,
        /// Required for DoT; verified against the upstream TLS certificate.
        #[arg(long)]
        tls_server_name: Option<String>,
        /// Required for DoH; must be an HTTPS URL.
        #[arg(long)]
        https_url: Option<String>,
    },
}

fn run(arguments: Arguments) -> Result<(), String> {
    match arguments.command {
        Command::Validate { file } => {
            let source = fs::read_to_string(&file)
                .map_err(|error| format!("cannot read {}: {error}", file.display()))?;
            let document = PolicyDocument::parse(&source)
                .map_err(|error| format!("{}: {error}", file.display()))?;

            println!("Policy is valid.");
            println!("Schema version: {}", document.schema_version);
            println!("Rules: {}", document.rule_count());
            println!("Mode: offline validation only; no host rules were changed.");
        }
        Command::Export { file, output } => {
            let source = fs::read_to_string(&file)
                .map_err(|error| format!("cannot read {}: {error}", file.display()))?;
            let document = PolicyDocument::parse(&source)
                .map_err(|error| format!("{}: {error}", file.display()))?;
            let canonical = document
                .canonical_toml()
                .map_err(|error| format!("cannot serialize policy: {error}"))?;

            if let Some(output) = output {
                fs::write(&output, canonical)
                    .map_err(|error| format!("cannot write {}: {error}", output.display()))?;
                eprintln!("Wrote validated canonical policy to {}.", output.display());
            } else {
                print!("{canonical}");
            }
        }
        Command::DnsValidate { file } => {
            let source = fs::read_to_string(&file)
                .map_err(|error| format!("cannot read {}: {error}", file.display()))?;
            let document = DnsPolicyDocument::parse(&source)
                .map_err(|error| format!("{}: {error}", file.display()))?;

            println!("DNS policy is valid.");
            println!("Schema version: {}", document.schema_version);
            println!("Rules: {}", document.rules.len());
            println!("Mode: offline validation only; no DNS settings were changed.");
        }
        Command::DnsExport { file, output } => {
            let source = fs::read_to_string(&file)
                .map_err(|error| format!("cannot read {}: {error}", file.display()))?;
            let document = DnsPolicyDocument::parse(&source)
                .map_err(|error| format!("{}: {error}", file.display()))?;
            let canonical = document
                .canonical_toml()
                .map_err(|error| format!("cannot serialize DNS policy: {error}"))?;

            if let Some(output) = output {
                fs::write(&output, canonical)
                    .map_err(|error| format!("cannot write {}: {error}", output.display()))?;
                eprintln!(
                    "Wrote validated canonical DNS policy to {}.",
                    output.display()
                );
            } else {
                print!("{canonical}");
            }
        }
        Command::DnsServe {
            file,
            listen_udp,
            listen_tcp,
            upstream,
            upstream_protocol,
            tls_server_name,
            https_url,
        } => {
            let source = fs::read_to_string(&file)
                .map_err(|error| format!("cannot read {}: {error}", file.display()))?;
            let service = DnsSecurityService::from_toml(&source, DnsSecurityConfig::default())
                .map_err(|error| format!("{}: {error}", file.display()))?;
            let proxy = DnsProxy::new(
                service,
                DnsProxyConfig {
                    upstream,
                    upstream_protocol: upstream_protocol.into(),
                    tls_server_name,
                    https_url,
                    ..DnsProxyConfig::default()
                },
            )
            .map_err(|error| format!("cannot configure DNS proxy: {error}"))?;

            let udp_socket = UdpSocket::bind(listen_udp)
                .map_err(|error| format!("cannot bind UDP listener {listen_udp}: {error}"))?;
            let tcp_listener = TcpListener::bind(listen_tcp)
                .map_err(|error| format!("cannot bind TCP listener {listen_tcp}: {error}"))?;

            eprintln!("EREBUS DNS proxy is running.");
            eprintln!("UDP listener: {listen_udp}");
            eprintln!("TCP listener: {listen_tcp}");
            eprintln!("Upstream resolver: {upstream}");
            eprintln!("Upstream protocol: {upstream_protocol:?}");
            eprintln!("Press Ctrl+C to stop. No system resolver settings were changed.");

            let shutdown = Arc::new(AtomicBool::new(false));
            let udp_shutdown = Arc::clone(&shutdown);
            let udp_proxy = proxy.clone();
            let udp_worker = thread::spawn(move || udp_proxy.run_udp(udp_socket, &udp_shutdown));

            let tcp_result = proxy.run_tcp(tcp_listener, &shutdown);
            shutdown.store(true, Ordering::Release);

            let udp_result = udp_worker
                .join()
                .map_err(|_| "UDP DNS proxy worker panicked".to_owned())?
                .map_err(|error| format!("UDP DNS proxy stopped: {error}"));

            tcp_result.map_err(|error| format!("TCP DNS proxy stopped: {error}"))?;
            udp_result?;
        }
    }

    Ok(())
}

fn main() -> ExitCode {
    let arguments = Arguments::parse();
    match run(arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("erebus: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_documents_its_offline_commands() {
        let help = Arguments::try_parse_from(["erebus", "--help"]).unwrap_err();
        let output = help.to_string();

        assert!(output.contains("validate"));
        assert!(output.contains("export"));
        assert!(output.contains("dns-validate"));
        assert!(output.contains("dns-export"));
        assert!(output.contains("dns-serve"));
        assert!(output.contains("upstream-protocol"));
        assert!(output.contains("tls-server-name"));
        assert!(output.contains("https-url"));
    }
}
