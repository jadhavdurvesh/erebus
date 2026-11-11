# EREBUS: Original Work and Dependency Ownership

## Summary

EREBUS is an independently designed and implemented security engine. Its policy model, traffic metadata model, rule evaluator, configuration schema, policy snapshot/reload mechanism, connection tracker, rate-limit primitives, event journal, DNS parser, domain policy, DNS transaction tracker, DNS cache, proxy orchestration, and platform adapter contract are project code.

"Built from scratch" does not mean reimplementing cryptography, HTTP, operating-system kernels, or standard networking primitives. EREBUS owns its security decisions and integration logic while using established libraries for well-defined infrastructure and native OS facilities for actual enforcement.

## Project-owned code

| Component | Ownership | Notes |
| --- | --- | --- |
| `erebus-types` | EREBUS | Normalized traffic descriptors, verdicts, flow IDs, IPv4/IPv6 prefix logic |
| `erebus-policy` | EREBUS | Ordered matching, selector semantics, explicit defaults |
| `erebus-config` | EREBUS | Versioned policy document, validation and canonical export |
| `erebus-engine::PolicyStore` | EREBUS | Immutable snapshots and transactional policy replacement |
| `erebus-engine::connection` | EREBUS | Bounded flow identity and simplified TCP/UDP state tracking |
| `erebus-engine::rate_limit` | EREBUS | Token-bucket and per-key limiting primitives |
| `erebus-engine::events` | EREBUS | Bounded metadata-only event journal |
| `erebus-engine::enforcement` | EREBUS | Policy-to-adapter orchestration, lifecycle, failure state, metrics |
| `erebus-dns::wire` | EREBUS | DNS wire parser and bounded validation |
| `erebus-dns::policy` | EREBUS | DNS domain matching and precedence |
| `erebus-dns::tracker` | EREBUS | DNS question/endpoint transaction correlation |
| `erebus-dns::cache` | EREBUS | Bounded positive response cache and TTL handling |
| `erebus-dns::proxy` | EREBUS | UDP/TCP server loops, forwarding, DoT/DoH orchestration, response validation |
| `erebus-adapter-api` | EREBUS | Platform adapter lifecycle and enforcement contract |
| `erebus-cli` | EREBUS | CLI commands and configuration workflow |

The DNS parser implements the relevant DNS wire structures itself. It does not delegate parsing or domain policy decisions to a commercial DNS-filtering service.

## Third-party crates

The repository's Cargo manifests declare these external dependencies:

| Crate | Why it is used | What EREBUS does not delegate to it |
| --- | --- | --- |
| `serde` | Data serialization and deserialization support | Policy semantics or verdict decisions |
| `toml` | TOML syntax parsing/serialization | EREBUS schema validation and policy conversion |
| `thiserror` | Error type ergonomics | Runtime behavior |
| `clap` | CLI argument parsing | Security policy or proxy decisions |
| `reqwest` | DoH HTTP client | DNS filtering, rule matching, or DNS response policy |
| `rustls` | TLS cryptographic protocol and certificate verification | DoT framing, resolver choice, policy, or fallback rules |
| `webpki-roots` | Public Web PKI trust-anchor data | EREBUS hostname/endpoint configuration |
| `url` | HTTPS URL syntax parsing | DoH security policy and resolver bootstrap selection |
| `rcgen` (dev only) | Generate an ephemeral test CA and serverAuth leaf certificate for local DoT/DoH tests | Production certificate or trust decisions |

Transitive dependencies are also brought in by the crates above. The exact resolved graph belongs in `Cargo.lock` once the workspace lockfile is committed and reviewed.

The test-only certificate and private key in `crates/erebus-dns/tests/fixtures/` are for local tests only. They must never be used as real service credentials or shipped as trusted production identity material.

## What "our own firewall" means

EREBUS owns:

- The policy language and decision model.
- The policy evaluation algorithm.
- Policy lifecycle and generation semantics.
- The enforcement orchestration and adapter contract.
- DNS parsing, DNS filtering rules, cache, and proxy coordination.
- Audit event meanings and rate-limit behavior.

EREBUS intentionally reuses:

- Rust's standard library for sockets, threads, synchronization and I/O.
- Established serialization, CLI, TLS, HTTP, and URL crates.
- OS-supported packet-filtering mechanisms in future native adapters.

A TLS implementation should not be rewritten as a project branding exercise. It is safer to use a maintained TLS library and own the way EREBUS configures and constrains it.

## Native enforcement ownership

A real firewall must ultimately ask the operating system to enforce the decision:

- **Linux:** EREBUS will own the Linux adapter and its policy translation, but the kernel and supported Linux filtering facilities perform packet enforcement.
- **Windows:** EREBUS will own the Windows adapter and service, but Windows Filtering Platform performs kernel-mediated filtering.
- **Sand OS:** EREBUS will own the adapter against Sand OS's own network-stack hooks. This can be the deepest integration because both the OS networking interfaces and EREBUS policy engine are under our project control.

Using these native facilities does not make EREBUS a wrapper around another firewall. The platform API is the enforcement boundary, while EREBUS owns the security policy, decisions, lifecycle and cross-platform behavior.

## Independence checks

For each new dependency, record:

1. The narrow capability it supplies.
2. Why a standard library or existing project code is not sufficient.
3. Whether it processes untrusted input.
4. Whether it can change a security verdict or only provides infrastructure.
5. Its license, maintenance status, security advisories and update policy before release.

No new dependency should be added merely to make EREBUS appear more advanced. Prefer small, replaceable interfaces and keep policy decisions in EREBUS-owned code.
