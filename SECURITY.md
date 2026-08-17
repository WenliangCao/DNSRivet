# Security notes

## Reporting

Please avoid publishing exploitable details before a fix is available. Include the affected
version, configuration, reproduction steps, and whether the listener was loopback-only or exposed
to a network.

## Reviewed RustSec exceptions

The project intentionally pins `hickory-proto 0.25.2`: version 0.26 moved its raw DoH, DoH3, DoT,
and DoQ client transports out of the public `hickory-proto` API. Two 2026 advisories therefore need
an explicit applicability review instead of an automatic upgrade.

### RUSTSEC-2026-0118 / GHSA-3v94-mw7p-v465

The NSEC3 closest-encloser loop is reachable only through `DnssecDnsHandle` when a
`dnssec-ring`/`dnssec-aws-lc-rs` feature is enabled and local DNSSEC validation is configured.
This project enables transport-only `*-ring` features, not either DNSSEC feature, and does not use
`DnssecDnsHandle`. The affected code is not compiled into the active path.

### RUSTSEC-2026-0119 / GHSA-q2qq-hmj6-3wpp

The affected encoder becomes quadratic when an attacker supplies many records and compression
candidates. `hickory-proto` is used to encode only encrypted-upstream requests. Before that call,
`safe_encrypted_query` in `src/upstream/mod.rs` requires exactly one question and rejects every
answer, authority, additional record, and signature; only the separately represented optional EDNS
record remains. TCP and UDP inputs are also capped at 4 KiB, with at most 512 requests in flight.

Upstream responses are returned through `DnsResponse::into_buffer()` as their original buffer and
are never re-encoded by this project. Bootstrap requests are constructed internally with one
question. These constraints remove the advisory's many-record amplification precondition.

The matching entries in `.cargo/audit.toml` are scoped exceptions, not claims that the affected
crate is generally safe. Do not weaken `safe_encrypted_query`, input-size limits, or concurrency
limits while the project remains on 0.25.2. Revisit the pin when Hickory exposes a supported raw
forwarding API or when the transports are replaced locally.

Run the current checks with:

```bash
cargo audit
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```
