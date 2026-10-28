# Security notes

## Reporting

Please avoid publishing exploitable details before a fix is available. Include the affected
version, configuration, reproduction steps, and whether the listener was loopback-only or exposed
to a network.

## Dependency security

The project uses the public raw DoH, DoH3, DoT, and DoQ transports in `hickory-net 0.26.3`
and its re-exported `hickory-proto 0.26.3` wire types. It does not use a higher-level resolver
or enable local DNSSEC validation. `.cargo/audit.toml` has no advisory exceptions.

The two former exceptions were removed by upgrading the affected dependencies:

- [RUSTSEC-2026-0118](https://rustsec.org/advisories/RUSTSEC-2026-0118.html): the NSEC3
  closest-encloser validator (`DnssecDnsHandle`) moved out of `hickory-proto` in 0.26.
  Its corresponding `hickory-net` issue,
  [RUSTSEC-2026-0120](https://rustsec.org/advisories/RUSTSEC-2026-0120.html), was fixed in 0.26.1.
- [RUSTSEC-2026-0119](https://rustsec.org/advisories/RUSTSEC-2026-0119.html): quadratic name
  compression in the encoder was fixed in `hickory-proto 0.26.1`.

The 0.26.3 minimum also includes subsequent parsing and denial-of-service fixes from 0.26.2
and their follow-up corrections. Keep the lockfile's TLS, HTTP, and QUIC dependencies up to date;
upgrading Hickory alone is not a substitute for auditing the full dependency graph.

## Forwarding boundaries

The patched encoder does not remove the need for input and resource limits. Before encrypted
forwarding, `safe_encrypted_query` in `src/upstream/mod.rs` requires exactly one question and
rejects answer, authority, additional records, and signatures; an optional EDNS record is allowed.
TCP and UDP queries remain capped at 4 KiB. Client requests and upstream attempts each have a
512-permit global budget, including encrypted attempts still running after a hedge wins.
Transport-local queues may impose lower limits; DoT retains Hickory's default of 32 active
requests per connection rather than expanding its internal pipeline during the security upgrade.

Upstream responses are returned through `DnsResponse::into_buffer()` as their original bytes,
not re-encoded. Client IDs are restored and responses are validated against the query. Channel
deadlines, cancellation, and connection backoff remain under DNSRivet's control.

Run the current checks with:

```bash
mbx audit
mbx test --all-targets --all-features
mbx clippy --all-targets --all-features -- -D warnings
```

A clean audit means no matching advisories in the database used for that run, not proof that the
software is free of vulnerabilities.
