# Cargo Audit Exceptions

## RUSTSEC-2023-0071

- **Advisory:** `RUSTSEC-2023-0071` (RSA Marvin Attack timing side-channel)
- **Current status:** Explicitly ignored by the CI `cargo audit` gate while the
  lockfile contains an `rsa` release in the `0.9.x` series.
- **Dependency chain:** `webauthn-rs -> crypto-glue -> rsa`
- **Locked version:** `rsa 0.9.10` as recorded in `Cargo.lock`.

### Impact and threat model

The affected dependency is used by the WebAuthn stack for RSA public-key
signature verification. The service does not use this dependency for RSA
private-key decryption or signing. Marvin Attack timing leakage is therefore
not directly exposed through a private-key operation in this service, which
limits the practical risk in the current server-side usage. The advisory is
still tracked because timing side channels are security-relevant and the
transitive dependency is outside this service's direct control.

### Compensating measures

- CI keeps the advisory visible in every run through a dedicated exception
  status step and the GitHub Actions step summary.
- The same step reads `Cargo.lock` and fails if `rsa` leaves the `0.9.x` line,
  forcing a review when the dependency graph changes.
- WebAuthn verification remains constrained to the existing `webauthn-rs`
  implementation; no RSA private-key operation is added to this service.

### Removal condition

When `webauthn-rs` or `crypto-glue` publishes a release that removes or fixes
the affected `rsa` dependency, upgrade the dependency chain, confirm the
lockfile no longer carries the vulnerable path, and remove both the CI
`--ignore RUSTSEC-2023-0071` argument and this exception record.
