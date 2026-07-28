# Login Factors Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add tested TOTP and WebAuthn passkey enrollment and factor verification to normal API and browser OAuth login.

**Architecture:** Keep HTTP handlers thin and put factor policy, TOTP encryption, WebAuthn ceremony calls, PostgreSQL repositories, and Redis login-ticket state in focused modules. Password authentication creates a short-lived pending ticket; only successful TOTP or passkey verification consumes it and creates the existing Session.

**Tech Stack:** Rust/Axum, PostgreSQL/SQLx, Redis, `totp-rs`, `webauthn-rs`, `aws-lc-rs` AEAD, existing Session/Cookie/Audit services.

---

### Task 1: Add factor domain and migration

**Files:**
- Create: `src/auth_factors/domain.rs`
- Create: `src/auth_factors/crypto.rs`
- Create: `src/auth_factors/mod.rs`
- Create: `migrations/0007_auth_factors.sql`
- Modify: `src/lib.rs`, `src/db.rs`
- Test: `tests/auth_factors_domain.rs`

- [ ] **Step 1: Write failing tests** for six-digit TOTP input validation, encrypted secret round trips, and factor method selection.
- [ ] **Step 2: Run `cargo test --test auth_factors_domain` and confirm the new APIs fail because the module is absent.
- [ ] **Step 3: Implement the focused domain and AEAD helpers and add the migration tables for encrypted TOTP secrets and serialized passkeys.
- [ ] **Step 4: Run the focused test and confirm it passes.

### Task 2: Add configuration, factor repositories, and Redis ticket state

**Files:**
- Create: `src/auth_factors/repository.rs`
- Create: `src/auth_factors/store.rs`
- Modify: `src/config.rs`, `src/db.rs`, `src/state.rs`, `Cargo.toml`
- Test: `tests/auth_factors_storage.rs`

- [ ] **Step 1: Write failing repository/store tests** covering ticket TTL, non-consuming lookup, one-time consume, and factor persistence shapes.
- [ ] **Step 2: Run the focused tests and record the expected missing-module or missing-method failures.
- [ ] **Step 3: Implement configuration parsing, PostgreSQL queries, and Redis JSON state with TTL and atomic ticket consumption.
- [ ] **Step 4: Run the storage tests against the configured PostgreSQL/Redis services.

### Task 3: Add TOTP login and enrollment endpoints

**Files:**
- Create: `src/auth_factors/totp.rs`
- Create: `src/auth_factors/handlers.rs`
- Modify: `src/users/domain.rs`, `src/users/handlers.rs`, `src/api.rs`
- Test: `tests/totp_auth.rs`

- [ ] **Step 1: Write failing tests** for password login returning a pending ticket, TOTP setup returning an `otpauth://` URI, valid confirmation creating cookies, invalid codes not consuming the ticket, and later login requiring a valid code.
- [ ] **Step 2: Run the focused test and confirm it fails before TOTP routes exist.
- [ ] **Step 3: Implement the minimum TOTP policy, encrypted persistence, ticket consumption, and Session issuance using `totp-rs`.
- [ ] **Step 4: Run the focused tests and confirm all TOTP cases pass.

### Task 4: Add WebAuthn passkey enrollment and login

**Files:**
- Create: `src/auth_factors/passkey.rs`
- Modify: `src/auth_factors/handlers.rs`, `src/state.rs`, `src/api.rs`, `Cargo.toml`
- Test: `tests/passkey_auth.rs`

- [ ] **Step 1: Write failing route tests** for registration/authentication challenge responses, rejected missing tickets, and no Session before a valid assertion.
- [ ] **Step 2: Run the focused tests and confirm the passkey behavior is absent.
- [ ] **Step 3: Implement fixed RP configuration, serialized short-lived ceremony state, passkey persistence, assertion counter updates, and Session issuance with `webauthn-rs`.
- [ ] **Step 4: Run the focused tests, including the library-supported fake ceremony where available.

### Task 5: Apply the same factor policy to browser OAuth login

**Files:**
- Modify: `src/web/login.rs`, `src/web/helpers.rs`
- Test: `tests/browser_flow.rs`, `tests/totp_auth.rs`

- [ ] **Step 1: Add a failing browser test** proving password success does not bind the OAuth request or issue a full Session until factor completion.
- [ ] **Step 2: Run the test and confirm current browser login bypasses the new policy.
- [ ] **Step 3: Render the pending-factor HTML flow and finish it through the shared factor service.
- [ ] **Step 4: Run browser and OAuth integration tests.

### Task 6: Synchronize contract and verify

**Files:**
- Modify: `openapi.yaml`, `API.md`
- Test: existing API/OAuth suites and project verification commands

- [ ] **Step 1: Document each public factor route, request field, response status, cookies, ticket security, and generic error in OpenAPI and API guidance.
- [ ] **Step 2: Run `python .codex/skills/sync-openapi/scripts/validate_openapi.py`.
- [ ] **Step 3: Run `python .codex/skills/src-line-limit/scripts/check_src_lines.py` and split any `src` file over 500 lines.
- [ ] **Step 4: Run `cargo fmt --check`, `cargo check --all-targets --all-features`, `cargo test --all-features`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info --fail-under-lines 75`, and `cargo audit`, recording unavailable external-service checks.

