# Session Storage Consistency Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make PostgreSQL session facts authoritative and make Redis converge through an encrypted, retryable PostgreSQL outbox.

**Architecture:** Metadata-enabled `SessionStore` writes session facts and outbox records in one PostgreSQL transaction. PostgreSQL stores an encrypted session payload so a worker can replay Redis after restart. Metadata-enabled reads validate PostgreSQL first; Redis-only stores keep their existing behavior.

**Tech Stack:** Rust, Tokio, SQLx PostgreSQL, Redis, AES-256-GCM, real-service integration tests.

---

### Task 1: Extend the durable session schema

**Files:**
- Create: `migrations/0003_session_outbox.sql`
- Modify: `src/db.rs`
- Test: `tests/database_schema.rs`

- [x] Add nullable encrypted `session_payload` to `user_sessions` and create `session_outbox` with operation, session/user references, token hash, retry timestamps, attempt count, and last error.
- [x] Register migrations 3-5 in the embedded migrator. Migration 5 keeps event user ids after user deletion so durable outbox work is not lost.
- [x] Add schema assertions for the payload and outbox retry columns.
- [x] Run `cargo test --test database_schema` and confirm the new schema checks pass.

### Task 2: Add failing metadata consistency tests

**Files:**
- Modify: `tests/integration_storage.rs`

- [x] Add tests that save with an unreachable Redis client, assert the PostgreSQL row and pending `sync_session`, then process it with a healthy Redis client.
- [x] Add equivalent failure/recovery coverage for `revoke`, `revoke_for_user`, and `revoke_all_for_user`.
- [x] Assert revoked PostgreSQL rows are rejected by `find` even while stale Redis payloads remain.
- [x] Run each new test before implementation and record the expected compile or behavior failure.

### Task 3: Implement encrypted PostgreSQL authority and outbox delivery

**Files:**
- Modify: `src/sessions/store.rs`
- Modify: `src/state.rs`
- Modify: `src/main.rs`
- Modify: `Cargo.toml`

- [x] Add AES-256-GCM payload encryption using the configured authentication key and return non-sensitive encryption/decryption errors.
- [x] Make metadata-enabled save and revoke mutations transactional with outbox insertion.
- [x] Make metadata-enabled find reconstruct sessions from PostgreSQL and use Redis only for legacy rows without an encrypted payload.
- [x] Implement idempotent outbox delivery, exponential backoff, safe row claiming, and structured failure logs.
- [x] Start one outbox worker with the application and add Tokio time support.
- [x] Run the focused integration tests and confirm the failure/recovery assertions pass.

### Task 4: Refactor and verify the complete change

**Files:**
- Modify: `tests/session_api.rs`
- Modify: `tests/admin_api.rs`
- Modify: `tests/admin_settings.rs`
- Modify: `tests/admin_ui_api.rs`
- Modify: `tests/integration_storage.rs`

- [x] Update metadata store construction to provide the test encryption key.
- [x] Run `cargo fmt --check`, `cargo check --all-targets --all-features`, `cargo test --all-features`, and `cargo clippy --all-targets --all-features -- -D warnings`.
- [x] Run the project source-line checker and confirm no changed source file exceeds 500 lines. Existing weak warnings remain documented in the completion report.
- [x] Review the diff for token leakage, ignored compensation errors, stale-event resurrection, and undocumented HTTP contract changes.

### Task 5: Preserve cleanup after user deletion

- [x] Emit durable per-session revoke projection events in the same batch-revocation transaction.
- [x] Keep outbox event user ids after the referenced user is deleted.
- [x] Add a real PostgreSQL/Redis regression test proving a pending batch revoke removes stale Redis keys after user deletion.
- [x] Hold the session row lock through `sync_session` projection and add a concurrent-revocation race regression test.
