# Post-Audit Security and Contract Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修复本轮独立审查确认的 9 个高置信问题（Issues #542-#550），并以可复现测试证明 OAuth、密钥、数据库权限、CI 与 API 契约边界。

**Architecture:** 保持 HTTP 路由薄、OAuth 业务规则在 use case、数据库权限在迁移、密钥安全在 key_storage/keys、契约以 `openapi.yaml` 为唯一来源。每个修复先增加能重现问题的聚焦测试，再实现最小必要修复；跨存储竞态必须保留原子消费和 fail-closed 语义。

**Tech Stack:** Rust, Axum, PostgreSQL/SQLx, Redis, React/Vite, GitHub Actions, Windows security APIs, OpenAPI 3.

---

### Task 1: OAuth Grant Fences and External-Provider Admission

**Issues:** #542, #543, #550

**Files:**
- Modify: `src/oauth/refresh_use_case.rs`, `src/oauth/issuance_fence.rs`, `src/oauth/token_use_case.rs`, `src/oauth/token_use_case_support.rs`
- Modify: `src/oauth/providers/service.rs`, `src/oauth/providers/repository.rs`, related provider error/response modules
- Test: `tests/consent_code_exchange_race.rs`, `tests/oauth_flow.rs`, `tests/oauth_provider_flow.rs`, focused unit tests under `src/oauth`
- Contract: `openapi.yaml` only if the external-login error contract changes

- [ ] **Step 1: Add a deterministic Refresh/revoke race test** that pauses after the consent gate, commits revocation, then asserts no new token response and no redeemable successor.
- [ ] **Step 2: Carry `EffectiveGrant.consent_version` through Refresh rotation and call the existing post-persist consent fence; rollback the successor on denial or unavailable storage.** Preserve `session_epoch`, client-secret generation, audit, and Redis tombstone behavior.
- [ ] **Step 3: Add a token-flow regression test for canonical redirect URI variants.** The exact URI accepted at authorization must redeem; a different textual URI must remain `invalid_grant`.
- [ ] **Step 4: Preserve the exact validated authorization-request URI for code binding or apply one documented, equally strict normalization at both endpoints.** Do not broaden redirect matching beyond existing loopback-port rules.
- [ ] **Step 5: Add external OAuth email-policy integration tests** for rejected domain, rejected alias, allowed domain, and no partial rows.
- [ ] **Step 6: Enforce `ensure_email_policy_allows` inside the external auto-provisioning transaction boundary** while leaving existing linked-identity login unchanged.
- [ ] **Step 7: Run focused tests with `test_sh/test.sh --test NAME`, then `cargo fmt --check` and `cargo check --all-features`.
- [ ] **Step 8: Run `src-line-limit` on changed `src` files and commit with `Refs: #542, #543, #550`.

---

### Task 2: Windows and Multi-Instance Key Safety

**Issues:** #544, #545, #546

**Files:**
- Modify: `src/key_storage/windows_acl.rs`, `src/key_storage/windows_policy.rs`, `src/key_storage/windows.rs`
- Modify: `src/key_lock.rs`, `src/keys/rotation.rs`, `src/keys/activation.rs`, `src/keys/sync.rs`, related config/docs
- Test: `src/key_storage/windows_tests.rs`, `src/key_lock_tests.rs`, `src/keys/activation_tests.rs`, `src/keys/rotation_tests.rs`
- Docs: `docs/security/key-storage.md`, README/config examples when behavior changes

- [ ] **Step 1: Add Windows policy tests** for attacker-owned directory/file with restrictive-looking DACL and for ACE masks granting unexpected control.
- [ ] **Step 2: Request `OWNER_SECURITY_INFORMATION` and reject untrusted owners; preserve reparse-point, inode, DACL, and no-secret-error behavior.
- [ ] **Step 3: Add deterministic lock tests for PID collision and pause/resume; ensure release cannot remove a successor generation.
- [ ] **Step 4: Replace PID/mtime-only ownership with a kernel-exclusive Windows handle, or add host/process-start/random fencing checked on acquire, heartbeat, stale cleanup, and release.
- [ ] **Step 5: Add fast/slow clock activation tests and include configured skew allowance (or an equivalent trusted-time fence) in activation eligibility.
- [ ] **Step 6: Preserve published-key and retirement grace windows; never delete or activate shared material before propagation safety is met.
- [ ] **Step 7: Run `cargo fmt --check`, `cargo check --all-features`, and Windows-target `cargo check --target x86_64-pc-windows-gnu --all-features` if available; run focused library tests only through `test_sh/test.sh --lib`.
- [ ] **Step 8: Run `src-line-limit`, update security docs, and commit with `Refs: #544, #545, #546`.

---

### Task 3: Database Role, CI Permissions, and OpenAPI Contract

**Issues:** #547, #548, #549

**Files:**
- Modify: `migrations/0019_audit_runtime_role.sql` plus a new forward migration, `src/db/audit_boundary.rs`/migration tests as needed
- Modify: `.github/workflows/build.yml`, `tests/deployment.rs` or workflow-structure tests
- Modify: `openapi.yaml`, `tests/openapi_contract.rs`, and only the route/gate files required to resolve the TOTP issuer inconsistency

- [ ] **Step 1: Add a migration/role test** proving `chenxing_runtime` cannot mutate `_sqlx_migrations` while the migration role still can.
- [ ] **Step 2: Add a forward migration that revokes ledger mutation privileges and prevents default-privilege regrant**; keep audit-table boundaries intact.
- [ ] **Step 3: Add YAML/structure tests for job-level GitHub Actions permissions and `persist-credentials: false` on build checkouts.**
- [ ] **Step 4: Set workflow defaults read-only; grant `contents: write` only to release and `packages: write` only to container publishing.
- [ ] **Step 5: Reconcile OpenAPI with runtime for revocation client auth, UserInfo POST form auth, admin Bearer-vs-CSRF alternatives, documented admin error responses, and TOTP issuer gating.
- [ ] **Step 6: Add operation-level contract tests for security arrays, request fields, and all expected response status codes; validate the YAML/OpenAPI structure.
- [ ] **Step 7: Use the project `sync-openapi` skill whenever route/request/response behavior changes, then run focused tests, `cargo fmt --check`, and `cargo check --all-features`.
- [ ] **Step 8: Run `src-line-limit` on changed `src`, review migration safety, and commit with `Refs: #547, #548, #549`.

---

### Integration and Verification

- [ ] Review each agent commit against its assigned Issue acceptance criteria and inspect the diff for unrelated changes.
- [ ] Merge the three worktree branches into `codex/audit-fixes-2026-08-17`, resolving only genuine conflicts.
- [ ] Run `cargo fmt --check`, `cargo check --all-features`, `cargo check --tests`, focused `test_sh/test.sh --test NAME`/`--lib`, workflow/YAML checks, and the project `src-line-limit` skill.
- [ ] Because the changes touch OAuth concurrency, migrations, and persistent storage, request one-time user authorization before `CHENXING_TEST_ROLE=orchestrator ./test_sh/test.sh --full` (or `--gate`) and run it only after focused checks are green.
- [ ] Verify `git diff dev...HEAD`, issue references, and branch cleanliness; push the integration branch and create a PR targeting `dev`.
