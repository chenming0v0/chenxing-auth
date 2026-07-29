# Custom OAuth Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add configuration-driven OAuth 2.0/OIDC external login, account creation/binding, administrator APIs, and a usable settings page without hard-coded providers.

**Architecture:** Add an `oauth::providers` boundary containing validated provider configuration, encrypted secret storage, PostgreSQL repositories, Redis state storage, external HTTP exchange, and thin Axum handlers. Existing users and browser Session services remain the source of truth for local accounts and sessions; provider identities are stored separately and are never linked by email automatically.

**Tech Stack:** Rust 2024, Axum, PostgreSQL/sqlx-core, Redis, reqwest with rustls, AES-256-GCM, Argon2, server-rendered HTML.

---

### Task 1: Add provider domain and security primitives

**Files:**
- Create: `src/oauth/providers/mod.rs`
- Create: `src/oauth/providers/domain.rs`
- Create: `src/oauth/providers/secrets.rs`
- Create: `src/oauth/providers/state_store.rs`
- Modify: `Cargo.toml`
- Modify: `src/oauth.rs`
- Test: `tests/oauth_provider_domain.rs`

- [ ] Add `aes-gcm` and `reqwest` dependencies with rustls and JSON support.
- [ ] Define validated provider input, provider summary, external user claims, supported client authentication methods, and dotted JSON claim extraction.
- [ ] Add unit tests for slug, endpoint, scope, claim path, and email verification validation.
- [ ] Implement AES-256-GCM secret key loading/creation under `KEY_DIRECTORY/oauth-provider-secret.key`; ciphertext includes a fresh 12-byte nonce and is base64 encoded.
- [ ] Implement Redis state records with 600-second TTL and atomic `GETDEL` consumption.

### Task 2: Add database persistence and service layer

**Files:**
- Create: `migrations/0004_external_oauth.sql`
- Modify: `src/db.rs`
- Create: `src/oauth/providers/repository.rs`
- Create: `src/oauth/providers/service.rs`
- Modify: `src/state.rs`
- Modify: `src/admin/domain.rs`
- Test: `tests/oauth_provider_storage.rs`

- [ ] Add provider and external identity tables with unique slug, `(provider_id, subject)`, and `(provider_id, user_id)` constraints.
- [ ] Register migration 4 in the embedded migrator.
- [ ] Implement provider CRUD/status operations and ensure repository records never serialize secrets.
- [ ] Implement external token exchange and UserInfo calls with request timeout, no automatic redirects, form encoding, Basic or body Client authentication, and generic error mapping.
- [ ] Implement transaction-safe external identity resolution: reuse active bound identity, reject disabled users, reject email collisions, or create a local user with an unusable random Argon2 password and bind the identity atomically.
- [ ] Add `ExternalOAuthService` to `AppState` and initialize its secret manager and HTTP client.

### Task 3: Add admin API and settings page

**Files:**
- Create: `src/admin/provider_handlers.rs`
- Modify: `src/admin/domain.rs`
- Modify: `src/api.rs`
- Modify: `src/admin/web_handlers.rs`
- Modify: `src/web.rs`
- Test: `tests/oauth_provider_admin_api.rs`

- [ ] Add provider management permission for Owner and Operator roles.
- [ ] Add protected create/list/update/enable/disable routes with administrator CSRF checks for session mutations and Bearer compatibility.
- [ ] Return callback URI and `client_secret_configured`, never the secret or ciphertext.
- [ ] Add `/admin/settings/oauth` with provider table, callback address, add/edit forms, enable/disable controls, and a link from the dashboard.
- [ ] Escape all provider-controlled values in HTML.

### Task 4: Add user login and callback flow

**Files:**
- Create: `src/oauth/providers/handlers.rs`
- Modify: `src/api.rs`
- Modify: `src/web/login.rs`
- Modify: `src/sessions/cookies.rs`
- Test: `tests/oauth_provider_flow.rs`

- [ ] Add dynamic provider buttons to `/auth/login`, preserving optional `request_id`.
- [ ] Add start endpoint that validates provider status, saves Redis state, sets an HttpOnly state cookie, and redirects with exact callback URI, scope, and state.
- [ ] Add callback endpoint that validates and consumes both state sources, exchanges code, verifies UserInfo claims, resolves the local user, creates a normal Session, and continues to consent when a pending authorization request exists.
- [ ] Clear the state cookie on every callback outcome and return generic non-sensitive errors.
- [ ] Test first registration, repeated login, request continuation, invalid/replayed state, provider errors, email collision, and disabled identity.

### Task 5: Synchronize contract, docs, and verify

**Files:**
- Modify: `openapi.yaml`
- Modify: `API.md`
- Modify: `README.md`
- Test: all repository tests

- [ ] Document every new API route, schema, security scheme, redirect and error in `openapi.yaml` and run the OpenAPI validator.
- [ ] Update user-facing API and current-status documentation.
- [ ] Run `cargo fmt --check`, `cargo check --all-targets --all-features`, `cargo test --all-features`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info --fail-under-lines 75`, `cargo audit`, and `python .codex/skills/src-line-limit/scripts/check_src_lines.py`.
- [ ] Review the diff for secret leakage, untracked runtime keys, and ensure changes are committed on `codex/custom-oauth-provider` without pushing.
