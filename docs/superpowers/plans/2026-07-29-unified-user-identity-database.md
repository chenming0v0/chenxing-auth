# Unified User Identity Database Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the split user/admin identity model with one incrementing `users.id`, hierarchical `user/admin/owner` roles, a clean database baseline, and one shared authentication/session system.

**Architecture:** Rebuild the development database from a squashed PostgreSQL baseline because existing data is disposable. Keep random public credentials separate from incrementing database keys, move authorization to a role-aware current-user context, and reuse the normal user Session/CSRF path for management APIs. Preserve `ADMIN_TOKEN` only as an optional owner-equivalent automation credential.

**Tech Stack:** Rust, Axum, PostgreSQL 16, SQLx, Redis 7, OAuth 2.0/OIDC, React, TypeScript, Vite, OpenAPI.

---

## File Structure

- Replace `migrations/0001_initial.sql` with the complete unified schema and remove `migrations/0002_*.sql` through `migrations/0012_*.sql`.
- Simplify `src/db.rs` to register one baseline migration.
- Add role and authenticated-user rules to `src/users/domain.rs`, `src/users/repository.rs`, and `src/users/service.rs`.
- Convert `src/admin/authorization.rs` into role authorization over normal user sessions.
- Remove administrator credential/session ownership from `src/admin/repository.rs`, `src/admin/service.rs`, and `src/admin/session.rs`; delete files when no remaining responsibility exists.
- Keep management route handlers under `src/admin/`, but make every handler operate on `UserId` and `UserRole`.
- Refactor `src/sessions/domain.rs`, `src/sessions/store.rs`, and `src/sessions/cookies.rs` so public Session tokens remain random while database IDs become `BIGINT`.
- Update OAuth Client/provider repositories for `BIGINT` internal IDs while preserving random protocol-facing identifiers.
- Update `web/src/api.ts`, `web/src/store.tsx`, authentication pages, and console layouts to share one login state.
- Update `openapi.yaml`, `API.md`, `README.md`, and `AGENTS.md` in the same contract change.

### Task 1: Add schema contract tests for the new baseline

**Files:**
- Create: `tests/database_schema.rs`
- Modify: `tests/deployment.rs`
- Test: `tests/database_schema.rs`

- [ ] **Step 1: Write a failing real-PostgreSQL schema test**

Add a test that creates a uniquely named temporary schema/database context, runs `db::migrate`, and queries `information_schema`/`pg_constraint` to assert:

```rust
assert_column("users", "id", "bigint", false).await;
assert_identity("users", "id").await;
assert_check_contains("users", "users_role_check", "user", "admin", "owner").await;
assert_table_missing("admins").await;
assert_column("user_passkeys", "user_id", "bigint", false).await;
assert_fk("user_passkeys", "user_id", "users", "id").await;
assert_column("oauth_clients", "id", "bigint", false).await;
assert_column("oauth_providers", "id", "bigint", false).await;
```

Also assert that inserting the first `users` row returns ID `1`, and that sequential rows return `2` and `3`.

- [ ] **Step 2: Run the schema test and verify RED**

Run:

```powershell
cargo test --all-features --test database_schema -- --nocapture
```

Expected: FAIL because the current baseline creates UUID keys and an `admins` table.

- [ ] **Step 3: Extend deployment tests for a single migration baseline**

Assert that all migration files referenced by `src/db.rs` exist, the old split-admin migrations are absent, and the Docker startup path does not mutate schema outside SQLx migration execution.

- [ ] **Step 4: Commit the failing tests**

```powershell
git add tests/database_schema.rs tests/deployment.rs
git commit -m "test: define unified identity database schema"
```

### Task 2: Replace the migration chain with the unified schema

**Files:**
- Modify: `migrations/0001_initial.sql`
- Delete: `migrations/0002_audit_events.sql`
- Delete: `migrations/0003_admins.sql`
- Delete: `migrations/0004_ui_sessions.sql`
- Delete: `migrations/0005_client_owners.sql`
- Delete: `migrations/0006_client_owner_cascade.sql`
- Delete: `migrations/0007_auth_factors.sql`
- Delete: `migrations/0008_admin_usernames.sql`
- Delete: `migrations/0009_user_integer_ids.sql`
- Delete: `migrations/0010_app_settings.sql`
- Delete: `migrations/0011_usernames.sql`
- Delete: `migrations/0012_external_oauth.sql`
- Modify: `src/db.rs`

- [ ] **Step 1: Define the clean baseline in dependency order**

Create these tables with explicit constraints and indexes:

```text
users
oauth_clients
user_consents
user_sessions
user_totp_factors
user_passkeys
oauth_providers
oauth_external_identities
audit_events
app_settings
```

Use `BIGINT GENERATED ALWAYS AS IDENTITY` for entity primary keys. Use `(user_id, client_id)` for `user_consents`, `user_id` for the one-to-one TOTP table, and `setting_key` for settings. Add `CHECK` constraints for role/status/client auth method/provider status. Use `ON DELETE CASCADE` for owned authentication data and `ON DELETE SET NULL` for audit actors.

- [ ] **Step 2: Register only the new baseline**

Reduce `embedded_migrator()` to migration version `1`, description `unified identity baseline`, and `include_str!("../migrations/0001_initial.sql")`.

- [ ] **Step 3: Reset local development services explicitly**

Run only after confirming the Docker project name/path resolves to this repository:

```powershell
docker compose down -v
docker compose up -d postgres redis
```

Do not delete any directory manually. Record in `README.md` that this refactor requires a development data reset.

- [ ] **Step 4: Run the schema test and verify GREEN**

```powershell
cargo test --all-features --test database_schema -- --nocapture
```

Expected: PASS with no `admins` table and all user foreign keys typed as `BIGINT`.

- [ ] **Step 5: Commit the baseline**

```powershell
git add migrations src/db.rs README.md
git commit -m "refactor: replace database with unified identity baseline"
```

### Task 3: Introduce hierarchical roles in the user domain

**Files:**
- Modify: `src/users/domain.rs`
- Modify: `src/users/repository.rs`
- Modify: `src/users/service.rs`
- Modify: `tests/users.rs`
- Modify: `tests/login_domain.rs`
- Replace: `tests/admin_domain.rs`

- [ ] **Step 1: Write failing role-domain tests**

Define expectations for:

```rust
assert!(UserRole::Owner.allows(UserPermission::RotateKeys));
assert!(UserRole::Admin.allows(UserPermission::ManageUsers));
assert!(!UserRole::Admin.allows(UserPermission::RotateKeys));
assert!(!UserRole::User.allows(UserPermission::ReadAudit));
assert!(UserRole::Owner.is_at_least(UserRole::Admin));
assert_eq!(UserRole::parse("owner"), Some(UserRole::Owner));
```

Add registration tests proving public registration always stores `role = user`, regardless of unknown JSON fields.

- [ ] **Step 2: Run focused tests and verify RED**

```powershell
cargo test --all-features --test admin_domain --test users --test login_domain
```

Expected: FAIL because roles currently live in the admin domain.

- [ ] **Step 3: Implement `UserRole` and `UserPermission`**

Move the permission matrix into `src/users/domain.rs`. Include `ManageUsers`, `ManageClients`, `ReadAudit`, `ManageSettings`, `ManageIdentityProviders`, `RotateKeys`, and `ManageRoles`. Map `admin` to all management permissions except `RotateKeys` and `ManageRoles`; map `owner` to all permissions.

- [ ] **Step 4: Return role in every authenticated profile**

Update repository projections and public/current-user response types to include `role`. Public self-registration inserts the database default `user`; bootstrap and Owner role-management paths use explicit role values.

- [ ] **Step 5: Verify GREEN and commit**

```powershell
cargo test --all-features --test admin_domain --test users --test login_domain
git add src/users tests/admin_domain.rs tests/users.rs tests/login_domain.rs
git commit -m "feat: add hierarchical user roles"
```

### Task 4: Replace administrator bootstrap with Owner user bootstrap

**Files:**
- Modify: `src/admin/auth_handlers.rs`
- Modify: `src/admin/authorization.rs`
- Modify: `src/users/repository.rs`
- Modify: `src/users/service.rs`
- Delete or reduce: `src/admin/repository.rs`
- Delete or reduce: `src/admin/service.rs`
- Modify: `src/state.rs`
- Modify: `tests/admin_api.rs`
- Modify: `tests/admin_settings.rs`

- [ ] **Step 1: Rewrite bootstrap tests first**

Use an isolated empty database and submit:

```json
{"username":"chenxing-owner","email":"owner@example.com","password":"1234567890"}
```

Assert `201`, `id = 1`, `role = owner`, no Session Cookie, and a stored `users` row with normalized email. Assert invalid email returns `400`, two concurrent requests produce exactly one `201`, and later requests return `409`.

- [ ] **Step 2: Add failing tests for Owner invariants**

Assert that disabling or demoting the last active Owner returns `409 last_owner_required`, while the same operation succeeds when another active Owner exists.

- [ ] **Step 3: Verify RED**

```powershell
cargo test --all-features --test admin_api --test admin_settings -- --nocapture
```

- [ ] **Step 4: Implement transactional bootstrap**

Inside one PostgreSQL transaction:

```sql
SELECT pg_advisory_xact_lock(7341928);
SELECT EXISTS (SELECT 1 FROM users WHERE role = 'owner');
INSERT INTO users (..., role, ...) VALUES (..., 'owner', ...) RETURNING id;
```

Reuse normal username/email/password validation and password hashing. Do not send email and do not create a Session.

- [ ] **Step 5: Implement role/status mutation with last-Owner protection**

Lock the target row with `FOR UPDATE`; for an active Owner demotion/disable, count other active Owners in the same transaction and reject when zero. Expose this only under `ManageRoles`.

- [ ] **Step 6: Remove admin account services from `AppState`**

Delete `AdminService`, `AdminId`, admin credential repository calls, and their state fields. Keep management route modules but make them depend on `UserService` and the common database.

- [ ] **Step 7: Verify GREEN and commit**

```powershell
cargo test --all-features --test admin_api --test admin_settings -- --nocapture
git add src/admin src/users src/state.rs tests/admin_api.rs tests/admin_settings.rs
git commit -m "refactor: bootstrap owner as unified user"
```

### Task 5: Unify user and management Sessions

**Files:**
- Modify: `src/sessions/domain.rs`
- Modify: `src/sessions/store.rs`
- Modify: `src/sessions/cookies.rs`
- Delete: `src/admin/session.rs`
- Modify: `src/admin/authorization.rs`
- Modify: `src/admin/auth_handlers.rs`
- Modify: `src/users/ui_auth.rs`
- Modify: `tests/sessions.rs`
- Modify: `tests/session_api.rs`
- Modify: `tests/admin_ui_api.rs`
- Modify: `tests/cookie_security.rs`

- [ ] **Step 1: Write failing Session credential tests**

Assert that:

- the Cookie value is a random URL-safe token, not a numeric database ID;
- PostgreSQL stores only `SHA-256(token)` and never the plaintext token;
- Redis keys are derived from the token hash;
- an admin/owner management request succeeds with the normal user Session and CSRF cookies;
- the removed admin cookie names are never issued;
- changing a user from `admin` to `user` immediately invalidates management authorization for an existing Session.

- [ ] **Step 2: Verify RED**

```powershell
cargo test --all-features --test sessions --test session_api --test admin_ui_api --test cookie_security
```

- [ ] **Step 3: Separate internal Session ID from public token**

Use a structure equivalent to:

```rust
pub struct SessionCredential {
    pub token: String,
    pub token_hash: [u8; 32],
}

pub struct Session {
    pub id: i64,
    pub user_id: UserId,
    pub csrf_token: String,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}
```

Generate 32 random bytes for the token and 32 random bytes for CSRF. Insert metadata in PostgreSQL, cache the payload in Redis, and compensate by deleting PostgreSQL metadata when Redis persistence fails.

- [ ] **Step 4: Implement one current-user extractor/service**

Every protected request must resolve the Session, then load the current user row from PostgreSQL. Reject disabled users and evaluate the current role at request time. Management writes require normal Session Cookie + CSRF Cookie + `X-CSRF-Token`; valid `ADMIN_TOKEN` Bearer requests bypass browser CSRF and receive owner-equivalent permissions with no user ID.

- [ ] **Step 5: Remove admin login/logout Session behavior**

Delete administrator credential login and dedicated Session creation. Keep a compatibility response only if an existing public route must temporarily redirect clients to the normal login endpoint; otherwise remove the routes and contract entirely.

- [ ] **Step 6: Verify GREEN and commit**

```powershell
cargo test --all-features --test sessions --test session_api --test admin_ui_api --test cookie_security
git add src/sessions src/admin src/users tests
git commit -m "refactor: share user sessions with management APIs"
```

### Task 6: Convert remaining entity keys and repositories to the clean schema

**Files:**
- Modify: `src/clients/domain.rs`
- Modify: `src/clients/repository.rs`
- Modify: `src/clients/service.rs`
- Modify: `src/consents.rs`
- Modify: `src/auth_factors/repository.rs`
- Modify: `src/oauth/providers/domain.rs`
- Modify: `src/oauth/providers/repository.rs`
- Modify: `src/oauth/providers/service.rs`
- Modify: `src/audit.rs`
- Modify: `src/audit/repository.rs`
- Modify relevant integration tests under `tests/`

- [ ] **Step 1: Add failing repository tests for key types and cascades**

Test sequential internal IDs for Clients, providers, passkeys, external identities, Sessions, and audit events. Test user deletion cascades owned Clients/factors/identities/consents while preserving audit rows with `actor_user_id = NULL`.

- [ ] **Step 2: Verify RED against UUID-backed repositories**

```powershell
cargo test --all-features --test integration_storage --test auth_factors_repository --test oauth_provider_flow
```

- [ ] **Step 3: Change internal ID types to `i64`**

Keep protocol identifiers unchanged:

- Client database `id: i64`, public `client_id: String`.
- Provider database `id: i64`, public `slug: String`.
- Passkey database `id: i64`, WebAuthn `credential_id: Vec<u8>`.
- External identity database `id: i64`, provider subject remains string.
- Audit database `id: i64`.

- [ ] **Step 4: Update SQL and error mapping**

Use `RETURNING id` for inserts. Match unique conflicts by constraint name rather than treating every `23505` as an email collision. Keep all JSONB serialization structured.

- [ ] **Step 5: Verify GREEN and commit**

```powershell
cargo test --all-features --test integration_storage --test auth_factors_repository --test oauth_provider_flow
git add src/clients src/consents.rs src/auth_factors src/oauth/providers src/audit.rs src/audit tests
git commit -m "refactor: use incrementing internal entity ids"
```

### Task 7: Update management APIs and audit attribution

**Files:**
- Modify: `src/admin/management_handlers.rs`
- Modify: `src/admin/handlers.rs`
- Modify: `src/admin/key_handlers.rs`
- Modify: `src/admin/provider_handlers.rs`
- Modify: `src/admin/settings_handlers.rs`
- Modify: `src/admin/ui_handlers.rs`
- Modify: `src/audit.rs`
- Modify: `tests/admin_api.rs`
- Modify: `tests/admin_ui_api.rs`
- Modify: `tests/oauth_provider_admin_api.rs`

- [ ] **Step 1: Write failing permission matrix tests**

Cover every management route for `user`, `admin`, `owner`, disabled user, expired Session, invalid CSRF, and `ADMIN_TOKEN`. Include Owner-only key rotation and role mutation.

- [ ] **Step 2: Replace admin list/create semantics**

List privileged users from `users WHERE role IN ('admin', 'owner')`. The management create endpoint must create a complete `users` row and require `username`, `email`, `password`, and `role`; accept only `admin` or `owner`. Existing-user role changes use the separate Owner-only role mutation endpoint. Do not reintroduce a second credential table.

- [ ] **Step 3: Attribute audit events to unified users**

Set `actor_user_id` for Session-authenticated operations and `actor_type = system_token` for `ADMIN_TOKEN`. Never record passwords, tokens, Session cookies, authorization codes, Client Secrets, or provider Secret ciphertext.

- [ ] **Step 4: Verify and commit**

```powershell
cargo test --all-features --test admin_api --test admin_ui_api --test oauth_provider_admin_api
git add src/admin src/audit.rs tests/admin_api.rs tests/admin_ui_api.rs tests/oauth_provider_admin_api.rs
git commit -m "refactor: authorize management through user roles"
```

### Task 8: Update the frontend to one login state

**Files:**
- Modify: `web/src/api.ts`
- Modify: `web/src/store.tsx`
- Modify: `web/src/App.tsx`
- Modify: `web/src/pages/Bootstrap.tsx`
- Modify: `web/src/pages/Auth.tsx`
- Modify: `web/src/pages/AdminLogin.tsx`
- Modify: `web/src/pages/AdminConsoleLayout.tsx`
- Modify: `web/src/pages/console/ConsoleLayout.tsx`
- Modify: `web/src/pages/console/Users.tsx`
- Modify: `web/src/pages/AdminSettings.tsx`

- [ ] **Step 1: Update typed API expectations before components**

Add `role: "user" | "admin" | "owner"` to current-user types. Change bootstrap input to `username`, `email`, and `password`. Remove admin Session/CSRF API helpers and use the normal mutation helper.

- [ ] **Step 2: Build once and verify RED**

```powershell
npm run build
```

Expected: TypeScript failures identify every remaining split-admin assumption.

- [ ] **Step 3: Use one authentication store**

Normal login establishes the only browser Session. Route guards permit `/console` to all active users and `/admin` only to `admin`/`owner`. Remove the separate administrator login flow; `/admin/login` may redirect to the common login page with a return target.

- [ ] **Step 4: Update Bootstrap and role management UI**

Require username, email, and password. Do not claim that email was sent or verified. Show role controls only to Owner, and prevent the UI from offering self-demotion or last-Owner removal while still relying on the backend as authority.

- [ ] **Step 5: Verify frontend and commit**

```powershell
npm run build
git add web/src
git commit -m "refactor: unify user and management login UI"
```

### Task 9: Synchronize OpenAPI and documentation

**Files:**
- Modify: `openapi.yaml`
- Modify: `API.md`
- Modify: `README.md`
- Modify: `AGENTS.md`
- Modify: `.env.example` when configuration semantics change

- [ ] **Step 1: Inventory routes from `src/api.rs`**

Record exact methods, paths, request fields, responses, errors, cookies, CSRF requirements, redirects, and removed administrator auth routes.

- [ ] **Step 2: Update the contract**

Document bootstrap email, unified role fields, unified Session security, role mutation, last-Owner conflict, removed admin cookies/login, and `ADMIN_TOKEN` automation behavior. Remove obsolete `adminSessionCookie` and `adminCsrfCookie` schemes.

- [ ] **Step 3: Update operational documentation**

State clearly that this development refactor requires deleting PostgreSQL and Redis volumes. Document the target tables and that SMTP is configured only after Owner initialization.

- [ ] **Step 4: Validate OpenAPI**

```powershell
python .codex/skills/sync-openapi/scripts/validate_openapi.py
```

Expected: PASS with unique `operationId` values and one documented path per route.

- [ ] **Step 5: Commit**

```powershell
git add openapi.yaml API.md README.md AGENTS.md .env.example
git commit -m "docs: document unified user identity contract"
```

### Task 10: Full database and security verification

**Files:**
- Modify tests only when a new failing regression is discovered.

- [ ] **Step 1: Start from an actually empty environment**

```powershell
docker compose down -v
docker compose up -d postgres redis
```

Wait for both health checks before running tests. Never run multiple Cargo compile/test commands concurrently.

- [ ] **Step 2: Run project verification sequentially**

```powershell
cargo fmt --check
cargo check --all-targets --all-features
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info --fail-under-lines 75
cargo audit
```

- [ ] **Step 3: Verify frontend, OpenAPI, deployment, and source size**

```powershell
npm --prefix web run build
python .codex/skills/sync-openapi/scripts/validate_openapi.py
python .codex/skills/src-line-limit/scripts/check_src_lines.py
```

Split or refactor every `src` file over 500 lines. Record files over 300 lines as weak warnings.

- [ ] **Step 4: Inspect the live schema**

Query `information_schema.columns`, `pg_constraint`, `pg_indexes`, and `pg_sequences`. Confirm:

- no `admins` table or legacy UUID columns;
- `users.id` starts at 1 and every user foreign key is `BIGINT`;
- no orphan rows;
- role/status checks and last-Owner application tests pass;
- database Session rows contain token hashes only;
- no secrets appear in audit metadata.

- [ ] **Step 5: Review the final diff and commit verification fixes**

```powershell
git status --short
git diff --check
git log --oneline --decorate -12
```

Do not claim completion if any required command is unavailable or failing; record the exact blocker and output instead.
