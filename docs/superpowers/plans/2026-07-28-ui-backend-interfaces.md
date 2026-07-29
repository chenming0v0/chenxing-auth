# UI Backend Interfaces Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add secure JSON APIs for the user center, administrator console, and OAuth login UI, including user-owned OAuth projects with atomic two-project ownership and per-project daily/monthly authorization quotas.

**Architecture:** Preserve the existing Axum routes and service/repository boundaries. Add owner-scoped Client service methods for normal users, keep administrator Client methods global, and expose new UI response DTOs from focused handler modules. Store session metadata in PostgreSQL while keeping session secrets, CSRF values, and per-client OAuth quota counters in Redis; bind pending OAuth requests to the initiating session.

**Tech Stack:** Rust, Axum, PostgreSQL/SQLx, Redis, Argon2, Serde, OpenAPI 3.0.3.

---

### Task 1: Add domain and repository tests for Client ownership and quota

**Files:**
- Modify: `tests/client_domain.rs`
- Modify: `tests/integration_storage.rs`
- Test: `src/clients/domain.rs` and `src/clients/repository.rs`

- [ ] **Step 1: Add pure validation tests for the owner quota contract**

Add tests that assert the public quota constant is two and that a disabled project is still counted by the documented ownership rule. Keep redirect URI and scope validation tests unchanged.

- [ ] **Step 2: Add PostgreSQL tests for owner isolation and atomic quota**

Using the existing integration setup, create one user, insert two owned clients, assert the owner query returns exactly those two, assert a different owner query returns none, and assert the transactional insert returns a quota error for the third project. Start two concurrent transactions for a user with one existing project and assert exactly one transaction creates the second project while the other returns `QuotaExceeded`; the repository transaction must lock the owner user row before counting.

- [ ] **Step 3: Run the tests and verify the new behavior fails**

Run:

```powershell
cargo test --test client_domain --test integration_storage
```

Expected: the new quota/owner tests fail because the schema and owner-scoped repository methods do not exist yet. Fix test compilation errors until the failure is specifically caused by the missing behavior.

### Task 2: Add Client ownership migration and service methods

**Files:**
- Create: `migrations/0005_client_owners.sql`
- Modify: `src/db.rs`
- Modify: `src/clients/domain.rs`
- Modify: `src/clients/repository.rs`
- Modify: `src/clients/service.rs`
- Create: `src/oauth/quota.rs`
- Modify: `src/state.rs`
- Modify: `src/oauth/authorization.rs`
- Modify: `src/oauth/handlers.rs`

- [ ] **Step 1: Add the migration**

Create:

```sql
ALTER TABLE oauth_clients
    ADD COLUMN owner_user_id UUID REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX oauth_clients_owner_user_id_idx
    ON oauth_clients (owner_user_id, created_at DESC);
```

Register migration version 5 in `src/db.rs`. Existing administrator-created Clients remain ownerless (`NULL`).

- [ ] **Step 2: Add typed owner and quota errors**

Add `USER_OAUTH_CLIENT_QUOTA: usize = 2` and service errors for `QuotaExceeded` and `NotFound` without changing the existing redirect URI validation rules. Keep client secrets generated and hashed by the service, never by handlers.

- [ ] **Step 3: Implement owner-scoped repository methods**

Add repository methods with these contracts:

```rust
pub async fn insert_owned_client(
    pool: &PgPool,
    owner_user_id: Uuid,
    registration: ValidatedClientRegistration,
    client_id: String,
    client_secret_hash: String,
) -> Result<NewClient, ClientInsertError>;

pub async fn list_clients_for_owner(
    pool: &PgPool,
    owner_user_id: Uuid,
) -> Result<Vec<ListedClient>, sqlx::Error>;

pub async fn update_owned_client(
    pool: &PgPool,
    owner_user_id: Uuid,
    client_id: &str,
    name: &str,
    redirect_uris: &[String],
    scopes: &[String],
) -> Result<bool, sqlx::Error>;

pub async fn set_owned_client_status(
    pool: &PgPool,
    owner_user_id: Uuid,
    client_id: &str,
    status: &str,
) -> Result<bool, sqlx::Error>;

pub async fn update_owned_client_secret(
    pool: &PgPool,
    owner_user_id: Uuid,
    client_id: &str,
    client_secret_hash: &str,
) -> Result<bool, sqlx::Error>;
```

`insert_owned_client` begins a transaction, executes `SELECT id FROM users WHERE id = $1 FOR UPDATE`, counts all rows with that `owner_user_id`, returns `QuotaExceeded` at two, and inserts the third only when the count is below two. Every update/status/secret statement includes `owner_user_id` in its `WHERE` clause.

- [ ] **Step 4: Add service methods and preserve administrator behavior**

Add `register_for_user`, `list_for_user`, `update_for_user`, `set_status_for_user`, and `rotate_secret_for_user`. Keep `register`, `list`, `update`, `set_status`, and `rotate_secret` global for administrator handlers. Map duplicate Client IDs and quota errors distinctly.

- [ ] **Step 5: Run the focused tests**

Run:

```powershell
cargo test --test client_domain --test integration_storage
```

Expected: all Client domain and storage tests pass, including the new owner/quota cases.

- [ ] **Step 6: Add Redis-backed per-project OAuth quotas**

Create `src/oauth/quota.rs` with:

```rust
pub const DAILY_AUTHORIZATION_LIMIT: u64 = 2_500;
pub const MONTHLY_AUTHORIZATION_LIMIT: u64 = 50_000;

#[derive(Clone)]
pub struct OAuthQuotaStore {
    client: redis::Client,
}

pub struct QuotaSnapshot {
    pub daily_limit: u64,
    pub daily_used: u64,
    pub monthly_limit: u64,
    pub monthly_used: u64,
}

pub enum QuotaConsumeResult { Allowed(QuotaSnapshot), DailyExceeded, MonthlyExceeded }
```

Implement a Redis Lua script that reads both period counters, rejects when either limit is already reached, otherwise increments both counters and sets each key to the next UTC day/month boundary. Add `snapshot(client_id)` without incrementing. Add `oauth_quotas: OAuthQuotaStore` to `AppState`; administrator-created ownerless Clients bypass this store.

- [ ] **Step 7: Add quota tests before wiring authorization**

Create `tests/oauth_quota.rs` covering first use, the 2,500th allowed daily use, the 2,501st rejection, the 50,000th allowed monthly use, the next rejection, snapshot values, and two concurrent consumers at the daily boundary. Run `cargo test --test oauth_quota` and confirm the tests fail only because the quota store or wiring is absent.

- [ ] **Step 8: Wire quota consumption into code issuance**

After all authorization validation and consent checks but before returning the redirect, load the Client owner ID. For a normal-user-owned Client, consume one daily/monthly quota unit and return a protocol-safe error redirect with the original `state` when rejected. For an ownerless administrator Client, issue the code without consuming a quota. Include quota values in normal-user project list/create responses.

### Task 3: Add user-center and owned OAuth project handlers

**Files:**
- Modify: `src/api.rs`
- Modify: `src/users/handlers.rs`
- Modify: `src/users/service.rs`
- Modify: `src/users/repository.rs`
- Create: `tests/user_oauth_api.rs`

- [ ] **Step 1: Write failing API tests**

Cover:

```rust
#[tokio::test]
async fn normal_user_can_create_only_two_owned_oauth_projects() {
    // Register and log in one user, create two valid projects, then assert
    // the third POST returns 409 and oauth_client_quota_exceeded.
}

#[tokio::test]
async fn normal_user_cannot_read_or_mutate_another_users_project() {
    // Create a project as owner A, log in owner B, assert the list is empty,
    // and assert GET, PUT, disable, enable, and rotate-secret return 404.
}

#[tokio::test]
async fn normal_user_cannot_access_admin_user_list() {
    // Log in a normal user and assert GET /api/v1/admin/users returns 401.
}
```

Also test `GET /api/v1/auth/status`, `GET /api/v1/auth/me`, owned list, update, disable/enable, rotation, CSRF rejection, and that the new secret is returned only by create/rotate responses.

- [ ] **Step 2: Run the new API tests to verify RED**

Run:

```powershell
cargo test --test user_oauth_api
```

Expected: route-not-found or missing service behavior failures, not fixture/setup errors.

- [ ] **Step 3: Add authenticated user request helpers**

Implement a helper that accepts only a browser `chenxing_session` cookie for new UI routes, loads the active Redis Session, parses its UUID user ID, and validates the session CSRF cookie and `X-CSRF-Token` for mutations. Do not use the development `X-Chenxing-Session` header for these browser UI mutations.

- [ ] **Step 4: Implement user status/profile and owned Client handlers**

Add JSON handlers for the routes in the design spec. Return `401` for missing/invalid user sessions, `403` for a CSRF failure, `404` for a project not owned by the current user without revealing whether another user owns it, and `409` with `oauth_client_quota_exceeded` for a third project. Use private response DTOs that omit secret hashes and owner data.

- [ ] **Step 5: Run user API tests and the existing API suite**

Run:

```powershell
cargo test --test user_oauth_api --test api --test clients --test client_lifecycle
```

Expected: all tests pass and existing admin Client registration remains global.

### Task 4: Add session metadata and remaining user-center APIs

**Files:**
- Create: `migrations/0004_ui_sessions.sql`
- Modify: `src/db.rs`
- Modify: `src/users/handlers.rs`
- Modify: `src/sessions/store.rs`
- Modify: `src/sessions/domain.rs`
- Modify: `src/api.rs`
- Create: `tests/user_sessions_api.rs`

- [ ] **Step 1: Write failing tests for session metadata**

Test session listing marks the current session, lists only the current user, revokes only owned sessions, clears cookies when the current session is revoked, and password change revokes all sessions. Test missing or mismatched CSRF values.

- [ ] **Step 2: Add migration and Redis user-session index**

Create the `user_sessions` metadata table from the design spec and register migration version 4. Extend `SessionStore` with a user index key containing session IDs. `save` writes Redis payload plus metadata; `revoke` deletes Redis and marks metadata; `revoke_all_for_user` reads the index and deletes only that user's sessions.

- [ ] **Step 3: Add profile/password service operations**

Add typed display-name validation, current-password verification, password hashing, and a repository update that is conditional on the user ID. Password rotation must update the hash before revoking the user's sessions and must not log either password.

- [ ] **Step 4: Implement status/profile/password/session handlers**

Add the six user-center routes from the design spec, reusing the authenticated-cookie and CSRF helpers. A successful password change returns `204` after revocation; a current-session revocation returns `204` and clears cookies.

- [ ] **Step 5: Run user-center tests**

Run:

```powershell
cargo test --test user_sessions_api --test user_oauth_api --test csrf --test sessions
```

Expected: all tests pass with no secret material in response bodies or logs.

### Task 5: Add administrator UI identity, overview, and filtered queries

**Files:**
- Modify: `src/admin/authorization.rs`
- Create: `src/admin/ui_handlers.rs`
- Modify: `src/admin/management_handlers.rs`
- Modify: `src/admin/repository.rs`
- Modify: `src/clients/repository.rs`
- Modify: `src/api.rs`
- Create: `tests/admin_ui_api.rs`

- [ ] **Step 1: Write failing permission-isolation tests**

Test Owner can access `/api/v1/admin/auth/me`, overview, user query, Client query, and audit query; Operator cannot read users; Auditor cannot mutate Clients; a normal user cookie cannot access any admin route. Test that Client query exposes owner ID only to administrators and never exposes secret hashes.

- [ ] **Step 2: Run tests to verify RED**

Run `cargo test --test admin_ui_api` and confirm missing routes or response behavior causes the failure.

- [ ] **Step 3: Add administrator identity and aggregate query methods**

Expose `AdminPermission::all()` or an equivalent fixed mapping for response serialization. Add repository count and filtered page methods with bounded `page_size` (1..=100), parameterized SQL, and a shared `{items, page, page_size, total}` DTO. Client queries include owner ID; user queries never expose password data.

- [ ] **Step 4: Implement handlers and routes**

Create focused handlers for `/api/v1/admin/auth/me`, `/api/v1/admin/overview`, `/api/v1/admin/users/query`, `/api/v1/admin/clients/query`, and `/api/v1/admin/audit/query`. Apply the existing `AdminPermission` checks per endpoint. Keep old array list routes unchanged.

- [ ] **Step 5: Run administrator tests**

Run:

```powershell
cargo test --test admin_ui_api --test admin_api --test admin_domain
```

Expected: role isolation and normal-user denial pass.

### Task 6: Add session-bound OAuth UI request APIs

**Files:**
- Modify: `src/oauth/consent.rs`
- Modify: `src/oauth/request_store.rs`
- Modify: `src/oauth/handlers.rs`
- Create: `src/oauth/ui_handlers.rs`
- Modify: `src/api.rs`
- Create: `tests/oauth_ui_api.rs`
- Create: `tests/oauth_quota.rs`

- [ ] **Step 1: Write failing tests**

Test that a logged-in user can inspect a pending request, another user's session cannot inspect it, approve consumes it once and returns the validated redirect URL, deny returns protocol-safe redirect data, and CSRF/missing/expired requests are rejected.

- [ ] **Step 2: Run the tests to verify RED**

Run `cargo test --test oauth_ui_api` and confirm the missing JSON routes or session binding fails as expected.

- [ ] **Step 3: Bind pending requests to the initiating session**

Add `session_id: Uuid` to `PendingAuthorization`, populate it when `/oauth/authorize` stores a browser request, and require the same active session in both HTML and JSON consent flows. Keep Redis `GETDEL` consumption atomic.

- [ ] **Step 4: Implement JSON inspection and decision handlers**

Add `GET` and `POST /api/v1/oauth/authorize/requests/{request_id}`. Resolve the registered Client for display data, expose only safe redirect host/scope information, validate `approve|deny`, and delegate approval to the existing code issuance path. Return JSON with `redirect_to` and never include an authorization code except inside that validated redirect URL.

- [ ] **Step 5: Run OAuth tests**

Run:

```powershell
cargo test --test oauth_ui_api --test oauth_flow --test authorization_code --test pkce
```

Expected: JSON UI behavior passes and existing protocol flow remains green.

- [ ] **Step 6: Assert quota errors are UI-safe**

Extend `tests/oauth_ui_api.rs` to exhaust a project quota through the authorization path and assert JSON returns `429` with `oauth_quota_exceeded`, while the protocol endpoint returns a redirect containing only `error`, `error_description`, and the original `state`; no authorization code or counter value appears in the response.

### Task 7: Synchronize contract and documentation

**Files:**
- Modify: `openapi.yaml`
- Modify: `API.md`
- Modify: `docs/superpowers/specs/2026-07-28-ui-backend-interfaces-design.md`

- [ ] **Step 1: Document all routes and schemas**

Add unique `operationId`s, user/admin cookie security, CSRF header parameters on every browser mutation, quota error responses, owner-scoped Client schemas, pagination envelope, and one-time Secret semantics. Keep protocol endpoints form-encoded and existing array routes documented as-is.

- [ ] **Step 2: Validate the OpenAPI contract**

Run:

```powershell
python .codex/skills/sync-openapi/scripts/validate_openapi.py
```

Expected: the validator exits 0 and every implemented public route has one path and a unique operation ID.

### Task 8: Full verification and review

**Files:**
- Inspect: all modified files and `git status --short`

- [ ] **Step 1: Run required repository checks**

Run each command separately and record failures explicitly:

```powershell
cargo fmt --check
cargo check --all-targets --all-features
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info --fail-under-lines 75
cargo audit
python .codex/skills/src-line-limit/scripts/check_src_lines.py
```

- [ ] **Step 2: Resolve source-size warnings**

Any file over 500 lines must be split before completion. Files from 301 through 500 lines must be listed in the final change summary.

- [ ] **Step 3: Inspect the final diff**

Run `git diff --check`, verify no `.env`, key material, Client Secret, password, or unrelated `web/` file is staged, and review all API permission paths against the requirements.

- [ ] **Step 4: Request code review before final completion**

Review the completed diff against this plan, fix all critical/important findings, rerun the affected tests, and only then mark the task complete.
