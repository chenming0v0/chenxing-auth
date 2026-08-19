# Account Security Backend Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将个人信息页的账户资料、邮箱变更、TOTP、Passkey 与可扩展外部账户绑定全部接入真实服务，关闭 GitHub Issues #555-#559 对应的前后端契约缺口。

**Architecture:** 保留现有 `auth_factors` 与 `oauth::providers` 领域边界，只补充契约、并发和回跳缺口；账户资料修改由 `UserService` 编排并复用现有密码重新认证；邮箱变更使用 Redis 短期 challenge、SMTP 基础设施和 PostgreSQL 原子更新/会话撤销。所有浏览器写操作继续使用 Session Cookie、CSRF Cookie 与 `X-CSRF-Token` 三者绑定。

**Tech Stack:** Rust 2024, Axum, PostgreSQL/SQLx, Redis Lua, React 19, TypeScript, Vite, Vitest, WebAuthn, TOTP, OpenAPI.

---

## Product Contract

- `/console/profile` 仍是唯一账户管理入口，保留“账户绑定 / 安全设置”双 Tab。
- “账户资料”弹窗只修改显示名称与用户名，不出现邮箱字段。
- “邮箱地址”使用独立的两阶段弹窗：先验证当前密码并发送验证码，再确认验证码。
- 不得用前端 mock、忽略未知字段或固定成功提示伪装后端完成。
- 新增 OAuth/OIDC Provider 后，前端不改 JSX 即出现绑定按钮；已绑定但停用的 Provider 仍可见且可解除。
- 用户名修改需要当前密码，但不会推进 `session_epoch`：它只更换登录别名，不改变权限、密码、第二因子或已签发凭据。
- 邮箱修改成功推进 `session_epoch` 并撤销全部 Cookie Session 与 Refresh Token，包括当前会话；前端成功后回到登录页。
- TOTP/Passkey 的 RP ID、Origin、Issuer、challenge、TTL 和单次消费语义必须来自可信配置或现有状态存储，禁止从请求 Host 推导。

### Task 1: Establish the Contract Baseline

**Files:**
- Modify: `tests/auth_factor_security_api.rs`
- Modify: `tests/external_identity_binding.rs`
- Modify: `tests/openapi_contract.rs`
- Modify: `web/src/pages/console/security.test.tsx`
- Modify: `web/src/pages/console/profile-apps.test.tsx`

- [x] **Step 1: Preserve the current working tree**

Run `git status --short --branch` and record all existing modified/untracked files. Do not reset, clean, checkout, or revert the completed account-security UI.

- [ ] **Step 2: Run the allowed baseline checks**

Run:

```bash
cargo check --all-targets --all-features
./test_sh/test.sh --test auth_factor_security_api
./test_sh/test.sh --test external_identity_binding
npm --prefix web test -- --run web/src/pages/console/security.test.tsx web/src/pages/console/profile-apps.test.tsx
```

Expected: current checks either pass or expose a reproducible contract gap. Do not run `--full`, `--gate`, `--coverage`, raw `cargo test`, or raw `cargo nextest run` without the user's one-time authorization.

- [ ] **Step 3: Add explicit contract assertions before implementation**

The focused tests must assert:

```text
PATCH /api/v1/auth/me accepts username only with current_password.
Email change start/confirm routes do not exist yet and therefore fail RED.
TOTP/Passkey writes reject a missing or mismatched CSRF token.
External binding success returns /console/profile?external=linked.
Disabled providers remain present through linked identity records but cannot start a new bind.
```

Run each affected focused test and observe the expected RED failure before production changes.

### Task 2: Verify and Close TOTP/Passkey Integration Gaps (#555, #556)

**Files:**
- Modify: `src/auth_factors/security_handlers.rs`
- Modify: `src/auth_factors/authenticated_enrollment.rs`
- Modify: `src/auth_factors/totp_enrollment.rs`
- Modify: `src/auth_factors/store.rs`
- Modify: `src/auth_factors/passkey.rs`
- Modify: `tests/auth_factor_security_api.rs`
- Modify: `tests/totp_factor_race.rs`
- Modify: `tests/passkey_cas.rs`
- Modify: `tests/passkey_rp_id_policy.rs`
- Modify: `web/src/api-response-guards.ts`

- [ ] **Step 1: Write missing RED tests around the existing routes**

Add or retain focused cases for:

```rust
// TOTP enrollment is bound to user_id + session_id + session_epoch.
// Expired/replayed enrollment_id returns invalid_factor_enrollment.
// Confirmation consumes the enrollment exactly once under concurrency.
// Passkey finish rejects another session's challenge and a changed session_epoch.
// Factor removal revokes all credentials and clears Session/CSRF cookies.
// Factor summary immediately reflects totp_enabled/passkey_count.
```

- [ ] **Step 2: Run the focused RED tests**

Run:

```bash
./test_sh/test.sh --test auth_factor_security_api
./test_sh/test.sh --test totp_factor_race
./test_sh/test.sh --test passkey_cas
./test_sh/test.sh --test passkey_rp_id_policy
```

- [ ] **Step 3: Repair only demonstrated gaps**

Keep the existing response shapes:

```rust
pub struct TotpStartResponse<'a> {
    enrollment_id: &'a str,
    secret_base32: &'a str,
    otpauth_url: &'a str,
}

pub struct PasskeyStartResponse {
    enrollment_id: String,
    options: CreationChallengeResponse,
}
```

Use `RequestIssuer`/persisted Passkey settings as the trusted source. Preserve Redis TTL, holder binding, atomic take/CAS and the existing recovery policy. Never log TOTP codes, secrets, WebAuthn challenges, attestation objects or credential IDs.

- [ ] **Step 4: Verify GREEN and the frontend response guards**

Re-run the four focused Rust tests, then:

```bash
npm --prefix web test -- --run web/src/pages/console/security.test.tsx
```

Expected: all focused tests pass and the frontend rejects malformed success bodies.

### Task 3: Finish Dynamic External Account Binding (#557)

**Files:**
- Modify: `src/oauth/providers/handlers/binding/start.rs`
- Modify: `src/oauth/providers/handlers/binding/identity.rs`
- Modify: `src/oauth/providers/handlers/callback.rs`
- Modify: `src/oauth/providers/error_helpers.rs`
- Modify: `tests/external_identity_binding.rs`
- Modify: `web/src/pages/console/security.test.tsx`

- [ ] **Step 1: Add RED cases for dynamic and disabled providers**

Cover these exact outcomes:

```text
active provider + no identity       -> bind is available
active provider + linked identity  -> linked identity is returned
disabled provider + linked identity -> identity is still returned and unlink works
disabled provider + no identity    -> bind start is rejected
binding callback success           -> /console/profile?external=linked
binding callback failure           -> /console/profile?external_error=<stable_code>
```

- [ ] **Step 2: Separate login callback redirects from binding redirects**

Keep login failures on `/login`, but centralize binding redirects:

```rust
fn external_binding_redirect(code: Option<&str>) -> Response {
    let location = match code {
        Some(code) => format!("/console/profile?external_error={code}"),
        None => "/console/profile?external=linked".to_owned(),
    };
    Redirect::to(&location).into_response()
}
```

Replace the stale `/settings/security?external=linked` redirect. Preserve state-cookie clearing on every callback outcome.

- [ ] **Step 3: Keep provider rendering data-driven**

Do not add provider-specific backend routes or frontend JSX. `GET /api/v1/auth/external-providers` remains the active-provider catalog; `GET /api/v1/auth/external-identities` remains the durable linked-identity catalog and must not filter rows merely because a provider is disabled.

- [ ] **Step 4: Verify**

Run:

```bash
./test_sh/test.sh --test external_identity_binding
npm --prefix web test -- --run web/src/pages/console/security.test.tsx
```

### Task 4: Implement Secure Username Updates (#558)

**Files:**
- Modify: `src/users/ui_handlers.rs`
- Modify: `src/users/service/profile.rs`
- Modify: `src/users/repository/write.rs`
- Modify: `src/users/repository/mod.rs`
- Modify: `src/audit/classification.rs`
- Create: `tests/user_profile_security_api.rs`
- Modify: `web/src/pages/console/profile-apps.tsx`
- Modify: `web/src/pages/console/profile-editor-dialog.tsx`
- Modify: `web/src/pages/console/profile-apps.test.tsx`
- Modify: `web/src/api.ts`

- [x] **Step 1: Write the RED API tests**

  Added `tests/user_profile_security_api.rs` with the username PATCH reauthentication
  contract. The integration runner reaches test setup but is currently blocked by the
  Windows protected-key fixture (`KeyManager::load_or_generate`, Win32 code 5).

The test matrix is:

```text
display_name only                         -> 200, no password required
same normalized username                 -> 200, no password required
changed username without password        -> 400 current_password_required
changed username with wrong password     -> 401 password_reauthentication_failed
password-login-disabled account          -> 403 password_reauthentication_unavailable
invalid/reserved username                -> 400 invalid_username
unique conflict                          -> 409 username_unavailable
concurrent password/username change race -> stale reauthentication loses
successful username change               -> latest UserMe, same session_epoch
```

- [x] **Step 2: Extend the HTTP input without exposing the password in Debug**

```rust
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateProfileInput {
    pub display_name: Option<String>,
    pub username: Option<String>,
    pub current_password: Option<String>,
}

impl fmt::Debug for UpdateProfileInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpdateProfileInput")
            .field("display_name", &self.display_name)
            .field("username", &self.username)
            .field("current_password", &self.current_password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}
```

- [x] **Step 3: Add a race-safe application/repository boundary**

The service must call `validate_display_name` and `validate_username`. When the normalized username changes, call `reauthenticate_password`, then pass its `AuthenticatedUser.session_epoch` into a transaction that locks the user row and compares the epoch before updating `username` and `display_name`.

Return a typed outcome:

```rust
pub enum ProfileUpdateOutcome {
    Updated(UserProfile),
    AuthenticationChanged,
    UsernameUnavailable,
    UserMissing,
}
```

Do not advance `session_epoch` for this operation. Map unique violations to `UsernameUnavailable` without returning SQL details.

- [x] **Step 4: Add audit and HTTP mappings**

Add `AuditAction::UserProfileUpdate` at Info and `AuditAction::UserUsernameChange` at Critical. Audit metadata may contain `result` and `username_changed`, but not the old username, new username or current password.

Map errors exactly:

```text
current_password_required              400
invalid_username                       400
password_reauthentication_failed       401
password_reauthentication_unavailable  403
username_unavailable                   409
invalid_session                        401
```

- [ ] **Step 5: Wire the existing profile dialog**

Remove the Issue #558 warning and disabled submit state. Submit:

```ts
{
  display_name: displayName.trim() || null,
  username: normalizedUsername,
  ...(usernameChanged ? { current_password: profilePassword } : {}),
}
```

Only show the current-password field when the username differs. After success, verify the returned `username` matches the requested normalized value before showing “账户资料已保存” and calling `refresh()`.

- [ ] **Step 6: Verify**

Run:

```bash
./test_sh/test.sh --test user_profile_security_api
npm --prefix web test -- --run web/src/pages/console/profile-apps.test.tsx
```

### Task 5: Add an Email Delivery Boundary

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `src/notifications/mod.rs`
- Create: `src/notifications/email.rs`
- Create: `src/notifications/smtp.rs`
- Modify: `src/lib.rs`
- Modify: `src/settings/service.rs`
- Modify: `src/oauth/providers/secrets.rs`
- Modify: `src/state.rs`
- Create: `tests/email_delivery.rs`

- [ ] **Step 1: Write a fake-backed RED test**

Define an object-safe application port:

```rust
pub trait EmailSender: Send + Sync {
    fn send<'a>(
        &'a self,
        message: EmailMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), EmailSendError>> + Send + 'a>>;
}
```

Tests use `RecordingEmailSender`; production uses `SmtpEmailSender`. The test must prove message Debug output redacts the verification code and SMTP password.

- [ ] **Step 2: Add the SMTP adapter**

Use a maintained SMTP crate with Tokio + rustls and no native TLS dependency. Before adding it, record its license/maintenance check and run the project's audit mode later. Read SMTP settings at send time so administrator changes take effect without restart. Add an internal `SettingsService::smtp_delivery_config()` that decrypts the configured password but never serializes it.

- [ ] **Step 3: Extend secret context safely**

Add an `EmailChange([u8; 16])` AEAD context to `SecretContext`. Encrypt the six-digit confirmation code before storing a Redis challenge; bind ciphertext AAD to the random challenge UUID. Do not introduce a second key file.

- [ ] **Step 4: Initialize dependency injection**

Add `Arc<dyn EmailSender>` to `AppState`, with a production SMTP implementation and a test-only constructor/replacement used by integration tests. Missing/incomplete SMTP configuration must return a typed unavailable error and fail closed.

- [ ] **Step 5: Verify**

Run:

```bash
./test_sh/test.sh --test email_delivery
cargo check --all-targets --all-features
```

### Task 6: Implement Two-Stage Email Change (#559)

**Files:**
- Create: `src/users/email_change.rs`
- Create: `src/users/email_change_store.rs`
- Create: `src/users/email_change_handlers.rs`
- Modify: `src/users/mod.rs`
- Modify: `src/users/service/mod.rs`
- Modify: `src/users/repository/write.rs`
- Modify: `src/users/repository/mod.rs`
- Modify: `src/api/routes.rs`
- Modify: `src/api/issuer_gate.rs`
- Modify: `src/audit/classification.rs`
- Create: `tests/email_change_api.rs`

- [ ] **Step 1: Write RED domain/store tests**

The challenge payload contains:

```rust
pub struct PendingEmailChange {
    pub challenge_id: Uuid,
    pub user_id: UserId,
    pub session_id: i64,
    pub session_epoch: i64,
    pub display_email: String,
    pub canonical_email: String,
    pub encrypted_code: Vec<u8>,
    pub expires_at: OffsetDateTime,
    pub failed_attempts: u8,
}
```

Test a 10-minute TTL, one active challenge per user, replacement invalidating the old challenge, session/user/epoch binding, five failed-code attempts, claim/release ownership and no resurrection after consumption.

- [ ] **Step 2: Implement Redis scripts**

Use namespaced keys:

```text
email-change:challenge:<challenge_id>
email-change:user:<user_id>
```

`replace_for_user` atomically removes the old challenge and installs the new marker/payload with the same TTL. `claim` uses a random claim token and refuses a second claimant. `release_claim` only succeeds for the same token. `consume` deletes marker and payload only for the same claim token. Never use a read-then-delete pair for final consumption.

- [ ] **Step 3: Implement start**

Add:

```text
POST /api/v1/auth/email-change/start
body: { "new_email": "...", "current_password": "..." }
response: 202 { "challenge_id": "...", "expires_at": "RFC3339" }
```

Order the gates:

```text
SessionWrite/CSRF -> EmailAddress::parse -> email policy -> current-password
reauthentication -> account/IP rate limit -> create/replace challenge -> send new-email code
-> best-effort old-email security notice -> generic 202
```

If the canonical email is already used by another account, return the same generic 202 shape using a non-persisted decoy challenge and do not send mail. This prevents the browser response from becoming an email-enumeration oracle.

- [ ] **Step 4: Implement confirm and atomic account update**

Add:

```text
POST /api/v1/auth/email-change/confirm
body: { "challenge_id": "...", "code": "123456" }
response: 204 and cleared Session/CSRF cookies
```

Confirm must:

```text
load bound challenge -> enforce attempt limit -> decrypt/constant-time compare code
-> claim challenge -> begin PostgreSQL transaction -> lock session scope/user row
-> compare session_epoch -> recheck canonical_email uniqueness
-> update email + canonical_email together
-> revoke_all_for_user_in_transaction -> record audit in the same transaction
-> commit -> consume Redis challenge -> clear cookies
```

On a definite PostgreSQL rollback, release the Redis claim. After a committed update, failure to delete the Redis challenge is non-fatal because the advanced `session_epoch` makes replay fail closed.

- [ ] **Step 5: Map stable errors**

```text
invalid_email                         400
email_unchanged                       400
password_reauthentication_failed      401
password_reauthentication_unavailable 403
email_change_invalid_or_expired        400
email_change_code_invalid              401
email_change_rate_limited              429
email_change_unavailable               503
invalid_session                        401
```

Do not reveal whether the target email belongs to another account. Logs/audit must not contain the code, encrypted code, current password, target email, SMTP password or full challenge payload.

- [ ] **Step 6: Verify concurrency and replay**

Run:

```bash
./test_sh/test.sh --test email_change_api
cargo check --all-targets --all-features
```

The focused test must include two concurrent confirmations where exactly one commits, replay after success, expired challenge, stale session epoch, wrong code exhaustion and canonical-email conflict at confirmation time.

### Task 7: Wire the Real Profile and Email UI

**Files:**
- Modify: `web/src/pages/console/profile-apps.tsx`
- Modify: `web/src/pages/console/profile-editor-dialog.tsx`
- Modify: `web/src/pages/console/email-change-dialog.tsx`
- Modify: `web/src/pages/console/profile-apps.test.tsx`
- Modify: `web/src/api.ts`
- Modify: `web/src/api-types.ts`
- Modify: `web/src/api-response-guards.ts`

- [ ] **Step 1: Write RED UI tests for both email stages**

Assert:

```text
account profile dialog never contains an email field
email dialog stage 1 sends new_email + current_password with CSRF
202 response transitions to a six-digit code form and shows expiry
stage 2 sends challenge_id + code with CSRF
204 success clears auth state and navigates to /login?returnTo=%2Fconsole%2Fprofile
closing/resetting the dialog erases password, code and challenge id
Issue #558/#559 placeholder text and “等待接口接入” are absent
```

- [ ] **Step 2: Implement an explicit email dialog state machine**

```ts
type EmailChangeState =
  | { stage: 'request'; newEmail: string; password: string }
  | { stage: 'confirm'; challengeId: string; expiresAt: string; code: string }
```

Keep the dialog in `HudPanel`; do not place email controls back into the account-profile dialog. Disable actions while requests are in flight and preserve Escape/focus restoration.

- [ ] **Step 3: Add guarded API types and messages**

Add response guards for the 202 start payload and username-update `UserMe`. Add the stable codes from Tasks 4 and 6 to `safeMessages`. Never display raw backend detail strings.

- [ ] **Step 4: Verify frontend and build embedded assets**

Run:

```bash
npm --prefix web test
npm --prefix web run build
```

Expected: all Vitest tests pass and `web/dist` contains the final UI.

### Task 8: Synchronize OpenAPI, Documentation and Final Verification

**Files:**
- Modify: `openapi.yaml`
- Modify: `API.md`
- Modify: `README.md` only if current capability/status text is stale
- Modify: `docs/superpowers/plans/2026-08-18-account-security-backend-integration.md`

- [ ] **Step 1: Use the required OpenAPI skill**

Invoke the project-level `sync-openapi` skill after route/schema/error/auth changes. Document:

```text
PATCH /api/v1/auth/me username/current_password semantics and errors
POST /api/v1/auth/email-change/start
POST /api/v1/auth/email-change/confirm
Session Cookie + CSRF requirements
202/204 responses and stable error codes
TOTP/Passkey/external-binding response shapes and redirects
```

- [ ] **Step 2: Validate the contract**

Run the validator specified by the local `sync-openapi` skill, then:

```bash
./test_sh/test.sh --test openapi_contract
cargo fmt --check
cargo check --all-targets --all-features
CHENXING_TEST_ROLE=orchestrator ./test_sh/test.sh --clippy
CHENXING_TEST_ROLE=orchestrator ./test_sh/test.sh --audit
```

- [ ] **Step 3: Run all focused suites**

```bash
./test_sh/test.sh --test auth_factor_security_api
./test_sh/test.sh --test totp_factor_race
./test_sh/test.sh --test passkey_cas
./test_sh/test.sh --test passkey_rp_id_policy
./test_sh/test.sh --test external_identity_binding
./test_sh/test.sh --test user_profile_security_api
./test_sh/test.sh --test email_delivery
./test_sh/test.sh --test email_change_api
npm --prefix web test
npm --prefix web run build
```

- [ ] **Step 4: Check source-file size**

Invoke the project-level `src-line-limit` skill. Any changed source file above 500 lines must be split before completion; record 301-500 line weak warnings in the final report.

- [ ] **Step 5: Request one-time authorization only for the full suite**

Because the implementation changes PostgreSQL transactions, Redis state, Session revocation and authentication flows, ask the user for explicit one-time authorization before running:

```bash
CHENXING_TEST_ROLE=orchestrator ./test_sh/test.sh --full
```

Do not infer authorization from this plan. If authorization is not granted, report that focused tests and static checks passed and that CI must cover the full suite.

- [ ] **Step 6: Perform browser verification**

Run the backend on its configured port and Vite on the fixed `5175` port. Verify `http://localhost:5175/console/profile` at desktop and 375px widths:

```text
profile/email dialogs are separate and non-overlapping
username save uses the real API
email request/confirm transitions are usable
dynamic provider appears without JSX changes
TOTP QR/manual secret match
callback notices clear query parameters
no horizontal overflow
```

Attempt a real Passkey registration with the available platform authenticator. External hardware-key verification requires user hardware; if unavailable, report it as a manual residual check instead of claiming it passed.

- [ ] **Step 7: Final issue accounting**

Summarize evidence against #555, #556, #557, #558 and #559. Close an Issue only when its acceptance criteria are actually satisfied; otherwise leave it open with the remaining manual/environmental evidence stated precisely.
