# SPA Deep-Link Routing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix GitHub Issues #248 and #249 so React-owned OAuth and admin deep links are served by the Rust SPA fallback without weakening protocol/API 404 behavior.

**Architecture:** Remove explicit same-path Rust routes for React pages, keep only legacy redirects whose destination differs, and replace the broad `/oauth/*` protocol classification with an exact real-endpoint allowlist. Lock behavior at unit, router-integration, OAuth-flow, and real-browser levels.

**Tech Stack:** Rust, Axum, tower-http `ServeDir`, Tokio integration tests, React/Vite static build, Codex in-app browser.

**Execution Constraint:** Work only in the Windows repository. Do not use WSL, commit, push, close Issues, reset unrelated changes, or expose credentials. Run Cargo commands sequentially.

---

### Task 1: Lock direct-navigation regressions

**Files:**
- Modify: `src/api/static_files.rs:103-111`
- Modify: `tests/protected_api.rs:79-187`
- Modify: `tests/web.rs:37-68`

- [ ] **Step 1: Add failing protocol-classification assertions**

Extend the `is_protocol_path` unit test so real endpoints remain protocol-owned while React pages are explicitly excluded:

```rust
for path in [
    "/oauth/authorize",
    "/oauth/token",
    "/oauth/revoke",
    "/oauth/userinfo",
] {
    assert!(is_protocol_path(path), "{path}");
}

for path in ["/oauth/account", "/oauth/consent", "/oauth/redirect"] {
    assert!(!is_protocol_path(path), "{path}");
}
```

- [ ] **Step 2: Replace self-redirect expectations with final SPA response assertions**

In `tests/protected_api.rs`, split React pages from true legacy redirects. For React pages, assert `200`, `text/html`, and no `Location` header:

```rust
for uri in [
    "/admin",
    "/admin?tab=overview",
    "/admin/users?search=alice&page=2",
    "/admin/clients?page=3",
    "/admin/audit?action=login",
] {
    let response = router.clone().oneshot(get(uri)).await.expect("SPA response");
    assert_eq!(response.status(), StatusCode::OK, "{uri}");
    assert_eq!(content_type(&response), Some("text/html"), "{uri}");
    assert!(!response.headers().contains_key(LOCATION), "{uri}");
}
```

Add a small local helper for GET requests and MIME-only content type parsing instead of duplicating builders.

- [ ] **Step 3: Add direct OAuth SPA route integration assertions**

Extend `tests/web.rs` or the focused router test to cover:

```rust
for uri in [
    "/oauth/account",
    "/oauth/consent?request_id=test-request",
    "/oauth/redirect?redirect_to=https%3A%2F%2Fclient.example%2Fcallback",
] {
    assert_spa_shell(router.clone(), uri).await;
}
```

- [ ] **Step 4: Run focused tests and confirm the red state**

Run sequentially:

```powershell
cargo test --lib api::static_files::tests::is_protocol_path_recognizes_api_oauth_wellknown_prefixes -j 1
cargo test --test protected_api admin_routes_forward_to_the_react_spa -j 1
cargo test --test web rust_forwards_root_and_spa_paths_to_the_compiled_react_app -j 1
```

Expected before implementation: OAuth SPA classification and admin direct-navigation assertions fail.

### Task 2: Correct route ownership

**Files:**
- Modify: `src/api/static_files.rs:88-111`
- Modify: `src/api/routes.rs:31-35,173-178`
- Modify: `src/admin/web_handlers.rs:1-39`

- [ ] **Step 1: Replace broad OAuth-prefix classification with an exact allowlist**

Implement the protocol boundary without changing API, discovery, health, or asset rules:

```rust
fn is_protocol_path(path: &str) -> bool {
    path == "/api"
        || path.starts_with("/api/")
        || matches!(
            path,
            "/oauth/authorize" | "/oauth/token" | "/oauth/revoke" | "/oauth/userinfo"
        )
        || path == "/.well-known"
        || path.starts_with("/.well-known/")
        || path.starts_with("/health/")
}
```

Do not classify `/oauth/account`, `/oauth/consent`, `/oauth/redirect`, or the entire `/oauth/*` namespace as protocol traffic.

- [ ] **Step 2: Remove React-owned admin routes from Axum registration**

Delete explicit registrations for:

```rust
.route("/admin", get(dashboard))
.route("/admin/users", get(users_page))
.route("/admin/clients", get(clients_page))
.route("/admin/audit", get(audit_page))
```

Keep:

```rust
.route("/admin/login", get(login_page).post(login_submit))
.route("/admin/settings/oauth", get(oauth_settings))
```

Update imports so removed handlers are not referenced.

- [ ] **Step 3: Delete same-path redirect handlers**

Reduce `src/admin/web_handlers.rs` to the `/admin/login -> /login` legacy redirect behavior. Preserve query strings for both GET and POST. Do not add an HTML renderer to Rust.

- [ ] **Step 4: Run focused tests and confirm green**

Run:

```powershell
cargo test --lib api::static_files::tests::is_protocol_path_recognizes_api_oauth_wellknown_prefixes -j 1
cargo test --test protected_api -j 1
cargo test --test web -j 1
```

Expected: all focused tests pass; `/admin/login` and `/admin/settings/oauth` still redirect to different paths.

### Task 3: Follow authorize redirect to the SPA shell

**Files:**
- Modify: `tests/oauth_token_flow.rs` around the existing first-consent authorization flow

- [ ] **Step 1: Extend the existing authorization flow test**

Immediately after asserting the authorization response redirects to `/oauth/consent?request_id=...`, follow the returned relative location with the same cloned Router:

```rust
let consent_response = router
    .clone()
    .oneshot(
        Request::builder()
            .uri(location)
            .body(Body::empty())
            .expect("consent SPA request"),
    )
    .await
    .expect("consent SPA response");

assert_eq!(consent_response.status(), StatusCode::OK);
assert_eq!(
    consent_response.headers().get(CONTENT_TYPE).and_then(|value| value.to_str().ok()),
    Some("text/html; charset=utf-8")
);
```

Reuse the redirect string before consuming it to parse `request_id`. Do not follow external client redirects.

- [ ] **Step 2: Run the focused OAuth flow**

```powershell
cargo test --test oauth_token_flow -j 1
```

Expected: the authorize response remains `303`, and following its consent location returns the embedded React shell.

### Task 4: Validate contract and full suite

**Files:**
- Inspect: `openapi.yaml`
- Inspect: `API.md`

- [ ] **Step 1: Confirm OpenAPI requires no route-contract edit**

The changed paths are static React pages, not public API operations. Do not add SPA page paths to OpenAPI. Run the project validator to prove the existing API contract remains valid:

```powershell
py .codex/skills/sync-openapi/scripts/validate_openapi.py
```

- [ ] **Step 2: Build the React artifact before Rust final verification**

```powershell
cd web
npm test
npm run build
cd ..
```

- [ ] **Step 3: Run Rust checks sequentially with the backend stopped**

```powershell
cargo fmt --check
cargo check --all-targets --all-features -j 1
cargo test --all-features -j 1
cargo clippy --all-targets --all-features -j 1 -- -D warnings
```

- [ ] **Step 4: Run repository policy checks**

```powershell
py .codex/skills/src-line-limit/scripts/check_src_lines.py
git diff --check
```

No source file may exceed 500 lines. Report all 301-500 line weak warnings.

### Task 5: Main-agent browser acceptance on port 3000

**Owner:** Main agent, not sol_max.

- [ ] **Step 1: Restart the newly built backend and verify health**

Start `target/debug/chenxing-auth.exe` from the Windows repository and verify `GET http://127.0.0.1:3000/health` returns 200.

- [ ] **Step 2: Verify admin hard navigation and refresh**

Using the browser against `http://127.0.0.1:3000`, directly navigate to and reload:

```text
/admin
/admin/users
/admin/clients
/admin/audit
```

Each path must return the React shell without `ERR_TOO_MANY_REDIRECTS`. Authentication redirects performed by React are acceptable; HTTP self-redirects are not.

- [ ] **Step 3: Verify OAuth React pages**

Directly navigate to:

```text
/oauth/account
/oauth/consent?request_id=invalid-browser-check
/oauth/redirect
```

Each must render the React application rather than a JSON 404 document. The invalid consent id may produce an in-app safe error after the shell loads.

- [ ] **Step 4: Verify protocol endpoints remain protocol-owned**

Request `/oauth/authorize` without required parameters and confirm the response is the protocol handler's structured error/redirect behavior, not the landing SPA shell.

- [ ] **Step 5: Record sanitized evidence**

Update GitHub Issues #248 and #249 with exact test commands and browser outcomes. Do not include cookies, request ids, credentials, secrets, or private configuration. Keep Issues open until the implementation is committed and pushed.
