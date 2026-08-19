# Bootstrap Navigation Guard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Preserve automatic first-deployment bootstrap navigation without issuing the expected initialized-instance `404` from the production SPA.

**Architecture:** A request middleware makes the bootstrap decision only for browser HTML document navigations before static fallback. React trusts the selected document path and never probes bootstrap status. Vite development forwards a `HEAD` document-navigation check to the backend and only relays redirects before serving its SPA shell. The existing hidden `bootstrap/status` API contract remains unchanged.

**Tech Stack:** Rust, Axum middleware, PostgreSQL-backed `UserService`, React/Vite, Vitest.

---

### Task 1: Add failing navigation-guard tests

**Files:**
- Modify: `src/api/mod.rs`
- Test: `src/api/mod.rs` unit tests or a focused `src/api/navigation_guard_tests.rs` module
- Test: `tests/bootstrap_invariant.rs`

- [x] **Step 1: Define the pure navigation classification contract**

Cover `GET`/`HEAD` HTML document requests, reject API paths, protocol paths, assets,
non-HTML requests, and requests without browser metadata that are not HTML navigations.

- [x] **Step 2: Run the focused Rust tests and verify the new cases fail**

Run `cargo test --lib api::tests` only through the repository runner when the test target is
available; otherwise use `cargo check --tests` for compile feedback and the focused runner target.
Expected: the new redirect decision tests fail because no guard exists yet.

- [x] **Step 3: Add the integration regression scenario**

Use the existing isolated database setup in `tests/bootstrap_invariant.rs`, send
`Accept: text/html` and `Sec-Fetch-Dest: document`, and assert:

```text
empty database + GET /login      -> 307 /bootstrap
empty database + GET /bootstrap  -> SPA shell (200)
Owner exists + GET /bootstrap    -> 307 /login
Owner exists + GET /login        -> SPA shell (200)
```

### Task 2: Implement the server navigation guard

**Files:**
- Modify: `src/api/mod.rs`
- Test: `src/api/mod.rs` and `tests/bootstrap_invariant.rs`

- [x] **Step 1: Add a middleware function with `State<AppState>`**

The function should:

```rust
if !is_html_document_navigation(&request) {
    return next.run(request).await;
}
if is_bootstrap_path(&request) {
    if state.users.owner_initialized().await == Ok(true) {
        return temporary_redirect("/login");
    }
    return next.run(request).await;
}
if state.users.owner_initialized().await == Ok(false) {
    return temporary_redirect("/bootstrap");
}
next.run(request).await
```

Log database errors with a non-sensitive event and continue to static delivery. Keep protocol and
asset requests outside this branch.

- [x] **Step 2: Install the middleware around the existing router**

Place it in `api::router` before the static fallback and alongside the existing security/timeout
layers so redirects receive the same security headers without changing application route matching.

- [x] **Step 3: Run the focused Rust tests and verify they pass**

Run the navigation unit tests and the single `bootstrap_invariant` integration target through
`test_sh/test.sh --test bootstrap_invariant` with the permitted role.

### Task 3: Remove the SPA bootstrap probe

**Files:**
- Modify: `web/src/auth-state.tsx`
- Modify: `web/src/pages/auth.tsx`
- Test: `web/src/auth-state.test.tsx`

- [x] **Step 1: Derive bootstrap state from the selected document path**

Initialize `/bootstrap` as `required` and other document paths as `ready`. Remove
`refreshBootstrap()` and all loading/error states tied to the anonymous status request.

- [x] **Step 2: Complete bootstrap locally after Owner creation**

After a successful Owner creation, show the success state, change bootstrap to `ready`, and navigate
to `/login` without another status request.

- [x] **Step 3: Add a regression assertion**

Assert that normal startup and a server-routed `/bootstrap` document only request `/auth/me` and
never call `/api/v1/admin/bootstrap/status`.

### Task 4: Preserve navigation behavior in Vite development

**Files:**
- Modify: `web/vite.config.ts`
- Add: `web/src/bootstrap-navigation.ts`
- Test: `web/src/bootstrap-navigation.test.ts`

- [x] **Step 1: Share a pure document-navigation classifier**

Match the backend's method, `Accept`, fetch destination, API/protocol, and asset exclusions.

- [x] **Step 2: Add Vite document navigation middleware**

For matching requests, issue a backend `HEAD` request with redirects disabled. Relay temporary or
permanent redirect responses and otherwise continue to Vite's SPA fallback.

- [x] **Step 3: Cover routing classification**

Verify page navigations are included while API, external OAuth, static asset, extension-bearing,
encoded, and non-document requests are excluded.

### Task 5: Build and verify the combined behavior

**Files:**
- Regenerate: `web/dist/*` using the existing web build command

- [x] **Step 1: Run formatting and compile checks**

Run `cargo fmt --check` and `cargo check --all-features`.

- [x] **Step 2: Run focused backend and frontend tests**

Run the focused Rust integration target with `test_sh/test.sh --test bootstrap_invariant` and the
relevant Vitest files from `web`.

- [x] **Step 3: Rebuild the production frontend**

Run the existing `web` build script so the embedded `web/dist` artifact matches the source.

- [x] **Step 4: Run `src-line-limit` and inspect the final diff**

Record any line-limit warnings and confirm `README.md` remains the only unrelated pre-existing
worktree modification.
