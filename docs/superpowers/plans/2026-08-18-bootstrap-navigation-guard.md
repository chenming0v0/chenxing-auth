# Bootstrap Navigation Guard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve automatic first-deployment bootstrap navigation without issuing the expected initialized-instance `404` from the production SPA.

**Architecture:** A request middleware makes the bootstrap decision only for browser HTML document navigations before static fallback. Production React trusts that navigation decision and skips the status probe; Vite development retains the probe because Vite owns the document shell. The existing hidden `bootstrap/status` API contract remains unchanged.

**Tech Stack:** Rust, Axum middleware, PostgreSQL-backed `UserService`, React/Vite, Vitest.

---

### Task 1: Add failing navigation-guard tests

**Files:**
- Modify: `src/api/mod.rs`
- Test: `src/api/mod.rs` unit tests or a focused `src/api/navigation_guard_tests.rs` module
- Test: `tests/bootstrap_invariant.rs`

- [ ] **Step 1: Define the pure navigation classification contract**

Cover `GET`/`HEAD` HTML document requests, reject API paths, protocol paths, assets,
non-HTML requests, and requests without browser metadata that are not HTML navigations.

- [ ] **Step 2: Run the focused Rust tests and verify the new cases fail**

Run `cargo test --lib api::tests` only through the repository runner when the test target is
available; otherwise use `cargo check --tests` for compile feedback and the focused runner target.
Expected: the new redirect decision tests fail because no guard exists yet.

- [ ] **Step 3: Add the integration regression scenario**

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

- [ ] **Step 1: Add a middleware function with `State<AppState>`**

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

- [ ] **Step 2: Install the middleware around the existing router**

Place it in `api::router` before the static fallback and alongside the existing security/timeout
layers so redirects receive the same security headers without changing application route matching.

- [ ] **Step 3: Run the focused Rust tests and verify they pass**

Run the navigation unit tests and the single `bootstrap_invariant` integration target through
`test_sh/test.sh --test bootstrap_invariant` with the permitted role.

### Task 3: Make the production SPA stop probing

**Files:**
- Modify: `web/src/auth-state.tsx`
- Modify: `web/src/pages/auth.tsx`
- Test: `web/src/auth-state.test.tsx`

- [ ] **Step 1: Add a development-only probe predicate**

Use `import.meta.env.DEV` to keep the existing `refreshBootstrap()` request and transient-error
semantics in Vite tests/development while initializing production bootstrap state as `ready`.

- [ ] **Step 2: Remove the post-bootstrap production re-probe**

After a successful Owner creation, set the existing success state directly. In development,
continue refreshing the probe so the current local behavior stays covered.

- [ ] **Step 3: Add a regression assertion**

Stub `import.meta.env.DEV` through the existing Vitest setup or isolate the predicate and assert
that production initialization does not call `/api/v1/admin/bootstrap/status`.

### Task 4: Build and verify the combined behavior

**Files:**
- Regenerate: `web/dist/*` using the existing web build command

- [ ] **Step 1: Run formatting and compile checks**

Run `cargo fmt --check` and `cargo check --all-features`.

- [ ] **Step 2: Run focused backend and frontend tests**

Run the focused Rust integration target with `test_sh/test.sh --test bootstrap_invariant` and the
relevant Vitest files from `web`.

- [ ] **Step 3: Rebuild the production frontend**

Run the existing `web` build script so the embedded `web/dist` artifact matches the source.

- [ ] **Step 4: Run `src-line-limit` and inspect the final diff**

Record any line-limit warnings and confirm `README.md` remains the only unrelated pre-existing
worktree modification.
