# 首个管理员初始化 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在空数据库首次打开 Web 时创建唯一的首个 Owner 管理员，并在初始化完成后回到管理员登录页。

**Architecture:** 保留 `AdminService::bootstrap` 和 PostgreSQL advisory lock，在 HTTP 层增加匿名初始化状态查询并让初始化请求根据管理员是否存在决定是否公开放行。React 根入口先读取状态，未初始化时渲染与现有认证页一致的初始化表单。

**Tech Stack:** Rust, Axum, PostgreSQL, SQLx, React, TypeScript, Vite, OpenAPI.

---

### Task 1: Add backend regression tests

**Files:**
- Modify: `tests/admin_api.rs`
- Modify: `tests/protected_api.rs`

- [ ] Add an integration test that requests `GET /api/v1/admin/bootstrap/status` and asserts `{ "initialized": false }` for an isolated empty admin table.
- [ ] Extend the bootstrap integration test to submit without `Authorization`, assert `201`, then assert the status is `true` and a second anonymous request returns `409`.
- [ ] Add a protected API regression assertion that a non-empty admin table cannot use the anonymous bootstrap path.
- [ ] Add a service/repository test or integration loop with two bootstrap requests and assert exactly one `201` response.
- [ ] Run the focused admin tests and confirm the new expectations fail before implementation because the status route is absent and anonymous bootstrap is unauthorized.

### Task 2: Implement public bootstrap status and gate

**Files:**
- Modify: `src/admin/repository.rs`
- Modify: `src/admin/service.rs`
- Modify: `src/admin/auth_handlers.rs`
- Modify: `src/api.rs`

- [ ] Add a repository query returning whether any row exists in `admins`.
- [ ] Add a service method that exposes only the boolean initialization state.
- [ ] Add `bootstrap_status` returning `{initialized}` with no sensitive fields.
- [ ] Update `bootstrap_admin` to allow anonymous requests only when the service confirms no admin exists, while preserving Bearer-token compatibility for already-supported administrative setup calls but still returning conflict once initialized.
- [ ] Keep `insert_bootstrap` as the atomic transaction boundary with `pg_advisory_xact_lock`; do not implement a check-then-insert outside the transaction.
- [ ] Route `GET /api/v1/admin/bootstrap/status` and keep `POST /api/v1/admin/bootstrap` request/response behavior explicit.
- [ ] Re-run the focused tests and confirm all backend initialization cases pass.

### Task 3: Implement the frontend initialization gate

**Files:**
- Modify: `web/src/api.ts`
- Modify: `web/src/App.tsx`
- Create or modify: `web/src/pages/Bootstrap.tsx`

- [ ] Add typed API methods for bootstrap status and anonymous bootstrap creation.
- [ ] Add a root initialization gate that shows a small loading state while checking status, renders `Bootstrap` when uninitialized, and preserves current routes after initialization.
- [ ] Build the form with the existing dark starfield shell and shared UI primitives, validate email/password client-side, show server errors, disable submit while busy, and display success before navigating to `/login`.
- [ ] Ensure the page never exposes a role selector and never calls the admin login/session endpoint.
- [ ] Run the frontend build and verify the route behavior in the local browser.

### Task 4: Synchronize contracts and project guidance

**Files:**
- Modify: `openapi.yaml`
- Modify: `AGENTS.md`

- [ ] Document the public status endpoint, anonymous first-admin request, `201`, `400`, and `409` responses, and public security declarations in `openapi.yaml`.
- [ ] Add the first-open initialization behavior, one-admin-only boundary, reset expectation, and post-success login redirect to `AGENTS.md`.
- [ ] Run `python .codex/skills/sync-openapi/scripts/validate_openapi.py`.

### Task 5: Full verification

- [ ] Run `cargo fmt --check`.
- [ ] Run `cargo check --all-targets --all-features`.
- [ ] Run focused admin tests and then `cargo test --all-features`.
- [ ] Run the frontend build under `web`.
- [ ] Run `python .codex/skills/src-line-limit/scripts/check_src_lines.py` and record existing weak warnings; resolve any new strong warning.
- [ ] Re-check the browser at `http://127.0.0.1:5175/` for initialization, success message, and login redirect without committing test credentials to the repository.
