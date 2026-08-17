# Migration-Gated Startup And Issuer Retry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Require successful schema migration before the web service starts and provide an explicit retry state when Issuer settings cannot load.

**Architecture:** Enforce ordering at the production Compose boundary and verify the embedded migration ledger in the read-only web startup path. Extend the shared settings loader with an observable failure flag, then render the existing `IssuerPanel` `HudPanel` as a retryable error state until a valid response arrives.

**Tech Stack:** Rust, SQLx, Docker Compose, React, TypeScript, Vitest, Testing Library.

---

### Task 1: Lock The Deployment Order

**Files:**
- Modify: `docker-compose.prod.yml`
- Modify: `tests/deployment.rs`

- [ ] Add a failing deployment contract test requiring `app.depends_on.migrate.condition: service_completed_successfully` and requiring the migration service to be available without an opt-in profile.
- [ ] Run `./test_sh/test.sh --lib` and confirm the new assertion fails against the current Compose file.
- [ ] Update the production Compose dependency graph so `migrate` completes successfully before `app` may start.
- [ ] Run `./test_sh/test.sh --lib` and confirm the deployment contract passes.

### Task 2: Reject A Stale Schema At Web Startup

**Files:**
- Modify: `src/db/mod.rs`
- Modify: `src/main.rs`
- Test: `src/db/migration_state_tests.rs`

- [ ] Add pure classification tests for a ledger whose latest successful version equals, trails, or is absent relative to the embedded latest version.
- [ ] Run `./test_sh/test.sh --lib` and confirm the stale/missing cases fail because no verifier exists.
- [ ] Add a read-only database ledger verification function and call it before `AppState::new_with_persisted_issuer` in the web path. Its error must name the observed and required versions and instruct the operator to run the migrate command.
- [ ] Run `cargo check --all-features` and `./test_sh/test.sh --lib`.

### Task 3: Make Issuer Loading Failure Retryable

**Files:**
- Modify: `web/src/pages/admin/settings/panel.tsx`
- Modify: `web/src/pages/admin/settings/issuer-panel.tsx`
- Create: `web/src/pages/admin/settings/issuer-panel.test.tsx`

- [ ] Add a failing Vitest case that returns HTTP 500 for the first Issuer GET, asserts a visible load-failure notice and retry button, then returns a valid payload and asserts the form appears after retry.
- [ ] Run the focused Vitest file and confirm it fails because the panel has no explicit failure state.
- [ ] Expose `failed` from `useSettingsResource`, clear it at reload start, set it on the active failed request, and clear it after a successful apply.
- [ ] Render a warning notice plus retry command inside the existing `HudPanel`; keep the form unavailable until settings have loaded.
- [ ] Run the focused Vitest file and the existing settings panel tests.

### Task 4: Build And Verify

**Files:**
- Update generated assets: `web/dist/**`

- [ ] Run the frontend build to synchronize embedded assets.
- [ ] Run `cargo fmt --check`, `cargo check --all-features`, and `cargo check --tests`.
- [ ] Run `CHENXING_TEST_ROLE=orchestrator ./test_sh/test.sh --clippy` and the allowed focused test commands.
- [ ] Run deployment shell/Compose validation required by the project deployment contract.
- [ ] Run `.codex/skills/src-line-limit/scripts/check_src_lines.py` and resolve any file above 500 lines.
- [ ] Review the final diff against both requirements and record any unavailable verification explicitly.
