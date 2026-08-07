# Browser Authentication Regressions Implementation Plan

> **For agentic workers:** Use test-driven development for every behavioral change and keep issue ownership separated while changes are in flight.

**Goal:** Resolve GitHub Issues #247 and #250-#255, restore fresh-browser authentication flows, and make public API timestamps conform to the documented RFC3339 contract.

**Architecture:** Keep CSRF enforcement fail-closed by requiring callers to explicitly mark only pre-session authentication requests. Represent authentication load failures as a recoverable UI state instead of treating them as logout. Serialize API-facing `OffsetDateTime` fields with explicit RFC3339 adapters while leaving Redis and other persisted payload formats unchanged.

**Tech Stack:** React, TypeScript, Vitest, Rust, Axum, Serde, PostgreSQL, Redis, Playwright/browser regression testing.

---

### Task 1: Lock fresh-browser and authentication-state regressions

**Files:**
- Modify: `web/src/api.test.ts`
- Add: `web/src/auth-state.test.tsx`
- Modify: `web/src/App.tsx` tests as needed

- [ ] Add a failing test proving explicitly marked pre-session POST requests reach `fetch` without a CSRF cookie.
- [ ] Preserve the existing failure for ordinary state-changing requests without CSRF.
- [ ] Add a failing provider test proving non-401 `/auth/me` failures leave loading and expose no retry path.

### Task 2: Implement explicit pre-session requests and recoverable auth errors

**Files:**
- Modify: `web/src/api.ts`
- Modify: `web/src/pages/auth.tsx`
- Modify: `web/src/pages/oauth.tsx` only if a pre-session factor call is present
- Modify: `web/src/auth-state.tsx`
- Modify: `web/src/App.tsx`

- [ ] Add an explicit request option that skips client-side CSRF only for pre-session calls.
- [ ] Mark bootstrap, registration, login, TOTP, and Passkey calls that occur before a session exists.
- [ ] Add a recoverable authentication error state with a retry action on protected routes.
- [ ] Keep 401 handling, logout race protection, and authenticated-session mutations unchanged.

### Task 3: Lock and correct API timestamp serialization

**Files:**
- Modify: `Cargo.toml`
- Add or modify: focused Rust serialization tests
- Modify: API response DTOs in `src/users`, `src/admin`, `src/audit.rs`, and `src/consents`
- Inspect/sync: `openapi.yaml`

- [ ] Add failing tests proving public timestamp fields serialize as RFC3339 strings.
- [ ] Enable only the `time` adapter feature required for field-level RFC3339 serialization.
- [ ] Apply explicit adapters at HTTP/API response boundaries without changing persisted session, authorization-code, or refresh-token JSON.
- [ ] Verify every OpenAPI `date-time` field matches the runtime response shape.

### Task 4: Resolve focused frontend issues

**Files:**
- Modify: `web/src/components/drawer-modal-effects.ts`
- Modify: redirect URI UX files identified by tests
- Modify: `web/src/pages/admin/users.tsx`
- Modify: `web/src/pages/console/integrate.tsx`

- [ ] Fix the TypeScript TS7022 build failure.
- [ ] Explain the literal loopback-IP redirect URI rule without weakening validation.
- [ ] Render disabled user status as `已禁用`.
- [ ] Replace the dead integration-document link with a real target.

### Task 5: Integrate and verify

- [ ] Review delegated changes for scope, security, accessibility, and consistency.
- [ ] Run frontend unit tests, TypeScript checking, and production build.
- [ ] Run Rust formatting, check, tests, and Clippy without concurrent Cargo jobs.
- [ ] Run OpenAPI validation and the project `src-line-limit` check.

### Task 6: Reset development data and run browser regression

- [ ] Confirm local development environment variables target only the development PostgreSQL and Redis instances.
- [ ] Use the repository's reset/migration scripts, or add a narrowly scoped development reset command if none exists.
- [ ] Start backend on port 3000 and Vite on fixed port 5175.
- [ ] Test fresh bootstrap, registration/login, TOTP or Passkey setup path, authenticated console/admin navigation, OAuth client creation, and redirect URI validation in the browser.
- [ ] Record sanitized evidence and update GitHub Issues #247 and #250-#255.
