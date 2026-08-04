# OAuth Token Validation Order Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ensure unsupported OAuth token grant types return `unsupported_grant_type` without querying PostgreSQL or Redis.

**Architecture:** Keep form parsing and syntactic client credential resolution at the HTTP boundary, but dispatch only supported grant types into dependency-backed processing. Plan-based QPS enforcement remains fail-closed for supported grants.

**Tech Stack:** Rust, Axum, Tokio, Tower integration tests.

---

### Task 1: Lock the regression behavior

**Files:**
- Modify: `tests/oauth_api.rs`

- [ ] Assert that the unsupported grant response body contains `unsupported_grant_type`.
- [ ] Run the focused test and confirm it fails with `temporarily_unavailable` before production changes.

### Task 2: Correct token request dispatch order

**Files:**
- Modify: `src/oauth/token_handlers.rs`

- [ ] Reject grant types other than `authorization_code` and `refresh_token` before resolving dependency-backed QPS state.
- [ ] Preserve client credential parsing, QPS fail-closed behavior, and existing supported grant flows.

### Task 3: Verify repository requirements

**Files:**
- Inspect: `openapi.yaml`

- [ ] Run the focused OAuth API test and the OAuth-related test targets.
- [ ] Run formatting, check, test, Clippy, OpenAPI validation, and source line-limit validation.
- [ ] Record any unavailable verification tools or source-size warnings.
