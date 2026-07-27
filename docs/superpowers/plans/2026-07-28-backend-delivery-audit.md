# Backend Delivery Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Verify and finish the Rust backend delivery requirements, including tested deployment and multi-platform release automation.

**Architecture:** Keep the existing Axum, PostgreSQL, Redis, OAuth/OIDC, admin, session, and JWK module boundaries. Extend only the repository-level delivery automation: GitHub Actions packages each target into a versioned archive, generates checksums, and publishes tag releases; the Docker installer validates configuration before startup and prints service diagnostics on failure.

**Tech Stack:** Rust 1.94, Axum, PostgreSQL, Redis, Docker Compose v2, GitHub Actions, Bash.

---

### Task 1: Audit Existing Delivery Artifacts

**Files:**
- Inspect: `.github/workflows/build.yml`
- Inspect: `deploy/install.sh`
- Inspect: `docker-compose.prod.yml`
- Inspect: `README.md`, `AGENTS.md`

- [x] Confirm the backend is split into focused Rust modules and that generated secrets are ignored.
- [x] Confirm the installer creates or preserves `.env`, starts the production Compose stack, and checks `/health`.
- [x] Identify missing versioned release archives, checksums, and preflight/failure diagnostics.

### Task 2: Add Delivery Regression Tests

**Files:**
- Create: `tests/deployment.rs`

- [x] Add tests that assert all supported Rust targets remain in the release matrix.
- [x] Add tests that require artifact download, tag release publishing, and `SHA256SUMS` generation.
- [x] Add tests that require Compose preflight validation and application log diagnostics.
- [x] Run `cargo test --test deployment` and observe the missing delivery markers fail before implementation.

### Task 3: Complete Multi-Platform Release Automation

**Files:**
- Modify: `.github/workflows/build.yml`

- [x] Package Unix binaries as `.tar.gz` and Windows binaries as `.zip`.
- [x] Download all matrix artifacts on tag builds, generate `SHA256SUMS`, and publish a GitHub release.
- [x] Preserve Linux amd64/arm64 container publishing and all six binary targets.

### Task 4: Harden One-Command Docker Installation

**Files:**
- Modify: `deploy/install.sh`

- [x] Validate the production Compose configuration before starting containers.
- [x] Print application logs when the health check fails, along with Compose service status.
- [x] Preserve generated-secret behavior and safe repeat runs.

### Task 5: Verify and Document Delivery

**Files:**
- Modify: `README.md`
- Modify: `AGENTS.md`

- [x] Run formatting, tests, Clippy, coverage, source line checks, shell syntax, YAML parsing, and Compose parsing.
- [x] Confirm no secrets or generated files are tracked.
- [x] Commit the completed delivery changes.
