# Deterministic Deployment Migration Test Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the deployment migration inventory assertion deterministic across Windows and Linux without weakening its exact-file validation.

**Architecture:** Keep the deployment test as the single repository-level check for the complete SQL migration inventory. Normalize the filesystem boundary by sorting collected migration filenames before comparing them with the canonical ordered list, because `std::fs::read_dir` does not guarantee iteration order.

**Tech Stack:** Rust standard library, Cargo integration tests

---

### Task 1: Normalize Migration Inventory Ordering

**Files:**
- Modify: `tests/deployment.rs:73`
- Test: `tests/deployment.rs:62`

- [ ] **Step 1: Confirm the existing regression evidence**

Use the supplied GitHub Actions output as the red phase. It must show that all five expected migration filenames are present but `database_uses_explicit_unified_baseline_migrations` fails because the Linux directory iterator returns them in this order:

```text
0004_relax_deleted_session_outbox_target.sql
0005_session_outbox_event_user.sql
0001_initial.sql
0002_plans.sql
0003_session_outbox.sql
```

Expected: the left and right lists contain identical filenames in different orders.

- [ ] **Step 2: Sort the collected filenames at the filesystem boundary**

Change the immutable collection to a mutable vector and sort it before the exact assertion:

```rust
let mut migrations = std::fs::read_dir("migrations")
    .expect("migrations directory")
    .filter_map(Result::ok)
    .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "sql"))
    .map(|entry| entry.file_name())
    .collect::<Vec<_>>();
migrations.sort();
```

Do not convert the comparison to a set or remove the expected vector. The assertion must continue to reject missing, duplicate, or unexpected SQL migration files.

- [ ] **Step 3: Run the focused deployment test**

Run:

```powershell
cargo test --all-features --test deployment database_uses_explicit_unified_baseline_migrations
```

Expected: `1 passed; 0 failed`.

- [ ] **Step 4: Run the complete deployment test target**

Run:

```powershell
cargo test --all-features --test deployment
```

Expected: `7 passed; 0 failed`.

- [ ] **Step 5: Run repository verification**

Run sequentially so Cargo processes do not contend for the target lock:

```powershell
cargo fmt --check
cargo check --all-targets --all-features
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
```

Expected: every command exits with code `0`; the deployment failure does not recur.

- [ ] **Step 6: Check source file line limits**

Count lines for tracked `src/**/*.rs` files and report every file above 300 lines. Treat files above 500 lines as blocking unless the user explicitly accepts an exception.

- [ ] **Step 7: Review the final diff**

Run:

```powershell
git diff --check
git diff -- tests/deployment.rs docs/superpowers/plans/2026-08-01-deterministic-deployment-migration-test.md
```

Expected: no whitespace errors, and the implementation diff contains only the deterministic sort needed by this plan plus this plan document.
