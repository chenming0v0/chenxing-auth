# Migration-Gated Startup And Issuer Retry Design

## Goal

Prevent the web service from serving requests against an unapplied database schema, and make an Issuer settings load failure visibly recoverable from the settings panel.

## Deployment Contract

The production Compose `app` service depends on a successful one-shot `migrate` service. Starting `app` through Compose therefore includes migrations even when an operator bypasses the installer. The installer keeps its explicit migration command so migration failures remain visible before replacement of the running application.

The Rust web startup path also verifies that the SQLx ledger contains the current embedded migration version before constructing application state. It does not mutate schema. A stale database makes the process exit with an actionable instruction to run `chenxing-auth migrate`, preventing request-time SQL errors such as the Issuer settings 500.

## Issuer Panel Contract

`useSettingsResource` exposes its failed state. `IssuerPanel` renders a warning notice and a dedicated retry button when the initial GET fails. The form is not rendered until a valid settings response exists, so the UI no longer resembles an enabled but ineffective save workflow.

The existing `HudPanel` remains the only panel container; no new glass or card styling is introduced.

## Verification

- Deployment contract tests assert the Compose dependency and startup ledger check.
- Rust unit tests cover current, stale, and missing ledger states without executing database integration tests.
- Vitest renders the Issuer panel through a failed GET, checks the retry state, then verifies a successful retry restores the form.
- Production frontend assets are rebuilt into `web/dist`.
