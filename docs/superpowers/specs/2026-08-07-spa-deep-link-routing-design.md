# SPA Deep-Link Routing Design

**Date:** 2026-08-07

**Issues:** #248, #249

## Goal

Make every React-owned deep link reachable through the Rust single-binary server while preserving JSON/protocol semantics for real API, OAuth/OIDC, discovery, health, and missing-asset requests.

## Current Failure

The router currently has two independent conflicts:

1. `src/api/static_files.rs` classifies the entire `/oauth/*` namespace as protocol traffic. React routes such as `/oauth/account`, `/oauth/consent`, and `/oauth/redirect` therefore receive JSON 404 responses instead of the embedded Vite `index.html` shell.
2. `src/api/routes.rs` explicitly registers React-owned `/admin` routes whose handlers redirect to the same URL. Because explicit Axum routes run before the static fallback, `/admin`, `/admin/users`, `/admin/clients`, and `/admin/audit` loop forever with 303 responses.

## Chosen Design

Use route ownership as the boundary:

- Axum explicitly owns real HTTP protocol/API endpoints.
- The static fallback owns React page routes and returns the embedded SPA shell for `GET`/`HEAD` requests without file extensions.
- Legacy server-rendered URLs may remain explicit only when they redirect to a *different* React URL.

Concretely:

- Remove explicit Rust registrations for `/admin`, `/admin/users`, `/admin/clients`, and `/admin/audit`.
- Remove the now-unused same-path redirect handlers.
- Keep `/admin/login -> /login` and `/admin/settings/oauth -> /admin/settings`, including query preservation.
- Replace the broad `/oauth/*` protocol prefix test with an exact allowlist for `/oauth/authorize`, `/oauth/token`, `/oauth/revoke`, and `/oauth/userinfo`.
- Leave `/api`, `/.well-known`, health probes, non-GET/HEAD fallback behavior, and missing static-asset behavior unchanged.

## Rejected Alternatives

### Serve the SPA shell from each Rust page handler

This would duplicate the static fallback's embedded HTML response logic and require every new React route to be registered twice. It preserves the ownership conflict instead of removing it.

### Add a broad `/oauth` nested router before the fallback

A nested router would still need to distinguish protocol endpoints from React pages. It adds routing machinery without improving the exact ownership rule.

## Error And Security Semantics

- Unknown `/api/*` paths remain JSON 404 responses.
- Unknown `/oauth/*` paths fall back to the React SPA shell; only the four real
  protocol endpoints are protocol-owned. This is the intended consequence of
  the exact allowlist: protocol and React ownership no longer share one prefix.
- Registered OAuth protocol endpoints continue reaching their handlers and never receive HTML fallback responses.
- Missing `.js`, `.css`, `.ico`, and other extension-bearing assets remain JSON 404 responses rather than `200 text/html`.
- Non-GET/HEAD unknown paths remain 404 and never receive the SPA shell.
- Query strings on React deep links are preserved naturally because the fallback serves the current request without redirecting.
- Legacy redirects preserve query strings but must always change the path.

## Test Strategy

1. Unit-test protocol classification with both real OAuth endpoints and React OAuth pages.
2. Integration-test direct `GET` requests for all affected `/admin` and `/oauth` React routes, asserting final `200 text/html` responses with no `Location` header.
3. Preserve tests for `/admin/login` and `/admin/settings/oauth` redirects to different destinations.
4. Extend an existing OAuth authorization integration flow: obtain the `303 /oauth/consent?request_id=...` response, follow that location through the same Router, and assert the final response is the SPA shell.
5. Use a real browser against backend port 3000, not only Vite port 5175, because the regression exists in Rust static fallback routing.

## Completion Criteria

- Direct navigation and hard refresh work for `/admin`, `/admin/users`, `/admin/clients`, `/admin/audit`, `/oauth/account`, `/oauth/consent`, and `/oauth/redirect` through port 3000.
- `/oauth/authorize` still behaves as a protocol endpoint.
- The authorize-to-consent redirect can be followed to HTML.
- All focused and full tests pass, OpenAPI validation remains clean, and no source file exceeds 500 lines.
