# UI Backend Interfaces Design

## Goal

Provide stable JSON APIs for a future Chenxing Pass user center, administrator console, and browser OAuth consent UI. Existing protocol and administrative routes remain compatible. New browser mutations use the existing HttpOnly session cookie, CSRF cookie, and `X-CSRF-Token` binding rules.

## Scope

### User center

- `GET /api/v1/auth/status` returns whether the browser has an active user session. It does not reveal account data when unauthenticated.
- `GET /api/v1/auth/me` returns the authenticated user's public profile and the current session expiration.
- `PATCH /api/v1/auth/me` accepts `display_name` and returns the updated public profile. It requires the user session and user CSRF validation.
- `POST /api/v1/auth/password` accepts `current_password` and `new_password`. It validates the current credential, updates the slow hash, and revokes all of the user's sessions after the password changes. It requires the user session and CSRF validation.
- `GET /api/v1/auth/sessions` returns session metadata owned by the authenticated user. Each item contains only an opaque session ID, creation time, expiration time, and a `current` flag.
- `DELETE /api/v1/auth/sessions/{session_id}` revokes one session owned by the authenticated user. It requires the user session and CSRF validation; revoking the current session also clears the browser cookies.

The account API does not expose password hashes, CSRF values, session payloads, IP addresses, user agents, or business data owned by downstream clients.

### Administrator console

- `GET /api/v1/admin/auth/me` returns the authenticated administrator's ID, email, role, explicit permissions, status, and current administrator-session expiration.
- `GET /api/v1/admin/overview` returns aggregate counts for users, OAuth clients, administrators, and audit events. It requires `ReadAudit` for the audit count and the least permission needed for each other count; the handler returns a stable object with nullable restricted counts when a role lacks that permission.
- `GET /api/v1/admin/users/query` returns `{items, page, page_size, total}` and supports `page`, `page_size`, `search`, and `status`. It requires `ManageUsers`.
- `GET /api/v1/admin/clients/query` returns the same pagination envelope and supports `page`, `page_size`, `search`, and `status`. It requires `ManageClients`.
- `GET /api/v1/admin/audit/query` returns the same pagination envelope and supports `page`, `page_size`, `action`, `resource_type`, and a UTC time range. It requires `ReadAudit`.

Existing array-based list routes remain unchanged for current consumers. Console query routes never return password hashes, client secret hashes, client secrets, private keys, or raw sensitive audit values. Bearer administrator authentication remains supported for API clients. Browser-session mutations continue to require the separate administrator CSRF cookie and header.

### OAuth and login UI

- `GET /api/v1/oauth/authorize/requests/{request_id}` returns the pending request for the current user session: client display name, client ID, redirect host, requested scopes, and request expiration. It rejects missing, expired, already-consumed, or differently-bound sessions.
- `POST /api/v1/oauth/authorize/requests/{request_id}` accepts `decision` equal to `approve` or `deny`. It requires user CSRF validation and atomically consumes the request. Approval issues the existing one-time authorization code and returns the validated redirect URL. Denial returns the OAuth error redirect data without leaking the authorization code.
- Existing HTML `/auth/login` and `/oauth/authorize/consent` flows continue to use the same pending request store and behavior. The JSON UI flow shares validation and consumption services with them.

## Data and storage

Add migration `0004_ui_sessions.sql` with a `user_sessions` table containing session ID, user ID, creation time, expiration time, revoked time, and an index on `(user_id, created_at DESC)`. This table is metadata only. The Redis session payload remains the source of truth for active session secrets and CSRF binding.

On login, create the Redis session and its metadata record. Session lookup requires an active Redis payload and an unexpired, non-revoked metadata row. Revocation removes the Redis payload and marks the metadata row revoked. Password changes revoke all metadata rows and Redis sessions belonging to the user through a user-session index maintained by the session store. Expired metadata is excluded from queries and may be retained for auditability.

Pending OAuth requests must include the initiating session ID. JSON and HTML consent handlers verify that the current session matches it before exposing or consuming the request. The existing authorization code remains bound to client, redirect URI, user, scopes, PKCE challenge, and nonce.

## Layering

HTTP handlers only extract inputs, invoke application services, and map typed errors to the existing error response shape. User profile/password and session orchestration belongs in user/session services. Query and count operations belong in repositories. OAuth request inspection and decision logic belongs beside the existing authorization request and consent services. Response DTOs are private to the HTTP layer and do not expose infrastructure types.

## Validation and errors

Use the existing JSON error envelope and stable error codes. Validate page bounds, search length, status/action filters, display-name length, and password policy before database or Redis work. Authentication failures must not reveal whether an email exists. Malformed or unauthorized OAuth requests return generic protocol-safe errors. Sensitive values are excluded from logs and audit details.

## Testing

- Add domain tests for profile validation, password policy, session ownership, pagination bounds, and OAuth decision parsing.
- Add API tests for authenticated/unauthenticated status, profile update, password rotation and session revocation, CSRF failures, admin permission isolation, query filters, and OAuth request binding/one-time consumption.
- Add repository/integration coverage for session metadata lifecycle and user-wide revocation using the existing PostgreSQL and Redis test setup.
- Update `openapi.yaml` for every new route, schema, parameter, response, security declaration, and CSRF header. Run the repository OpenAPI validator and all required Rust checks.

## Compatibility and rollout

Implement in three focused slices: user center, administrator console, then OAuth/login UI. Each slice keeps existing routes working, adds tests before production code, updates OpenAPI in the same change, and runs the source line checker. No downstream business records or client-owned profile data are added to this authentication service.
