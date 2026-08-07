# Login Factors Design

## Goal

Add backend support for Google Authenticator-compatible TOTP and WebAuthn passkeys to normal user login. A password-only login creates a short-lived pending login, and a configured factor must complete the login before a normal user Session is issued. A user without a factor must enroll TOTP or a passkey during that first login transaction.

## Scope and flow

The existing JSON login endpoint and browser OAuth login endpoint share the same password-and-factor policy. The password step never creates a full Session when a factor is required.

1. The client submits email and password to `POST /api/v1/auth/login`. The optional `totp_code` completes an already configured TOTP login in one request.
2. If the password is valid and no factor is configured, the response is `202` with a `factor_setup_required` status and available methods. If a factor is configured but not completed, the response is `202` with `factor_required` and the available methods. The single-use ticket is carried by an HttpOnly browser cookie and bound to a separate holder cookie; it is not returned in the JSON body.
3. TOTP enrollment starts with the ticket and returns an `otpauth://` URI and the base32 secret once. A separate confirmation endpoint validates the six-digit code and atomically stores the encrypted secret before issuing the Session.
4. Passkey enrollment starts with the ticket and returns WebAuthn creation options. The finish endpoint validates the browser's registration response with `webauthn-rs`, stores the serialized public credential, and issues the Session.
5. Passkey login starts with a ticket and returns WebAuthn request options. The finish endpoint validates the assertion, updates the credential counter/backup state when required, consumes the ticket, and issues the Session.
6. Once a factor exists, normal login requires one configured factor. TOTP and passkey are alternatives; no factor bypass is exposed. Factor management after login is intentionally outside this change.

The browser OAuth flow uses the same pending-login ticket stored in Redis. The SPA receives only factor state and methods; the ticket and holder proof remain in HttpOnly cookies and do not enter page data or URLs. OAuth authorization remains blocked until the factor-complete Session is bound to the authorization request.

## Storage and security

- PostgreSQL adds `user_totp_factors` with one encrypted secret per user and `user_passkeys` with serialized WebAuthn public credentials. Both have foreign keys to `users` with cascade deletion.
- The TOTP secret is encrypted with the configured 32-byte application authentication key using the existing `aws-lc-rs` AEAD implementation. It is returned only during enrollment start and never logged or returned from status/list endpoints.
- Redis stores password-authenticated login tickets, a hash of the browser holder, WebAuthn registration/authentication state, user id, and expiry. Tickets and challenge state have a five-minute TTL and are consumed only after successful factor verification. Invalid factor attempts leave the ticket available until expiration; missing holder proofs and legacy unbound tickets fail closed.
- WebAuthn RP ID and origin are fixed configuration values derived from `APP_ISSUER` by default and can be explicitly set with `WEBAUTHN_RP_ID` and `WEBAUTHN_ORIGIN`. They are never derived from request headers.
- Login responses use generic factor errors and do not disclose password validity beyond the existing login contract. Audit events record factor type and result, not codes, secrets, or credential payloads.

## Testing

Unit tests cover TOTP code validation, six-digit input validation, encryption round trips, and login-factor state transitions. Integration tests cover the 202 pending response, TOTP enrollment and successful/failed login, ticket expiry/one-time use, passkey route challenge shapes, and browser OAuth blocking until factor completion. WebAuthn cryptographic ceremony tests use the library's supported fake authenticator where practical; no private key is sent to or stored by the service.
