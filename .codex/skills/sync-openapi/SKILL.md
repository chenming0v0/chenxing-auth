---
name: sync-openapi
description: Use when adding, removing, or changing a backend HTTP route, request or response schema, error code, authentication rule, or OAuth/OIDC behavior in this repository.
---

# Sync OpenAPI

Keep the repository's backend contract and Apifox import source synchronized. The source of truth for the importable contract is `openapi.yaml` at the repository root; `API.md` is explanatory documentation and must not replace it.

## Workflow

1. Inspect `src/api.rs` and the handler/domain modules affected by the change. Record the exact method, path, path/query/header/form/JSON fields, status codes, response shape, error codes, cookies, redirects, and security requirements.
2. Update `openapi.yaml` in the same change. Add or update the relevant tag, `operationId`, parameters, request body, responses, reusable schema, and `security` declaration. Keep OAuth endpoints form-encoded and preserve PKCE, client authentication, cookie, and CSRF constraints.
3. Update `API.md` when user-facing examples or integration guidance changed. Keep the external Wiki entry `https://wiki.auth.clya.top/llms.txt` documented in `AGENTS.md`; do not invent or silently publish external content without explicit authorization.
4. Run the validation script:

```powershell
python .codex/skills/sync-openapi/scripts/validate_openapi.py
```

5. For code changes, also run the repository's required Rust checks and `.codex/skills/src-line-limit/scripts/check_src_lines.py`.

## Contract Rules

- Every implemented public route must have one OpenAPI path and a unique `operationId`.
- Every `{path_parameter}` must have a matching required `in: path` parameter.
- Do not document secrets, password hashes, private keys, or sensitive values in responses.
- Document one-time Client Secret responses explicitly; list and query responses must omit secrets.
- Use exact redirect URI and OAuth parameter constraints from the implementation. Do not document planned flows as available.
- Use `application/json` for JSON endpoints and `application/x-www-form-urlencoded` for `/oauth/token` and `/oauth/revoke`.
- Keep global reusable errors and security schemes in `components`; apply security per operation so public endpoints remain public.

## Common Mistakes

- Updating only `API.md` and forgetting `openapi.yaml`.
- Marking every endpoint as globally authenticated, which incorrectly protects health, registration, and login.
- Omitting CSRF headers from browser-session mutations.
- Treating OAuth redirects as JSON responses.
- Adding a path without documenting its required path parameter.
