# Security

This document describes controls that are implemented in code, not aspirations.

## Authentication

- Passwords are hashed with Argon2id.
- Access tokens are short-lived JWTs returned in the login body and held in memory by the SPA.
- Refresh tokens are opaque, stored hashed, set as `httpOnly` cookies scoped to `/api/v1/auth`.
- CSRF double-submit: a readable `cybertrace_csrf` cookie must be echoed as `X-CSRF-Token` on
  cookie-authenticated routes (`/auth/refresh`).
- Sessions are revocable. Changing a password signs out other sessions.
- Login is rate-limited per client and per account; lockout raises a security alert.

## Authorization

Permissions live in the database and are attached to roles. Code checks
`Permission` enum values via `require()`, never role name strings.

Separation of duties:

| Role | Can download evidence | Can sign reports | Sees all cases |
| --- | --- | --- | --- |
| Investigator | yes | no (unless granted) | no |
| Forensic analyst | yes | no | assigned only |
| Auditor | **no** | no | yes |
| Administrator | **no** | no | yes |

Object scoping is in SQL. A successful 200 on `/cases` for an investigator contains only
rows they are entitled to; the UI is not the filter.

Downloads require a stated `reason` query parameter, always use
`Content-Disposition: attachment` and `application/octet-stream`, and write a custody event
before streaming.

## Evidence at rest

Each object has a random AES-256-GCM data key, wrapped by `CYBERTRACE_MASTER_KEY`.
Nonce, wrapped key, and authentication tag are stored on `stored_objects`. Path traversal
is structurally avoided: keys are content-derived and resolved under the storage root.

## Tamper evidence

`custody_events` and `audit_log` are append-only:

- Application writers compute `entry_hash = SHA256(canonical_json || prev_hash)` and sign
  with Ed25519.
- Database triggers reject `UPDATE`/`DELETE`/`TRUNCATE`.
- A verifier replays the chain and reports breaks (`content_modified`, `sequence_gap`,
  `link_broken`, `invalid_signature`).

## HTTP hardening

Every response (including errors) receives:

- `Content-Security-Policy` (`default-src 'none'` on the API)
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Permissions-Policy` disabling camera, microphone, geolocation, USB
- `Cross-Origin-Opener-Policy` / `Cross-Origin-Resource-Policy`
- HSTS in production

CORS is an explicit origin allowlist with credentials. Production startup refuses default
secrets from `.env.example`.

## Logging and PII

Request ids propagate into audit and custody rows. Application logs redact secrets.
Interactive OpenAPI docs are disabled when `CYBERTRACE_ENV=production`.
