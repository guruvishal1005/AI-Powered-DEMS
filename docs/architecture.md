# Architecture

CYBERTRACE is a FastAPI application with a React console. The API is the system of
record. The interface never invents metrics, never hides unauthorized rows, and never
treats model output as a forensic fact.

## Process layout

- **API** (`backend/`) — FastAPI, SQLAlchemy 2.0, Pydantic v2. One process serves HTTP
  and, in development, an in-process asyncio worker that claims jobs from PostgreSQL.
- **Console** (`frontend/`) — React 19, Vite, TypeScript, Tailwind 4, TanStack Query.
  Access tokens live in memory. Refresh tokens are httpOnly cookies.
- **PostgreSQL 18** — the only required service. Compose file in `ops/`.
- **Object store** — content-addressed files under `CYBERTRACE_STORAGE_ROOT`, each
  envelope-encrypted with AES-256-GCM.

```
SPA  →  /api/v1  →  routers (authn, require(permission), HTTP) 
                 →  services(RequestContext, …)
                 →  models / forensics / analysis / storage
                 →  PostgreSQL + encrypted objects
Worker ← jobs table (FOR UPDATE SKIP LOCKED)
```

## Layers

Routers are thin. Every mutating service method receives a `RequestContext` so audit and
custody writers always know who acted, from where, and under which request id.

Authorization is two independent layers:

1. `require(Permission.*)` — deny by default, 403 if the caller lacks the grant.
2. `apply_case_scope` / `scope_case_ids` — investigators and analysts only *select* casesf
   they own or are assigned to. Auditors and administrators have `case:read_all`.

`evidence:download` and `report:sign` are intentionally absent from the administrator and
auditor roles.

## Evidence and integrity

Uploads are streamed. SHA-256 is computed over plaintext. The object is stored as
ciphertext at `objects/ab/cd/<sha256>.<nonce>.enc`. Deduplication is on
`stored_objects.sha256`, not on the path.

Verification distinguishes:

- **verified** — GCM authenticated and plaintext SHA-256 matches acquisition.
- **decryption_failed** — the encrypted container was altered.
- **hash_mismatch** — decryption succeeded, plaintext digest did not match.
- **object_missing** — the file is gone.

Custody and audit rows are hash-chained and protected by PostgreSQL triggers that reject
`UPDATE`/`DELETE` unless `cybertrace.allow_chain_purge` is set for a deliberate purge.

## Analysis and AI

Analyzers implement `supports` / `run` and are versioned. Correlation edges store the
`basis` that produced them (shared entities, IDF weights, windows). Insights split
`observed`, `interpretation`, and `llm_narrative`. `LLMProvider` cannot write `entities`,
`observations`, or `findings`.

## Reports

A report captures an immutable JSON snapshot, then renders PDF/HTML/JSON/CSV from that
snapshot. Signing is Ed25519 over the snapshot SHA-256. The preparer cannot sign their
own draft.

## Frontend

Types can be regenerated with `pnpm gen:types` against a running API
(`/openapi.json`). The console uses the same permission codes the API returns on `/auth/me`.
Command palette search is `/api/v1/search`. Dashboard figures come from `/api/v1/dashboard`.

## Operations

```
make setup     # venv, pnpm, postgres, migrate, seed
make api       # uvicorn :8000
make web       # vite :5173
make test      # pytest + vitest
```

Demo password: `Investigate!2026`.
