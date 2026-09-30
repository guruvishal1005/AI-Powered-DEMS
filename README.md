# CYBERTRACE

AI-assisted cybercrime evidence management and digital forensic investigation platform.

CYBERTRACE manages the full lifecycle of digital evidence — from incident registration
through acquisition, cryptographic preservation, analysis, correlation, timeline
reconstruction and signed forensic reporting — while keeping a tamper-evident record of
everything that ever happened to each artifact.

```
Incident -> Case -> Acquisition -> Ingestion -> Preservation -> Integrity Verification
    -> Investigation -> AI Analysis & Correlation -> Timeline -> Findings -> Report -> Closure
```

## Quick start

Requires Python 3.13+, Node 20+, pnpm and Docker.

```bash
cp .env.example .env     # development defaults work as-is
make setup               # venv + deps + database + migrations + demo data
make api                 # terminal 1 -> http://localhost:8000/docs
make web                 # terminal 2 -> http://localhost:5173
```

`make help` lists every target.

### Demo accounts

Seeded by `make seed`, all with password `Investigate!2026`:

- `admin@cybertrace.gov` — Administrator
- `r.mehta@cybertrace.gov` — Investigator
- `s.iyer@cybertrace.gov` — Forensic Analyst
- `audit@cybertrace.gov` — Auditor

Sign in as each to see role-based access control genuinely change what the API returns,
not merely what the interface displays.

## Architecture

| Layer | Choice |
| --- | --- |
| Frontend | React 19, Vite, TypeScript, Tailwind 4, TanStack Query, Cytoscape |
| API | FastAPI, Pydantic v2, synchronous SQLAlchemy 2.0 |
| Database | PostgreSQL 18 (JSONB, `pg_trgm`, `FOR UPDATE SKIP LOCKED`) |
| Evidence store | Content-addressed local filesystem, AES-256-GCM envelope encryption |
| Background work | Database-backed queue with an in-process worker |
| Reports | Jinja2 to HTML to PDF via WeasyPrint, Ed25519 signed |

The backend is layered `routers -> services -> models`, with routers holding no business
logic. Every service call receives a `RequestContext`, which is why attribution for audit
and custody records cannot be accidentally omitted.

### Design decisions worth knowing

**The forensic fingerprint is the hash of the plaintext, not the ciphertext.** Evidence is
stored encrypted, but the SHA-256 that identifies an artifact is computed over the original
bytes, because that is the value an investigator must be able to reproduce independently.
This yields two independent tamper signals: an AES-GCM authentication failure means
storage-level corruption or tampering, while a plaintext hash mismatch means the artifact
itself no longer matches what was acquired. The interface distinguishes them, because they
mean very different things.

**Custody and audit records are hash-chained.** Each entry stores the previous entry's hash
and its own `SHA256(canonical_json(entry) || prev_hash)`. Editing, deleting or reordering
history breaks verification detectably. Database triggers additionally reject `UPDATE` and
`DELETE` on those tables, so append-only is enforced by the database rather than by
convention.

**Correlation is explainable, and scored by rarity.** Shared indicators are weighted by
inverse document frequency, so a shared reference to a common domain scores near zero while
a specific address appearing in three items scores high. Every edge records exactly which
shared entities and time windows produced it.

**The AI layer cannot invent forensic facts.** Insights are produced by deterministic rules
over the analysis graph, and each carries its supporting evidence references, a confidence
value and a provenance tag. The optional `LLMProvider` is architecturally forbidden from
writing `entities`, `observations` or `findings` — a language model can phrase an
interpretation, but it cannot enter a fact into the case record.

**Auditors and administrators cannot download evidence content.** Auditors inspect history,
metadata and integrity; administrators operate the platform. Neither role is granted
`evidence:download`, which keeps separation of duties real rather than advisory.

## Repository layout

```
backend/
  app/
    api/v1/      HTTP routers (thin)
    services/    business logic
    forensics/   hashing, MIME detection, metadata extraction, integrity
    analysis/    analyzer registry, correlation, anomaly detection
    ai/          insight engine, risk scoring, LLM provider interface
    storage/     StorageBackend interface + encrypted local implementation
    jobs/        queue interface, worker, scheduler, task registry
    reports/     snapshot builder, templates, renderers, signing
    security/    permissions, policy engine, scoping
    audit/       hash-chained custody and audit writers
    seed/        demo scenario generator
frontend/
  src/
    design/      tokens and primitives
    features/    screen modules
    lib/         API client, hooks, formatters
ops/             docker compose for PostgreSQL
docs/            architecture and API notes
```

## Security posture

Argon2id password hashing; short-lived in-memory access tokens with rotating,
revocable refresh tokens in `httpOnly` cookies; CSRF double-submit on cookie-authenticated
routes; per-account and per-IP login rate limiting with lockout that raises alerts;
permission checks plus SQL-level object scoping so unauthorized rows are never selected;
content-based MIME validation; evidence served only as signed, short-lived attachment
downloads that require a stated reason and write a custody event; strict CSP and security
headers; secret validation that refuses to boot in production with shipped defaults.

See [docs/system-guide.md](docs/system-guide.md) for a full product explanation of every component,
[docs/architecture.md](docs/architecture.md) for process layout, and [docs/security.md](docs/security.md) for controls.
