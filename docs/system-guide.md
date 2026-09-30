# CYBERTRACE: what it is and how it works

This document is the product knowledge needed to understand every part of CYBERTRACE. It describes the investigation, the records, the guarantees, and the screens. It does not describe programming languages, libraries, or how to run the software.

---

## 1. What this platform is

CYBERTRACE is an **AI-assisted digital forensic evidence platform**. It is the system of record for a cybercrime investigation from the moment an incident is registered until a signed report is issued and the case is closed.

It is not a generic case-management tool with files attached. Every artifact is treated as **evidence**: hashed, encrypted at rest, custody-tracked, integrity-verified, analysed, correlated, and eventually cited in a report that can be independently checked.

The console never invents numbers, never hides unauthorised rows, and never treats model-generated prose as a forensic fact. If a figure, a link, or a finding appears on screen, it came from a persisted record that can be opened and inspected.

### What it is for

A typical investigation looks like this:

```
Incident
  → Case opened
  → Evidence acquired and registered
  → Artifact preserved (hash + encrypted storage + custody chain)
  → Integrity verified (and re-verified over time)
  → Analysis extracts entities, observations, technical findings
  → Correlation, anomalies, threat-intelligence matches, risk, insights
  → Timeline and relationship graph
  → Human findings and narrative
  → Immutable report snapshot, review, independent signature
  → Closure, retention, legal hold, or disposal
```

Everything that happens on the platform — including denied access attempts — is written to an append-only audit trail. Everything that happens to an artifact is written to that artifact’s chain of custody.

### What it is not

- It is not a malware sandbox or a packet dissector. Analyzers extract structured facts from common forensic artifacts (email, logs, documents, images, archives, generic files). They do not emulate malware or reconstruct full disk images.
- It is not a court. Risk scores, insights, and anomalies are **triage aids**. They are labelled as derived, statistical, or (optionally) phrasing-assisted. They are not judgements of guilt or admissibility.
- It is not a live dashboard over another system. The API is the source of truth. The console is a window onto it.

---

## 2. Design rules that apply everywhere

These rules are load-bearing. Almost every component exists to keep one of them true.

### Observed versus interpretation

A forensic record must distinguish **what was found** from **what someone concluded**. CYBERTRACE enforces this as structure, not as writing advice:

| Layer | What it may write | What it may not write |
| --- | --- | --- |
| Analyzers | Entities, observations, technical findings, all with a location inside an artifact | Meaning, alerts, risk, insights |
| Correlation / anomaly / threat intel / risk | Edges, anomalies, matches, scored breakdowns, all with the arithmetic stored | New entities or observations |
| Insight generator | `observed` (traceable facts) and `interpretation` (labelled inference) in **separate fields** | An inference inside `observed` |
| Language model (optional) | A prose rewrite of facts already persisted | Entities, observations, findings, scores, identifiers it invented |

If a claim cannot point at a byte offset, line, header, or page inside a named artifact, it cannot enter the analysis record.

### Two kinds of time

| Field | Meaning | Trust |
| --- | --- | --- |
| `occurred_at` | When it happened in the world (email sent, log written, device seized) | Untrusted. Comes from the artifact or from an investigator. May lack a timezone. |
| `recorded_at` | When the platform observed it | Authoritative. Comes from the server clock. Used for hash-chained history. |

A timeline that silently invents a timezone is worse than one that admits the ambiguity. Observations therefore carry `time_confidence` and `timezone_assumed`.

### Attribution is structural

Every mutating action carries a **request context**: who acted, from where, under which request, and (for downloads and similar acts) why. Background work is attributed to the platform itself and still records why it ran. A custody or audit row cannot be written without this context, so “unknown actor” is not a possible outcome of a forgotten parameter.

Actor identity on custody records is also stored as a **label** (name/email at the time), not only as a user-account link. The record must remain readable years later if the account has been removed.

### Authorisation is two independent layers

1. **Capability.** Does this person hold `evidence:download` at all?
2. **Object scope.** May they see *this* case?

The second layer is applied when rows are selected, not after the fact in the interface. An investigator’s case list, dashboard totals, search hits, and timeline contain only cases they lead or are assigned to. Hiding a button is not a control.

Auditors and administrators can see every case (`case:read_all`) because oversight must not depend on what an investigator chose to share. They still cannot download artifact content.

### The forensic fingerprint is the plaintext hash

Evidence is stored encrypted. The SHA-256 that **identifies** an artifact is computed over the **original bytes**, because that is the value an independent examiner must be able to reproduce from the seized file.

This yields two independent tamper signals:

- Authentication failure of the encrypted container → the *stored object* was altered.
- Plaintext hash mismatch after successful decryption → the *artifact itself* no longer matches acquisition.

The interface refuses to collapse these into a single “corrupt” state.

### History cannot be edited quietly

Custody events and the platform audit log are **hash-chained**: each entry commits to the previous entry’s hash. Altering, deleting, or reordering history changes every subsequent hash and is detectable by replaying the chain. The database itself rejects updates and deletes on those tables. The only deliberate exception is a controlled purge under an explicit operator flag.

### The console is not the filter

The console shows permission-gated navigation and uses the same permission codes the API returns for the signed-in user. If a role cannot download evidence, the download control is absent **and** the API will refuse the request. Metrics on the Command Center are scoped the same way list endpoints are.

---

## 3. People, roles, and capabilities

### Identities

A user account holds identity (name, email, job title, badge number, timezone), status (`active`, `invited`, `suspended`, `disabled`), and one or more **roles**. Roles are bundles of **permissions**. Runtime checks always use permission codes (`evidence:download`), never role names (`investigator`). An administrator can change a role’s grants without a new deployment.

A protected “superuser” account cannot be locked out of user management. That flag does **not** bypass the permission table. If it did, “administrators cannot take the evidence home” would be a boolean exception rather than a real control.

### Default roles

| Role | Remit | Sees all cases? | Download evidence? | Sign reports? |
| --- | --- | --- | --- | --- |
| **Investigator** | Owns cases end to end: open, assign, acquire, find, report | No — lead or assigned only | Yes | Yes (but not a report they prepared) |
| **Forensic analyst** | Deep examination on assigned cases: analyse, verify, timeline, attest | No — assigned only | Yes | Yes (same four-eyes rule) |
| **Auditor** | Oversight: custody, integrity, audit trail, compliance. No writes. | Yes | **No** | No |
| **Administrator** | Operates the platform: accounts, roles, retention, jobs, backups | Yes | **No** | No |

Administrators also cannot author investigative findings. Administration is not investigation.

Redeploying the platform refreshes the permission *vocabulary* and creates missing system roles. It does **not** reset an existing role’s grants. If an operator removed `evidence:download` from investigators, a restart will not hand it back.

### Permission groups

**Cases.** Create, read assigned, read all, update, assign personnel, close, reopen, delete (empty drafts only).

**Evidence.** Upload/register, read metadata/hashes/custody, download original bytes, preview a sanitised rendering, update metadata, verify integrity, transfer custody, archive, dispose.

**Custody.** Read the chain and its verification state.

**Analysis.** Run analyzers; read entities, observations, correlations, insights.

**Findings.** Create, update, delete human investigative findings.

**Reports.** Generate, read, sign (sensitive), delete drafts.

**Alerts.** Read; triage (acknowledge, assign, resolve).

**Audit.** Read the platform-wide trail and verify its chain (sensitive).

**Intelligence.** View indicator matches; manage feeds and entries.

**Administration.** Users, roles, system status, configuration, job queue, retention, backups.

Sensitive grants (`evidence:download`, `evidence:preview`, `report:sign`, `case:read_all`, `audit:read`, user/role/retention management, case/evidence destruction) are marked as such so operators can see which capabilities are dangerous.

### Sessions and access

Sign-in is uniform: a wrong password, an unknown address, and a disabled account produce the same failure, so an attacker cannot enumerate accounts. Failed attempts are counted per account and per client; lockout raises a security alert. Changing a password signs out other sessions.

Downloads of original bytes always require a **stated reason**, are served as an attachment (never inline in the browser), and write a custody event before the stream begins. Refresh-token reuse is treated as compromise: the whole session is revoked.

---

## 4. Cases

A **case** is the investigation container. Everything else hangs off it.

### Identity and classification

Cases are quoted by a human reference of the form `CT-2026-0001`, not by an internal identifier. The reference is unique and stable.

A case records:

- Title, summary, incident type, severity, status
- Three distinct times: **when the incident occurred**, **when it was reported**, **when the case was opened**
- Lead investigator, creator
- Jurisdiction, organisation, external reference, classification (default `RESTRICTED`)
- Tags, legal hold, retention policy and expiry
- Cached **risk score** plus a **breakdown** of how the number was reached

Incident types cover the usual cybercrime vocabulary: ransomware, phishing, business email compromise, data breach, insider threat, financial fraud, identity theft, malware, denial of service, unauthorised access, IP theft, cyber harassment, cryptocurrency fraud, supply-chain compromise, and other.

### Status lifecycle

`draft` → `active` → `pending_review` → `closed` → `archived`, with `on_hold` as a parking state.

Status changes are recorded in **case status history**. Closing requires a closure summary. Empty draft cases may be deleted; cases with evidence are not casually erased.

### Who may work a case

**Lead investigator** plus **assignments**. An assignment that has been withdrawn (`unassigned_at` set) confers nothing. Object-level authorisation joins this table: if you are not lead and not currently assigned, and you lack `case:read_all`, the case does not exist in your queries.

### People on the case

**Case persons** are parties to the investigation, not platform users: suspect, victim, witness, complainant, person of interest, organisation, custodian.

**Case notes** are investigator prose on the case itself.

### Human findings versus analysis findings

Two different records, on purpose:

| | **Finding** (human) | **Analysis finding** (technical) |
| --- | --- | --- |
| Author | Investigator or analyst | An analyzer, with name and version |
| Kinds | Observation, IoC, attribution, timeline reconstruction, root cause, impact, recommendation | Codes such as MIME mismatch, spoofing indicators, high entropy where unexplained |
| Purpose | What the investigation concludes, with confidence and linked evidence | What the artifact itself supports without interpretation |

Human findings are what a report’s narrative section is built from. Technical findings feed risk, insights, and the timeline’s analysis lane.

---

## 5. Evidence

Evidence is modelled as three layers so forensic identity, revision history, and storage can change independently.

```
Evidence item  ("the laptop's auth log")
  └── Evidence version  (acquired revision 1, 2, … each with its own hash)
        └── Stored object  (one encrypted blob, addressed by plaintext SHA-256)
```

- **Evidence** is what custody attaches to and what an investigator reasons about.
- **Evidence version** is a specific acquired revision.
- **Stored object** is the encrypted blob. Identical bytes are stored once (reference-counted) but remain distinct evidence items with independent custody. Deduplication is on the plaintext hash, not on the filename.

### Registration (ingestion)

When an investigator uploads an artifact onto an open case:

1. The stream is hashed while it is read (SHA-256 is the forensic fingerprint; other algorithms may be recorded alongside).
2. The bytes are envelope-encrypted: a random data key encrypts the artifact; that data key is wrapped by the platform master key. The database alone cannot decrypt anything. Rotating the master key re-wraps small keys rather than re-encrypting the whole store.
3. The object is stored at a path derived from the plaintext hash. A new identical upload increments the reference count instead of writing a second copy.
4. Immediately after write, the object is **read back, decrypted, and re-hashed**. Ingestion is not complete until that round-trip matches. The item starts as `integrity_status = verified`.
5. Content-based type identification runs on the first bytes. Declared MIME / filename extension is compared with detected type. A mismatch is stored as a **masquerading signal**, not recomputed later and forgotten.
6. Shannon entropy per byte is recorded (high values suggest encryption or compression).
7. A unique evidence reference is assigned (`E-2026-00001`).
8. The custody chain is opened (`collected` / `uploaded`).
9. Analysis is queued for the new version.

Acquisition metadata is first-class: source category (device, network, cloud/communication, external intelligence), acquisition method (live, dead-disk, logical copy, physical extraction, file export, network capture, log export, cloud API, screenshot, manual, third-party), source description/identifier/location, who acquired it and when (which may predate the platform and may not be a user account), and collection notes.

### Evidence types

Disk image, memory dump, document, spreadsheet, email, image, video, audio, screenshot, network capture, network log, system log, application log, database export, mobile extraction, chat export, cloud export, archive, executable, other.

An investigator may override the detected type when they know the artifact’s *role* better than its bytes reveal.

### Status and integrity

**Evidence status:** `registered` → `processing` → `analyzed`, with `requires_attention`, `archived`, `disposed`.

**Integrity status** (result of the most recent verification):

| Status | Meaning | Typical response |
| --- | --- | --- |
| `pending` | Not verified since last relevant change | Wait or trigger verify |
| `verified` | Container authenticated and plaintext SHA-256 matches acquisition | Trust the bytes |
| `decryption_failed` | Encrypted container or its authentication tag was altered | Original content unrecoverable from this copy |
| `hash_mismatch` | Decryption succeeded; plaintext digest does not match | Substitution through a path that held the key — more alarming |
| `object_missing` | File is gone from storage | Restore from backup; do not silently re-acquire |

Every verification is persisted as an **integrity check** recording both expected and computed digests — including on success, so a report can show the comparison rather than assert that it passed. Failures raise a custody event and an alert.

A cheap periodic sweep can hash ciphertext without decrypting, to detect at-rest container damage across the whole store.

### Versions, tags, notes, legal hold

A later acquisition of the same logical item becomes a new **version** with its own hash and its own analysis run. Re-analysis is version-aware: analysing version 2 must not be suppressed because version 1 already ran.

Tags and notes attach to the item. Legal hold blocks retention destruction. Archiving moves the item out of the working set; disposal destroys content under policy while **keeping custody history**.

### Preview versus download

- **Preview** is a sanitised derivative (text extract, not the original container). It still requires a grant and is recorded.
- **Download** is the original bytes. Reason required, attachment only, custody event first.

Auditors and administrators have neither grant.

---

## 6. Chain of custody and audit

### Custody (per artifact)

Each evidence item owns an append-only sequence:

```
entry_hash[n] = SHA256( canonical record of event n  concatenated with  entry_hash[n-1] )
```

The genesis event has no predecessor. Each event also carries an independent platform signature over its hash.

A custody event records:

- Sequence number, action, actor (id + surviving label + role)
- `occurred_at` and `recorded_at`
- Previous and new state
- Reason and notes
- SHA-256 and integrity status **at that moment**
- Network/request identifiers
- Chain fields: previous hash, entry hash, signature

Actions include: collected, uploaded, accessed, previewed, downloaded, analyzed, verified, integrity failed, metadata updated, version created, transferred, exported, included in report, archived, restored, legal hold applied/released, disposed.

Verification of a chain replays every hash and reports `content_modified`, `sequence_gap`, `link_broken`, or `invalid_signature`. A chain that is not trustworthy is surfaced on the evidence record and in reports; it is not silently skipped.

### Audit (platform-wide)

Where custody answers “what happened to this artifact?”, the audit log answers “what happened on this platform?”: successful actions, failures, **denied** attempts, administrative changes that never touch evidence.

The audit log is a single global hash chain (one total order). Access denials are recorded even when the request is rejected, so “nobody tried” and “someone tried and was refused” remain distinguishable.

---

## 7. Analysis

Analysis is a pipeline that **observes**. It does not interpret.

### Analyzer contract

An analyzer receives a read-only handle to one artifact (filename, detected type, size, hash, a way to open a decrypted stream). It returns:

- **Entities** — indicators or actors, each with a locator and excerpt
- **Observations** — timestamped events recovered from content
- **Technical findings** — what the artifact alone supports
- Optional extracted metadata

It never receives a database session. It cannot raise an alert or write an insight.

Analyzers are **named and versioned**. A result produced by version 1 is never presented as though the current version produced it. Improving an analyzer adds new results on re-run; it does not rewrite history.

**One analyzer’s failure is not the pipeline’s failure.** A malformed PDF must not prevent the log analyzer from having run. Each analyzer is isolated; a crash is recorded as a failed analysis run with the error attached, so a gap is *visible* rather than looking like an empty artifact.

**Re-analysis replaces, never appends.** Running twice must not double entity counts. Previous output for that analyzer on that item is cleared before new results are written.

### What each analyzer does

| Analyzer | Applies to | What it extracts |
| --- | --- | --- |
| **File metadata** | Every artifact (runs first) | Confirmed type, hashes, entropy profile, trailing-data checks. High entropy in a ZIP is reported as a measurement, not a finding — the file type already explains it. |
| **Text** | Generic text | Indicators (IPs, domains, emails, URLs, hashes, wallets), keywords |
| **Logs** | Syslog, auth logs, web logs, similar | Timestamped login success/failure, connections, HTTP requests, as observations with actors and sources |
| **Email** | `.eml` / RFC 822 | From/to/cc, Message-ID, received hops, SPF/DKIM/DMARC signals, URLs, attachments as entities; sent/received/relay observations; spoofing as a technical finding when headers support it |
| **Documents** | PDF and Office | Author, title, creation/modification times, embedded identifiers, text-derived entities |
| **Image** | JPEG and similar | EXIF timestamps, camera/device identifiers, GPS as a geolocation observation |
| **Archives** | ZIP and similar | Member list, nested names, hashes of members where practical |

### Entities

An **entity** is a globally unique indicator or actor: one row per `(type, canonical_value)`. Canonical form is normalised (lowercase, trimmed, address canonicalisation) so the same wallet in a PDF and in an email is one thing. Display value preserves how it appeared, for quoting.

Types include person, organisation, location, IP, domain, URL, email, phone, username, account, device, device identifier (IMEI, camera serial — a *specific* unit), software, file name/path/hash, MAC, crypto wallet, payment card, CVE, registry key, process, port, user agent, credential, keyword.

Each **occurrence** records analyzer, version, locator (`byte_offset`, `line`, `field`, `page`, …), excerpt, context (sender, source_ip, gps), and confidence.

`document_frequency` (how many evidence items contain this entity) is maintained so correlation can weight by **rarity**. A value in almost every artifact is not an investigative link.

### Observations

A timestamped event from content: login success/failure, lockout, privilege change, file lifecycle, process execution, network/DNS/HTTP, email sent/received/hop, media captured, geolocation, document authored, raw log entry, transaction, configuration change, generic.

Observations are the raw material of the reconstructed timeline. They carry time confidence and timezone-assumed flags because artifact clocks lie.

### Analysis runs

One analyzer execution against one evidence version: status, timing, bytes examined, counts, error or skip reason, summary. The administration view can list the analyzer inventory (name, version, description).

---

## 8. Intelligence layer

After analysis, a separate layer **reads** recorded facts and writes derived products. It cannot create entities or observations. That is the observed/interpretation boundary by construction.

### Correlation

Two artifacts are related if they share correlatable entities (IPs, domains, emails, wallets, hashes, device identifiers, and similar — not generic keywords). Shared values are **not** weighted equally.

Weight is inverse document frequency: a private RFC1918 address that appears in half the logs is nearly worthless; a specific Bitcoin wallet in two cases is not. Every edge stores its full arithmetic in `basis`: which entities matched, each document frequency, each weight, the total. An edge whose score cannot be explained should not exist.

Small corpora are a special case: with three artifacts every shared value looks “common.” Weighting therefore uses a minimum nominal corpus size until the real corpus is large enough, and both figures are recorded on the edge.

Edges below a minimum score are not stored. Correlation kinds include shared indicator, temporal proximity, near-duplicate, identical content, same device, same account, cross-case.

Stale edges are removed when they no longer hold, rather than left to age into fiction.

### Anomalies

Detectors ask: is this unusual **for this case**, against a baseline drawn from the case’s own data? Fixed global thresholds (“more than 50 events per hour”) are meaningless without knowing the subject’s normal volume.

Every stored anomaly records method, threshold, observed value, baseline, deviation, and sample size, so a defence expert can recompute it.

Detectors stay **silent on small samples**. A z-score over four points is arithmetic, not evidence.

Kinds include temporal burst, off-hours activity (with an explicit local-time assumption), failed-login burst, privilege escalation, MIME/extension mismatch, high entropy where unexplained, timestamp inconsistency, volume outlier, access outside scope, email spoofing indicator, known-malicious indicator.

### Threat intelligence

Extracted entities of look-up-able types (IP, domain, URL, hash, email, wallet) are matched against a **provider**. The shipped platform is useful with **no outbound connectivity**: a curated offline feed. Sending victim indicators to a third party is an operational and legal decision; live feeds are opt-in.

Providers return statements; they never write case data. Two feeds disagreeing about the same value is stored as two matches — a fact to see, not a conflict to hide. Matches annotate the entity (`intel_severity`, tags) and feed risk and insights.

### Risk

A case risk score is a **0–100 triage aid**, not a judgement of guilt. Every point belongs to a named component; components are capped so two hundred weak findings cannot outrank a confirmed malicious indicator plus a broken integrity check. The caps sum to 100; there is no opaque remainder.

Components include finding severity, anomalies, threat intelligence, cross-case links, integrity failures, high-value indicators, recent activity, and the case’s own declared severity. The breakdown is persisted on the case so the interface can always explain the number.

### Insights

An insight is something worth an investigator’s attention, ranked so four hundred of them do not become none.

| Field | Meaning |
| --- | --- |
| `observed` | What the evidence records. Traceable to persisted rows; artifacts listed in `evidence_refs` with locators. |
| `interpretation` | What those facts might mean. Labelled inference. Alternative explanations remain visible. |
| `llm_narrative` | Optional prose rewrite. Display-only. Never a source of facts. |
| `provenance` | `derived`, `statistical`, or `llm_assisted` — shown verbatim in the interface |
| `basis` | The supporting arithmetic or rule |
| `rank_score` | Severity raised by corroboration (sub-linear: the jump from one artifact to two matters more than from nineteen to twenty) |

Kinds: correlation, cross-case link, anomaly, temporal pattern, entity pivot (an entity in many artifacts — usually the most productive next step), integrity, risk assessment, coverage gap (for example analysed items with no observations).

Analysts can **pin** or **dismiss** an insight. Dismissal survives recomputation so a rejected hypothesis does not keep coming back.

### Language-model boundary

A language model, if configured, may rewrite **already established** facts into clearer prose. It:

- receives only short declarative statements produced by deterministic code
- returns **one string**
- is never given a database session
- has its output dropped if it introduces an identifier, address, hash, filename, or date not present in the supplied facts

With no model configured, the platform is fully functional. With one configured, wording may improve and nothing else changes.

---

## 9. Timeline

The reconstructed timeline is **not a separate store**. It is a projection of records that already exist:

| Source lane | Origin |
| --- | --- |
| Custody | Chain-of-custody events |
| Observation | Analyzer-extracted timestamped events |
| Analysis finding | Technical findings |
| Finding | Human investigative findings |
| Lifecycle | Case status history |
| Alert | Alerts on the case |
| Integrity | Integrity checks |

Because it is a projection, it cannot drift from the case record. Each event names its source so a reconstruction is never mistaken for a single homogeneous log.

When a window is too dense to plot as raw points (a month of syslog), the server returns **density buckets** (minute / hour / day counts by source and kind). Buckets are counts, never a substitute for the events. Investigators can brush a bucket to zoom the window.

Events that carry an evidence id navigate to that item. Timezone-assumed observations are labelled as such.

---

## 10. Relationship graph

The graph is also a projection: entities, evidence items, correlation edges, and recorded relationships. It is **scoped**. Depth is a walk from the seed set (every entity in the case, or a chosen pivot), not “show the whole corpus,” which would be unreadable and would leak other cases.

The server ranks nodes (degree, betweenness, PageRank) and marks **pivots** — entities that actually hold the case together — so the console is not inventing topology. Truncation prefers seeds and high-degree neighbours so the investigative centre is not dropped.

Selecting a node shows its kind, label, and centrality. Pivot nodes are visually distinct.

---

## 11. Alerts and notifications

An **alert** is an actionable signal that needs a human: integrity failure, chain verification failure, unauthorised access attempt, access outside scope, suspicious download volume, AI anomaly, malicious indicator match, evidence pending analysis, case requiring attention, retention expiry approaching, backup failure, job failure, account locked.

Alerts have type, source, severity, status (`open`, `acknowledged`, `resolved`, `suppressed`), assignment, and a **dedupe key**. Repeating the same failure bumps `occurrence_count` on one open alert rather than flooding the queue. Once resolved, a recurrence opens a fresh alert.

**Notifications** are the per-user inbox derived from alerts and similar events (unread until marked). The console polls them so the shell badge stays current.

Triage (acknowledge, assign, resolve) requires `alert:manage`. Seeing them requires `alert:read`.

---

## 12. Reports

A report is an **immutable artifact**, not a live view of the case.

### Snapshot

When a report is generated, the platform captures a point-in-time JSON **snapshot**: case metadata, evidence inventory with hashes and integrity, custody chain verification for each item, findings, observations, correlations, insights, anomalies, author-written executive summary and conclusion. A SHA-256 of that snapshot is stored.

Everything downstream — PDF, HTML, JSON, CSV inventory — **renders from the snapshot**. Re-rendering an old report cannot silently pick up later analysis. Recapture is an explicit action that replaces the snapshot and is itself audited.

### Four-eyes signing

The signature is over the **snapshot hash**, not a particular PDF file. A PDF can be regenerated; the snapshot is what the signer attested to.

The preparer **cannot** submit-review or sign their own draft. Another authorised officer who holds `report:sign` must attest. Administrators and auditors do not hold that grant.

Status: `draft` → `pending_review` → `approved` or `rejected`, later `superseded` if a new version is issued.

Citing evidence in a report writes `included_in_report` custody events.

Verification answers: is this the document that was signed? Independently of whether a particular rendered file still exists.

---

## 13. Background work

Work that should not block an investigator (analysis, correlation, integrity sweeps, backups) runs as **jobs**. Jobs are named by a stable task name, not by an internal function, so a job queued before a change still resolves after it.

The worker claims jobs, runs them under a system context (fully attributed), and owns the transaction: either the task and all of its audit/custody records land together, or none do.

Deduplication matters for analysis: two concurrent runs over the same evidence version would race. The key is `analyze:{evidence_id}:{version}` so a new version is not suppressed.

### Recurring work (visible and adjustable)

| Work | Why it exists |
| --- | --- |
| Platform health sample | Queue depth, storage, integrity counters for operations |
| Evidence integrity sweep | Re-verify oldest-checked-first against acquisition fingerprints |
| Correlation refresh | Rarity weights depend on the whole corpus; old scores age as new items arrive |
| Case intelligence refresh | Anomalies, intel matches, insights, risk for open cases — including the *older* side of a new cross-case link, which gets no ingestion event of its own |
| Uncorrelated / unanalysed sweeps | Cover jobs lost between ingest and queue, or between analysis and correlation |
| Failed analysis retry | Many failures are environmental |
| Retention review | Warn before expiry; honour legal holds; never silent destroy |
| Audit/custody chain verification | Replay hash chains; alert on breaks |
| Encrypted backup | Capture and verify it can be read back |

Schedules live as data so operators can see and change them. Existing schedule rows are not overwritten on startup.

---

## 14. Retention, legal hold, and backups

**Retention policies** set how long material is kept and what the default disposition is (retain, review, archive, destroy). Cases and evidence can inherit a policy and an expiry.

**Legal hold** freezes destruction regardless of expiry. Applying and releasing hold are custody events.

The retention scanner **never deletes silently**. Approaching expiry raises an alert. Past expiry flags for review unless hold is on. Actual destruction is a separate explicit action that writes custody and leaves the historical chain intact.

**Backups** are encrypted captures of the store plus the records needed to restore. A backup that cannot be verified is a failed backup, not a file on disk that looks complete.

---

## 15. Search

Investigators search across **cases, evidence, hashes, and entities**. Results are scoped the same way lists are: you cannot find a hash on a case you cannot see.

The command palette is the same search, intended for keyboard use: type a reference (`CT-2026-0001`), a filename, a SHA-256 prefix, or an indicator value, and jump.

Confirming that a case reference exists to someone who cannot access it would itself be a disclosure. Unauthorised lookups fail as “not found,” not “forbidden but it exists.”

---

## 16. The console: every view

The console is a dark, dense investigation workplace. Navigation items appear only if the signed-in user holds the matching permission. Breadcrumbs, a command palette, notification badge, density toggle, and sign-out live in the shell.

### Command Center

Home. Scoped aggregates only:

- Open / total cases
- Evidence count and storage
- Integrity: verified, pending, failed
- Open alerts, queue depth, failed jobs
- Activity over recent days (uploads)
- Cases needing attention (open, high/critical)
- Recent evidence and recent alerts

If this view cannot load, it is because the API refused or failed — not because the console guessed.

### Cases list

Filterable inventory of cases in scope. Create a case (title, summary, incident type, severity). Open a row to enter the workspace.

### Case workspace

The investigation’s home. Header shows reference, title, severity, status, legal hold. Actions (upload, request closure) follow grants.

Tabs:

| Tab | Contents |
| --- | --- |
| Overview | Case facts, pinned/top insights |
| Evidence | Items on this case; upload |
| Timeline | Projected reconstruction (see §9) |
| Graph | Relationship projection (see §10) |
| Findings | Human findings; create with kind, severity, linked evidence |
| Chain of custody | Per-item chains rolled up for the case |
| Reports | Reports for this case; generate |
| Activity | Status history and notes |

### Evidence list and detail

Global evidence list is still scoped to accessible cases.

Detail tabs: overview (hashes, integrity badge, MIME mismatch, entropy, acquisition), preview, analysis runs and technical findings, entities, relationships, custody (events + chain verification), versions. Verify-now and download (with reason) live here.

Integrity badges and hash displays are first-class UI: hashes are copyable, statuses explain what they mean on hover.

### Intelligence

Ranked insights with provenance tags (`derived` / `statistical` / `llm_assisted`). Observed text, interpretation, optional narrative, evidence citations. Pin / dismiss. Entity pages when pivoting from a value.

### Alerts

Queue of open/acknowledged/resolved alerts. Open an alert to triage. Linked case/evidence when present.

### Reports

List and detail: snapshot metadata, status, prepare/submit/sign/reject according to role and four-eyes rules. Download rendered artifacts. Verify signature.

### Audit log

Platform-wide trail for roles with `audit:read`. Filter by actor, action, result (`success` / `failure` / `denied`). Chain verification status.

### Administration

Users, roles and their grants, retention policies, job queue (inspect, retry, cancel), platform health, backups, security settings. Visible only with system/user grants. An administrator still cannot open original evidence bytes from here.

### Settings

The signed-in user’s own profile (name, title, timezone) and session controls — not platform configuration.

### Shared language in the interface

- **Severity badges** — informational through critical
- **Integrity badges** — the five integrity states, with meaning in the tooltip
- **Status pills** — case/evidence/report/alert/job status
- **Provenance tags** — how an insight was produced
- **Timestamps** — absolute and relative; timezone-aware
- **Empty / error / loading states** — a failed load says so; it does not show zeros that look like “nothing happened”

---

## 17. How a fact travels (end-to-end)

A concrete path, using the kind of artifact the demo world contains:

1. Investigator opens case `CT-2026-0001` and uploads `auth.log`.
2. Ingestion hashes, encrypts, round-trip verifies, identifies type `system_log`, opens custody.
3. File-metadata analyzer confirms type and entropy. Log analyzer extracts “Failed password … from 203.0.113.77” as observations and that address as an entity occurrence with line locators.
4. Correlation notices the same IP (and perhaps a wallet or domain) in another case’s email or netflow, weighted by rarity, and stores an edge with the arithmetic.
5. Threat intel marks the IP malicious if the feed says so.
6. Anomaly detection may flag a failed-login burst against this case’s own baseline.
7. Insight generator writes: *observed* — this IP appears in these artifacts at these locators; *interpretation* — possible shared infrastructure; provenance `derived`.
8. Risk adds points under threat intelligence and findings, visible in the breakdown.
9. Timeline shows custody `uploaded`, then login-failure observations in the observation lane.
10. Graph shows the IP as a pivot between evidence nodes.
11. Analyst writes a human finding (IoC) citing the log.
12. Report snapshot freezes inventory, hashes, chain status, findings, insights. A second officer signs the snapshot hash.
13. Nightly integrity sweep re-verifies the stored object. Any break alerts and writes custody `integrity_failed`.

No step after (3) is allowed to invent a new IP. If the language model is on, it may only rephrase the sentences already produced in (7).

---

## 18. The demo world

The seeder does not insert fake analysis rows. It creates four people, three linked investigations, and **real files**, then drives the same ingest → analyse → correlate → insight path.

**People** (same password in the demo environment):

| Person | Role |
| --- | --- |
| Priya Nair | Administrator |
| Rohan Mehta | Investigator (lead on the demo cases) |
| Sana Iyer | Forensic analyst |
| Marcus Hale | Auditor |

Sign in as each to see authorisation change **what the API returns**, not merely which buttons render.

**Cases** (titles abbreviated):

1. **Globex file-server encryption — InvoiceLock** (ransomware, critical). Auth log: brute force then success from `203.0.113.77`; backups stopped; ransom PDF naming a wallet.
2. **Globex CFO — supplier payment diversion** (BEC, high). Spoofed accounts-payable email, failed SPF/DKIM, domain `invoices-secure-mail.net`.
3. **Suspected insider copy of customer database** (insider, high). Syslog, camera JPEG with GPS EXIF, archive of copied files.

**Artifacts** include a ransom PDF, SSH auth log, netflow CSV, BEC `.eml`, nginx log, zip archive, JPEG with GPS, insider syslog. They **actually share** the attacker IP, command-and-control domain, wallet, and related identifiers, which is why cross-case insights exist.

A curated offline indicator feed is loaded so threat-intelligence matches are real lookups against that feed, not hard-coded flags on the cases.

---

## 19. Component map

Use this as an index back into the sections above.

| Component | Job | Depends on | Produces |
| --- | --- | --- | --- |
| Identity & sessions | Who is acting | Users, roles, permissions | Request context |
| Permission + SQL scope | What they may do / see | Assignments, `case:read_all` | Denied audit rows; scoped queries |
| Cases | Investigation container | Users | References, status history, assignments |
| Evidence ingest | Register bytes as evidence | Open case, storage | Item, version, stored object, custody genesis |
| Storage | Encrypted content-addressed blobs | Master key | Ciphertext + wrapped data key |
| Type identification | Content vs declared MIME | File head + name | Evidence type, mismatch flag |
| Integrity verification | Are these still the acquired bytes? | Stored object + acquisition hash | Integrity status, check rows, alerts |
| Custody chain | What happened to this artifact | Request context | Hash-chained events |
| Audit chain | What happened on the platform | Request context | Hash-chained log |
| Analyzers | Observe inside one artifact | Decrypted stream | Entities, occurrences, observations, technical findings, analysis runs |
| Correlation | Link artifacts by rare shared entities | Entity occurrences | Edges with `basis` |
| Anomalies | Unusual-for-this-case patterns | Observations | Anomalies with arithmetic |
| Threat intel | Reputation of extracted values | Entities + feed | Matches, entity intel fields |
| Risk | Explainable 0–100 triage score | Findings, anomalies, intel, integrity, correlations | Score + breakdown |
| Insights | Ranked attention items | All of the above | Insights with observed/interpretation split |
| LLM provider | Optional phrasing | Insight facts only | `llm_narrative` or nothing |
| Timeline | Reconstruction | Custody, observations, findings, lifecycle, alerts, integrity | Events and density buckets |
| Graph | Relationship picture | Entities, edges, evidence | Ranked nodes, pivot flags |
| Alerts | Human attention queue | Integrity, security, intel, jobs, retention | Deduped alerts + notifications |
| Human findings | Investigation conclusions | Case + evidence links | Findings for reports |
| Reports | Immutable attested document | Snapshot of the case | Signed snapshot, rendered artifacts |
| Jobs & schedule | Deferred and periodic work | Task registry | Analysis, sweeps, backups |
| Retention & hold | Keep or destroy under policy | Policies, legal hold | Alerts; explicit disposal only |
| Search | Find in scope | Cases, evidence, hashes, entities | Scoped hits |
| Command Center | Scoped situation picture | Aggregates over scoped rows | Dashboard |
| Administration | Operate the platform without touching exhibits | Users, roles, jobs, health | Operational changes, still audited |

---

## 20. Glossary

| Term | Meaning in CYBERTRACE |
| --- | --- |
| Artifact | The original file or blob acquired as evidence |
| Canonical value | Normalised form of an entity used for identity and correlation |
| Chain of custody | Per-item append-only, hash-chained history of handling |
| Console | The investigator-facing application; not the system of record |
| Coverage gap | Insight that analysis did not produce expected observations |
| Deduplication (storage) | Identical plaintext stored once; separate evidence items still have separate custody |
| Deduplication (jobs / alerts) | Collapse redundant work or repeated failures |
| Derived | Insight provenance: deterministic rule over recorded facts |
| Document frequency | How many evidence items contain an entity; used for rarity |
| Envelope encryption | Per-object data key wrapping the artifact; master key wraps that data key |
| Excerpt | Surrounding text proving an entity or observation was seen |
| Four-eyes | Preparer of a report cannot sign it |
| Integrity | Whether stored bytes still match the acquisition fingerprint, and *how* they fail if not |
| Locator | Where inside an artifact something was found (offset, line, field, page) |
| Observation | Timestamped event extracted from content (untrusted clock) |
| Pivot | Entity that appears across enough artifacts to organise the investigation |
| Provenance (insight) | `derived` / `statistical` / `llm_assisted` |
| Recorded at | When the platform observed something (trusted clock) |
| Reference | Human-quotable id: `CT-…` for cases, `E-…` for evidence |
| Snapshot | Frozen JSON document a report signature attests to |
| Statistical | Insight provenance: threshold or distribution test with maths recorded |
| Stored object | Encrypted blob addressed by plaintext SHA-256 |
| System context | Background actor; attributed, permission-bypassing only for platform work |
| Technical finding | Analyzer conclusion supported by one artifact alone |
| Version | A specific acquired revision of an evidence item |

---

## 21. What to remember

1. **The API is the system of record.** The console displays it.
2. **Facts have locations.** No locator, no record.
3. **Observed and interpretation never share a field.**
4. **Plaintext hash identifies; encryption authenticates storage.** Different failures, different meanings.
5. **History is append-only and hash-chained.** Replay, don’t trust.
6. **Authorisation is capability plus SQL scope.** The UI is not the control.
7. **Administrators and auditors cannot take the exhibits.** Oversight without possession.
8. **Language models may phrase, never find.**
9. **A report attests to a snapshot.** Later analysis cannot rewrite what was signed.
10. **Every number on the Command Center is a scoped query.** If you cannot see the case, you cannot see its count.

---

## 22. What is implemented, what is not

Sections 1–21 describe the product model. This section is the delta: what actually runs today, what exists only as an API with a thin or missing console, what is a workaround, and what is vocabulary waiting for an engine.

Legend:

| Status | Meaning |
| --- | --- |
| **Done** | Works end-to-end: engine, API, and a usable console path (or no console is required). |
| **API only** | The capability is real on the server; the console lists it, omits it, or cannot drive it. |
| **Partial** | Real code with a narrowed, mislabelled, or incomplete behaviour. |
| **Seam** | An interface exists so a later adapter can plug in. Nothing is plugged in. |
| **Placeholder** | Enum, table, route, or copy exists; nothing produces or consumes the behaviour. |

---

### Fully working (Done)

These are not mock-ups. The demo seed drives the same paths.

**Identity and access**

- Password sign-in with uniform failure, attempt counting, lockout alerts, session list and revoke.
- Short-lived access tokens in memory; rotating refresh cookies; CSRF on cookie refresh; refresh-token reuse revokes the session.
- Permission catalogue, four default roles, startup sync that does **not** overwrite existing role grants.
- Capability checks plus SQL case-scoping on lists, detail, dashboard, search, timeline, and graph.
- Auditors and administrators genuinely cannot download or preview artifact bytes.
- Access denials are written to the audit chain.

**Cases and evidence**

- Case create/list/detail, status changes with history, notes, human findings with kinds and evidence links.
- Evidence ingest: stream hash (SHA-256 identity plus SHA-1/MD5 for cross-reference), envelope encryption, content-addressed store, deduplication by plaintext hash, write-then-read verification, MIME detection vs filename, entropy, custody genesis, analysis queued.
- Evidence versions in the API (a later acquisition is a new version and re-analysis is version-aware).
- Integrity verify-now and periodic sweep; three failure modes kept distinct; integrity-check rows stored including successes.
- Download requires a reason, is an attachment, writes custody first.
- Archive (move out of the working set) in the API.
- Legal-hold flag on evidence and a legal-hold table; retention scanner skips held items.

**Custody and audit**

- Hash-chained custody and audit writers; database rejects update/delete on those tables.
- Chain replay reports `content_modified`, `sequence_gap`, `link_broken`, `invalid_signature`.
- Nightly chain-verification job raises alerts on breaks.

**Analysis (observe, don’t interpret)**

- Analyzer contract, versioning, isolated failure, replace-on-re-run.
- **File metadata** on every artifact (type confirmation, hashes, entropy, trailing data).
- **Text/CSV** (indicators, structured columns, netflow-style rows as observations).
- **Logs** (auth/syslog/web-style lines as observations).
- **Email** (headers, hops, auth results, spoofing findings).
- **PDF and Office** (metadata, text, PDF active-content findings).
- **Images** (EXIF, camera identifiers, GPS as geolocation).
- **Archives** listed from the central directory only — not unpacked (this is intentional, not a stub).

**Intelligence**

- Entity identity on `(type, canonical_value)` with document frequency.
- Correlation by shared correlatable entities, IDF-weighted, `basis` stored, stale edges removed. Produced kinds: **`shared_indicator`** and **`cross_case`**.
- Anomaly detectors that actually run: temporal burst, off-hours, failed-login burst, timestamp inconsistency, plus promotion of certain analyzer findings (MIME mismatch, unexplained entropy, email spoofing, zip-bomb/path-traversal).
- Local threat-intelligence table lookup (offline feed; seeder loads indicators). Matches persist; two sources can disagree.
- Explainable 0–100 risk with capped components that sum to the total.
- Insights with `observed` / `interpretation` split, provenance, `basis`, ranking, pin and dismiss **in the API** (dismissals survive recomputation).
- Language-model boundary: disabled provider by default, narrative validation, no path for a model to write entities/observations/findings. Deterministic insights work with no model.

**Timeline, graph, search, dashboard**

- Timeline is a live projection of custody, observations, analysis findings, human findings, lifecycle, alerts, integrity; server-side density buckets; source filters.
- Graph is a scoped walk of entities and correlation edges, with server-side centrality and pivot flags.
- Command-palette / global search over cases, evidence, hashes, entities — scoped.
- Command Center aggregates are real scoped queries.

**Reports**

- Immutable JSON snapshot, SHA-256 of the snapshot, HTML/PDF/JSON/CSV render from that snapshot.
- Four-eyes: preparer cannot review or sign their own draft. Signature is over the snapshot hash. Verify endpoint exists. Console can submit, reject, sign, and download artifacts.

**Jobs**

- Database-backed queue, in-process worker, named tasks, dedupe keys.
- Periodic schedule as data: health sample, integrity sweep, correlation refresh, case intelligence refresh, unanalysed/uncorrelated sweeps, failed-analysis retry, retention scan, chain verification, backup.
- Admin can list jobs, retry, and cancel.

**Alerts that are actually raised**

- Integrity failure, chain verification failure, account locked, unauthorised access attempt (failed login), job failure, retention expiry approaching, MIME/extension mismatch (see Partial — mislabelled type).

**Demo world**

- Four users, three linked cases, real files, real ingest/analysis/correlation. Cross-case links exist because artifacts share indicators.

---

### API exists; console is thin or missing (API only)

The server will do these. An investigator using only the console often cannot.

| Capability | Server | Console today |
| --- | --- | --- |
| Assign / unassign people on a case | Yes | Assignments are listed; no add/remove controls |
| Case persons (suspect, victim, …) | Yes | No screen |
| Case notes | Yes | Activity tab is limited; no full notes editor |
| Add an evidence **version** | Yes | Versions tab is read-only |
| Archive evidence | Yes | No button |
| Apply / release legal hold | Yes (evidence + admin) | Hold is displayed; admin lists holds; no apply/release form |
| Transfer custody | **Permission exists; no service** | — (see Placeholders) |
| Dispose / destroy content | Permission and enum; **no destroy action** | — |
| Insight dismiss / unpin | Yes | Pin always sends `pinned: true`; no dismiss |
| Anomaly dismiss | Yes | No anomalies screen |
| Entity detail | Yes | Route `/intelligence/entities/:id` loads the insights list and **ignores** the id |
| Threat-indicator curation (`intel:manage`) | Permission exists | No manage UI; no dedicated feed-admin routes beyond reading matches on an entity |
| Create/update users | Yes | Users table is read-only |
| Change role grants | Yes | Roles are cards of counts, not editors |
| Create retention policies | Yes | Policies listed only |
| Edit system settings | Yes | Settings shown; no save |
| Edit periodic schedule | Yes | Not shown |
| API tokens | Yes | Settings page can create/revoke (needs `user:manage` / admin token routes — investigators will see failures) |
| Alert assign | Yes | Acknowledge / resolve / suppress only |
| Recapture report snapshot | Yes | Not exposed as a labelled action in the console (submit/sign/download are) |

Administration is therefore **oversight plus a few actions** (trigger backup, retry/cancel jobs), not a full operator console.

---

### Partial implementations and workarounds

These are easy to mistake for the full story in sections above.

**Preview is not a sanitised rendering.** The console says “Sanitised preview.” The server reads a **bounded prefix**, decodes UTF-8 if it can, otherwise shows **hex**. It does not strip macros, rasterise PDFs, or disable scripts. Custody records `previewed`. Integrity is explicitly not fully verified on this path.

**Evidence “Entities” tab lists observations.** The detail page queries `/observations` and labels the table “Observed entities.” Real entity occurrences have a separate API; this tab is a stand-in.

**MIME mismatch alerts use the wrong type.** Ingestion correctly detects name-vs-content disagreement and raises an alert immediately, but the type stored is `ai_anomaly_detected` from source `anomaly_detector`. It is not an AI result.

**Correlation kinds in the vocabulary vs what is written.** The model lists temporal proximity, near-duplicate, identical content, same device, same account. The engine writes **`shared_indicator`** or **`cross_case`** only. Identical files still deduplicate in storage; that is not a correlation edge of kind `identical_content`.

**Typed entity relationships are unused.** `entity_relationships` is meant for “this email From is this IP.” Analyzers do not write those rows. The graph still works from **correlation edges** and evidence–entity occurrence links.

**Archives: inventory, not member hashes.** The guide’s “hashes of members where practical” overstates it. Members are listed; contents are not extracted or hashed. Compression-ratio and path-traversal findings are real.

**Backup is a ciphertext copy, not a platform restore.** The job copies encrypted objects into a dated directory, writes a manifest, verifies a sample of ciphertext, and checks a prefix of the audit chain. It does **not** dump the database. `custody_chain_verified` is set to `true` without replaying custody chains — a recorded workaround. Failed backups do not raise `backup_failure` alerts.

**Retention warns; it does not destroy.** Approaching/past expiry raises an alert and skips legal holds. There is no implemented disposition that deletes ciphertext and writes `disposed`.

**Master-key rotation is prepared, not operable.** Each object stores `key_version`. Unwrap refuses unknown versions. There is no job to re-wrap data keys under a new master key.

**SHA-512** appears in the hash-algorithm vocabulary and is not computed. SHA-256 is the integrity identity; SHA-1 and MD5 are stored for external cross-reference.

**Risk and insights after ingest** depend on queued jobs (`analyze` → `correlate` → delayed `refresh_case`). They are real, but not instantaneous; empty insight lists right after upload are expected until the worker finishes.

**Object store is local encrypted files only.** The storage interface is written so another backend could replace it. Only the local backend exists.

**Health and admin stats** in the console are raw JSON dumps, not designed operational views.

**Pin control** cannot unpin. Repeated clicks keep pinning.

---

### Seams: designed, not filled

These are intentional boundaries. The platform is specified to work without them.

| Seam | What exists | What does not |
| --- | --- | --- |
| Language model | `LLMProvider`, disabled default, validation that drops invented identifiers | No shipped adapter (no remote model is ever called). `llm_narrative` stays empty unless an operator installs a provider in process. |
| Live threat intel | `ThreatIntelProvider`; local table is the working provider | No MISP, AbuseIPDB, or other remote feed. Comments describe them; they are not classes. |
| Alternate object stores | Stream-oriented storage interface | No S3/KMS/WORM implementation |
| Key-encryption-key rotation | `key_version` on stored objects | No rotation procedure |
| Typed graph relations | Table + graph reader | No analyzer writes relationships |

With no language model and no remote intel, **every insight is deterministic** and **every match is against the local feed**. That is the supported production posture of this tree, not a degraded mode.

---

### Placeholders: vocabulary or UI without an engine

**Analyzers not built** (types can still be registered; only file-metadata plus a catch-all if the bytes look like text will run):

- Disk images, memory dumps
- Video, audio (beyond treating a file as “other”)
- Native PCAP / full packet capture (netflow **CSV** is handled as text)
- Mobile extractions, cloud exports as specialised formats
- Executables (no disassembly; file-metadata only)

**Anomaly kinds in the enum that no detector emits as a first-class result:**

- `privilege_escalation`
- `known_malicious_indicator` (malicious matches affect **risk and insights**, not this anomaly kind)

**Alert types declared but never raised:**

- `access_outside_scope` (as an alert — the *anomaly* kind can appear via log/archive findings)
- `suspicious_download_volume`
- `malicious_indicator_match`
- `evidence_pending_analysis`
- `case_requires_attention`
- `backup_failure`

Unanalysed evidence is covered by a **sweep job**, not by that alert type.

**Custody actions with no writer:** `transferred`, `exported`, `restored`, `disposed` (others are written by ingest, preview, download, analysis, verify, hold, archive, report cite).

**MFA.** User rows have `mfa_enabled` / `mfa_secret`. Login never challenges a second factor. The console shows the flag if present. This is schema ahead of the control.

**Evidence transfer permission** (`evidence:transfer`) is granted to investigators and has no service or route.

**Case delete** is permission-gated for empty drafts in the model; not a console action.

**Coverage-gap and similar insights** are generated when the intelligence refresh runs; they are not placeholders. Entity **pages** in the console are.

---

### Console honesty check (by screen)

| Screen | Status |
| --- | --- |
| Login | Done |
| Command Center | Done (activity query and scoped totals are real) |
| Cases list / create | Done |
| Case workspace — overview, evidence list, upload, findings create, timeline, graph, reports entry, closure request | Done for those actions |
| Case workspace — assign people, persons, legal hold, notes | Display or missing |
| Evidence list / detail — hashes, integrity, verify, download, preview, custody, versions (read), analysis findings | Done, with the Entities-tab workaround |
| Evidence — new version, archive, hold, transfer | API only / missing |
| Intelligence | Lists insights and pins; no dismiss, no entity page, no anomaly browser, no feed admin |
| Alerts | List + acknowledge/resolve/suppress |
| Reports | List, detail, four-eyes actions, download |
| Audit log | Done for roles with `audit:read` |
| Administration | Read-mostly; backup trigger and job retry/cancel work |
| Settings | Profile and sessions work; API tokens depend on admin grants |
| Entity route | Placeholder (wrong page) |

---

### How to read the rest of this document

Treat sections 1–21 as **the contract the code is written toward**. Treat this section as **what a reviewer can demonstrate today**.

Safe claims to make about a running demo:

- Evidence is hashed, encrypted, custody-chained, and re-verified.
- Analysis extracts real entities and observations from email, logs, documents, images, archives, and text/CSV.
- Correlation is rarity-weighted and explainable; cross-case links in the seed are from shared bytes, not fixtures.
- Insights split observed from interpretation; no language model is required or consulted by default.
- Reports freeze a snapshot and refuse self-signing.
- Auditors cannot download exhibits.

Claims that overshoot the implementation:

- “Full MFA.”
- “Live threat-intel feeds.”
- “AI-written findings.”
- “Disk-image / memory / PCAP forensics.”
- “One-click legal hold, assignment, versioning, and destruction from the console.”
- “Backup that restores the whole platform.”
- “Sanitised document preview.”
- “Every correlation kind and every alert type in the enumerations.”

