# Threat model

Scope: the shared governance service in this repository and its interfaces to
SendBox hosts, people, and its database. The SendBox VM boundary, host broker,
and increment-1 local authority are covered in the sendbox repository.

Status column: **implemented** means implemented and tested here; **planned**
means designed but not implemented (see [roadmap.md](roadmap.md)).

## Assets

- Authorization decisions: session admission, grants, per-request decisions.
- Policy state: signed profile revisions, minimum revisions, project roles,
  exceptions.
- Audit evidence and its integrity.
- Availability of authorization for running sessions.

Provider credentials are **not** an asset of this service: they stay in the
SendBox host broker and never reach the fleet.

## Actors

| Actor | Trust |
| --- | --- |
| Operator | Trusted to sign and publish profiles, create projects, and recover ownership |
| Project owner, admin, member, viewer | Trusted within their project role |
| SendBox host (user or worker token) | Trusted to report sessions of the principal whose token it holds; untrusted for anything else |
| Service host administrator (`sendbox-fleet admin`) | Issues tokens and creates principals; equivalent to database access |
| Workload (agent inside a VM) | Untrusted; never talks to the fleet directly |
| Network attacker | Untrusted |
| Database administrator | Can bypass application controls; mitigated by evidence anchoring |

## Threats and mitigations

| # | Threat | Mitigation | Status |
| --- | --- | --- | --- |
| T1 | Caller spoofs identity with headers such as `X-Forwarded-User` | Only bearer tokens authenticate; identity headers are ignored; auth runs before routing | Implemented (tested) |
| T2 | Workload-supplied identity in a body is trusted | Binding and grant principals must equal the authenticated caller; projects and sessions are checked against stored state; `local-user:` principals rejected by API and schema | Implemented (tested) |
| T3 | Stolen or replayed bearer token | Tokens stored only as SHA-256, expiring within 90 days, revocable, void when the principal is disabled; TLS in front of the service | Implemented; identity provider and audience binding planned |
| T4 | Compromised worker acts for sessions it does not run | A caller can only admit, use, renew, or end sessions bound to its own principal; grants bound to session, principal, project, binding digest, and profile revision (composite foreign key) | Implemented (tested) |
| T5 | Stale policy or approval authorizes changed work | Sessions, grants, and exceptions reference an exact profile revision and digest; a new revision or raised minimum makes them stale; approvals of stale requests are refused; sessions bound to a revoked or expired exception are denied | Implemented (tested) |
| T6 | Grant wider than the profile allows | Methods and path prefixes must be inside the profile service; lifetime capped by the profile TTL, profile expiry, exception expiry, and 7 days | Implemented (tested) |
| T7 | Audit evidence altered or deleted | Append-only triggers, contiguous hash chain computed by the service and enforced on insert, `GET /v1/audit/verify`; service role without `UPDATE`/`DELETE`; external anchoring of chain heads against a database administrator | Implemented except role hardening and anchoring (planned) |
| T8 | Secrets leak into logs or audit | No request bodies, headers, or query strings logged; database URL credentials redacted; tokens stored only as digests; no credential columns; audit keeps a redacted target without query strings (schema check) and omits exception reasons | Implemented (tested) |
| T9 | Authority outage silently allows requests | Hosts deny with `authority_unavailable` on any non-200 answer, timeout, or redirect; a token lookup failure is `503` | Implemented (host client tested in sendbox) |
| T10 | Exception abuse or self-approval | Only denials the signed revision lists as liftable; reason; expiry at most the profile's `exceptions.max_ttl_seconds` and 7 days; approver is a different `owner` or `admin` (also a schema check); lifting never widens the ceiling; every request, decision, refusal, use, and revocation audited | Implemented (tested) |
| T11 | Revocation does not stop in-flight traffic | New requests denied at once; open streams bounded by the profile grace window (at most 60 seconds) on the host; uncertain outcomes audited on the host as `aborted_uncertain` | Implemented; central outcome reporting planned |
| T12 | Resource exhaustion | Body limits (64 KiB, 1 MiB for profile publication), bounded connection pool and acquire timeout, bounded list sizes, non-lossy bounded log queue | Implemented; rate limiting planned |
| T13 | Supply-chain compromise | Actions pinned by commit SHA, images pinned by digest, `Cargo.lock` committed, contract pinned by git revision, `cargo audit` in CI with documented exceptions | Implemented |

## Known accepted risks

- `RUSTSEC-2026-0459` (bundled SQLite older than 3.54): SQLite is used only
  for local development and tests on files the service creates. Fixing it
  needs sqlx 0.9, which needs Rust 1.94; this workspace matches SendBox's
  pinned Rust 1.93.1. Tracked in [roadmap.md](roadmap.md).
- `RUSTSEC-2023-0071` (`rsa`): present in `Cargo.lock` only through sqlx's
  optional MySQL support and never compiled.
- Database triggers do not stop a database superuser. Production must run the
  service with a least-privilege role, and chain heads must be anchored
  outside the database.
