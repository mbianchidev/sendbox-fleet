# Threat model

Scope: the shared governance service in this repository and its interfaces to
SendBox hosts, people, and its database. The SendBox VM boundary, host broker,
and increment-1 local authority are covered in the sendbox repository.

Status column: **in scaffold** means implemented and tested here; **planned**
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
| Operator | Trusted to sign and publish profiles |
| Project owner, admin, member, viewer | Trusted within their project role |
| Worker (SendBox host) | Trusted to report its own sessions; untrusted for anything else |
| Workload (agent inside a VM) | Untrusted; never talks to the fleet directly |
| Network attacker | Untrusted |
| Database administrator | Can bypass application controls; mitigated by evidence anchoring |

## Threats and mitigations

| # | Threat | Mitigation | Status |
| --- | --- | --- | --- |
| T1 | Caller spoofs identity with headers such as `X-Forwarded-User` | Only bearer tokens authenticate; identity headers are ignored; auth runs before routing | In scaffold (tested) |
| T2 | Workload-supplied identity in a body is trusted | Body principals and projects are claims checked against the authenticated caller and stored state; `local-user:` principals rejected by API and schema | Partly in scaffold; checks planned |
| T3 | Stolen or replayed bearer token | Short-lived tokens from a real identity provider, audience binding, TLS everywhere | Planned (provider not chosen) |
| T4 | Compromised worker acts for sessions it does not run | Workers may only act on sessions they admitted; grants bound to session, principal, project, binding digest, and profile revision (composite foreign key) | Schema in scaffold; logic planned |
| T5 | Stale policy or approval authorizes changed work | Sessions, grants, and exceptions reference an exact profile revision and digest; minimum revisions; stale revisions deny | Schema in scaffold; logic planned |
| T6 | Grant wider than the profile allows | Contract validation of methods and path prefixes at the API; ceiling checks; 7-day TTL bound in the schema | Validation and bounds in scaffold; ceiling checks planned |
| T7 | Audit evidence altered or deleted | Append-only triggers, contiguous hash chain enforced on insert, service role without `UPDATE`/`DELETE`; external anchoring of chain heads against a database administrator | Triggers in scaffold; hashing and anchoring planned |
| T8 | Secrets leak into logs or audit | No request bodies, headers, or query strings logged; database URL credentials redacted; no credential columns; audit keeps a redacted target without query strings (schema check) | In scaffold |
| T9 | Authority outage silently allows requests | Hosts must deny with `authority_unavailable` on any non-200 answer (contract semantics); the scaffold answers `501` | Contract rule; host integration planned |
| T10 | Exception abuse or self-approval | Bounded scope, reason, expiry of at most 7 days, approver differs from requester (schema check), never wider than the profile ceiling | Bounds in scaffold; approval flow planned |
| T11 | Revocation does not stop in-flight traffic | New requests denied at once; open streams bounded by a grace window of at most 60 seconds; uncertain outcomes audited as `unknown` | Schema in scaffold; logic planned |
| T12 | Resource exhaustion | Body limits (64 KiB, 1 MiB for profile publication), bounded connection pool and acquire timeout, non-lossy bounded log queue | In scaffold; rate limiting planned |
| T13 | Supply-chain compromise | Actions pinned by commit SHA, images pinned by digest, `Cargo.lock` committed, contract pinned by git revision, `cargo audit` in CI with documented exceptions | In scaffold |

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
