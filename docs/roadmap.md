# Roadmap

Increment-2 work for
[mbianchidev/sendbox#87](https://github.com/mbianchidev/sendbox/issues/87).
Each item names the issue's acceptance criteria (AC) it serves:

- **AC1** A trusted shared profile is enforced at actual session admission and
  execution; project configuration and CLI flags cannot broaden or bypass it.
- **AC4** Cross-principal, project, or session requests, changed policy
  bindings, and forbidden destinations, methods, or paths are rejected at the
  enforcement boundary.
- **AC5** Expired or revoked grants, stale policy, and unavailable
  authorization produce explicit denial without credential export or fallback.
- **AC6** Session cancellation and teardown end grants while preserving
  redacted audit evidence and reporting uncertain external outcomes honestly.
- **AC7** The shared-service increment enforces project-scoped roles and
  authorized, expiring exceptions with attributable audit records.
- **AC8** Standalone workflows stay unchanged unless governance is selected;
  compatibility and trust boundaries are documented.

## Done

The scaffold delivered the service skeleton, the schema with its database
invariants, CI, and these documents. Increment 2 then delivered:

- **Caller authentication** (AC7). Opaque bearer tokens issued by
  `sendbox-fleet admin token issue`, stored only as SHA-256 digests, expiring
  within 90 days, revocable, and void when the principal is disabled. The
  bearer-only rule and "authenticate before validating" ordering are kept.
- **Persistence** (all). Backend-neutral transactions over PostgreSQL and
  SQLite with serialized writers, an injectable clock, random identifiers,
  and every change committed with its audit event.
- **Profiles** (AC1, AC5). Publication verified against `FLEET_PROFILE_TRUST`
  using the `sendbox.governance-signatures` bundle from `sendbox governance
  sign`; monotonic revisions; current-revision lookup; rising minimums.
- **Project-scoped roles** (AC7). Operator project bootstrap, owner-managed
  assignment and removal, last-owner guard, audited refusals. Roles gate
  admission, exceptions, and audit visibility.
- **Session admission** (AC1, AC4). Caller-bound principal, this authority,
  `member` role, current revision, offered services, and valid exceptions.
- **Grants and revocation** (AC4, AC5, AC6). Issue, renew, revoke, and end
  sessions with bounded leases, exception-capped expiry, and the profile grace
  window. The SendBox host's remote authority client lives in the sendbox
  repository.
- **Per-request authorization** (AC4, AC5). Same rules as the local authority
  through the shared `evaluate_request`, plus session and exception state.
- **Exceptions** (AC7). Request, approve, reject, revoke; a different
  `owner` or `admin` approves; scope limited to denials the signed revision
  lists as liftable; expiry at most 7 days; stale approvals rejected after a
  new revision or minimum.
- **Central audit** (AC6, AC7). Hash-chained events for every decision with
  actor, principal, project, session, grant, exception, revision, decision,
  redacted target, and detail; role-scoped queries; chain verification.

## Remaining

1. **Identity provider** (AC7 hardening). Replace or complement admin-issued
   tokens with OIDC for people and mTLS or signed short-lived tokens for
   workers; self-service token issuance.
2. **Live end-to-end runs.** Run Apple and Kata governed sessions against a
   deployed fleet and real model providers.
3. **Audit anchoring and outcomes.** Anchor chain heads outside the database;
   accept host-reported stream outcomes (`succeeded`, `failed`, `unknown`).
4. **Operations** (AC8). TLS termination guidance, rate limiting, metrics,
   backups, database role hardening (no `UPDATE`/`DELETE` on audit),
   deployment docs, and size-based log rotation.
5. **Dependency follow-ups.** Move the contract pin to a merged sendbox
   commit; upgrade to sqlx 0.9 once the toolchain moves to Rust 1.94 or later
   and drop the `cargo audit` exceptions in `.cargo/audit.toml`.

## Non-goals

Kubernetes or fleet scheduling, universal TLS interception, formal policy
verification, and replacing SendBox isolation providers (as in the issue).
The service never stores or forwards provider credentials.
