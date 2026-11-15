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

The scaffold delivers the service skeleton, contract-validated `/v1` routes
that return `501`, the schema with its database-level invariants, CI, and
these documents.

## Work items

1. **Caller authentication** (AC7). Integrate an identity provider for users
   and a workload identity for SendBox hosts (for example mTLS or signed,
   short-lived worker tokens). Replace `UnconfiguredAuthenticator`; keep the
   bearer-only rule and the "authenticate before validating" ordering.
   *Done when* users and workers authenticate with expiring credentials and
   every `/v1` call records the authenticated actor.
2. **Persistence layer** (all). Repositories over the existing tables, an
   injectable clock, random identifiers, and transactions that keep the
   database invariants as the only source of truth.
3. **Profiles** (AC1, AC5). Publication with signature verification over the
   exact bytes (adopting the signing envelope from `sendbox-governance`),
   current-revision lookup, minimum revisions, and a `RevisionSource`
   backed by the database. *Done when* a host can only admit sessions under a
   current, verified revision.
4. **Project-scoped roles** (AC7). Owner bootstrap, assignment and listing
   with role checks, and audit of every change. *Done when* role checks gate
   admission, exceptions, and audit visibility.
5. **Session admission** (AC1, AC4). Verify the worker, the principal's role in
   the project, the profile revision, and the binding digest; record the
   session. *Done when* a host that presents a changed binding or stale
   revision is refused.
6. **Grants and revocation** (AC4, AC5, AC6). Issue, renew, and revoke with
   bounded leases (profile `lease_seconds`, `max_ttl_seconds`); end all grants
   when a session completes, fails, or is cancelled; deny new requests at once
   and let open streams finish only within `revocation_grace_seconds` (at most
   60 seconds); record uncertain external effects as outcome `unknown`.
   Includes the remote authority client in the sendbox host (sendbox
   repository). *Done when* revoked or expired grants deny on the next request
   and existing connections close within the grace window.
7. **Per-request authorization** (AC4, AC5). `POST /v1/authorize` with the same
   semantics as `LocalGrantAuthority::authorize`, a latency budget, and
   fail-closed behaviour on the host (`authority_unavailable`). *Done when*
   every cross-identity and stale-policy case from the contract tests denies
   through the service.
8. **Exceptions** (AC7). Request, approve, reject, and revoke; approver must be
   an authorized principal other than the requester; scope must stay inside
   the bound profile revision's ceiling (never above the operator maximum);
   expiry at most 7 days. *Done when* an approval bound to an older revision
   is rejected after a new revision or minimum revision is published (stale
   approval rejection).
9. **Central audit** (AC6, AC7). Compute the hash chain, correlate principal,
   project, session, profile revision, redacted target, decision, and outcome
   from hosts and the service; role-scoped queries; anchor chain heads outside
   the database. *Done when* every decision above produces an attributable,
   verifiable event without secret-bearing payloads.
10. **Operations** (AC8). TLS termination guidance, rate limiting, metrics,
    backups, database role hardening (no `UPDATE`/`DELETE` on audit), and
    deployment docs. Size-based log rotation alongside the daily rotation.
11. **Dependency follow-ups.** Move the contract pin to a merged sendbox
    commit; upgrade to sqlx 0.9 once the toolchain moves to Rust 1.94 or later
    and drop the `cargo audit` exceptions in `.cargo/audit.toml`.

## Non-goals

Kubernetes or fleet scheduling, universal TLS interception, formal policy
verification, and replacing SendBox isolation providers (as in the issue).
The service never stores or forwards provider credentials.
