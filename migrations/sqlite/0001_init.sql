-- SendBox fleet schema, version 1 (SQLite, for local development and tests).
--
-- Keep equivalent to migrations/postgres/0001_init.sql: same tables, columns,
-- and constraints. SQLite has no regular expressions by default, so grammar
-- checks use GLOB character classes; tables are STRICT so column types are
-- enforced. The service connects with foreign keys enabled. No table stores
-- provider credentials, bearer tokens, authorization headers, request
-- bodies, or any other secret-bearing payload.

-- Authenticated callers: people (`user`) and SendBox hosts (`worker`).
CREATE TABLE principals (
    id TEXT PRIMARY KEY CHECK (
        length(id) <= 160
        AND instr(id, ':') BETWEEN 2 AND 33
        AND length(id) > instr(id, ':')
        AND substr(id, 1, instr(id, ':') - 1) NOT GLOB '*[^a-z-]*'
        AND substr(id, instr(id, ':') + 1) NOT GLOB '*[^A-Za-z0-9._@+:-]*'
        -- Local OS accounts belong to single-host increment 1 and are never
        -- fleet principals.
        AND id NOT GLOB 'local-user:*'
    ),
    kind TEXT NOT NULL CHECK (kind IN ('user', 'worker')),
    display_name TEXT CHECK (display_name IS NULL OR length(display_name) BETWEEN 1 AND 200),
    created_at_unix INTEGER NOT NULL CHECK (created_at_unix >= 0),
    disabled_at_unix INTEGER CHECK (disabled_at_unix IS NULL OR disabled_at_unix >= created_at_unix)
) STRICT;

CREATE TABLE projects (
    id TEXT PRIMARY KEY CHECK (
        length(id) <= 160
        AND (
            (
                id GLOB 'github:[a-z0-9_-]*/[a-z0-9_-]*'
                AND substr(id, 8) NOT GLOB '*[^a-z0-9._/-]*'
                AND length(id) - length(replace(id, '/', '')) = 1
                AND instr(id, '/') - 8 BETWEEN 1 AND 100
                AND length(id) - instr(id, '/') BETWEEN 1 AND 100
            )
            OR (
                id GLOB 'path-sha256:*'
                AND length(id) = 76
                AND substr(id, 13) NOT GLOB '*[^0-9a-f]*'
            )
        )
    ),
    display_name TEXT CHECK (display_name IS NULL OR length(display_name) BETWEEN 1 AND 200),
    created_at_unix INTEGER NOT NULL CHECK (created_at_unix >= 0),
    archived_at_unix INTEGER CHECK (archived_at_unix IS NULL OR archived_at_unix >= created_at_unix)
) STRICT;

-- Project-scoped roles: one role per principal per project.
CREATE TABLE role_bindings (
    project_id TEXT NOT NULL REFERENCES projects (id),
    principal_id TEXT NOT NULL REFERENCES principals (id),
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    granted_by TEXT NOT NULL REFERENCES principals (id),
    granted_at_unix INTEGER NOT NULL CHECK (granted_at_unix >= 0),
    PRIMARY KEY (project_id, principal_id)
) STRICT;
CREATE INDEX role_bindings_principal ON role_bindings (principal_id);

-- Operator-signed profile revisions. `signed_bytes` are the exact bytes the
-- signatures cover and `sha256` is their digest; rows are never edited, a
-- change is a new revision.
CREATE TABLE profiles (
    id TEXT NOT NULL CHECK (
        length(id) BETWEEN 1 AND 64 AND id GLOB '[a-z0-9]*' AND id NOT GLOB '*[^a-z0-9._-]*'
    ),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    sha256 TEXT NOT NULL UNIQUE CHECK (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
    signed_bytes BLOB NOT NULL CHECK (length(signed_bytes) BETWEEN 1 AND 262144),
    signatures TEXT NOT NULL CHECK (
        CASE WHEN json_valid(signatures)
            THEN json_type(signatures) = 'array' AND json_array_length(signatures) BETWEEN 1 AND 16
            ELSE 0
        END
    ),
    not_before_unix INTEGER NOT NULL CHECK (not_before_unix >= 0),
    expires_at_unix INTEGER NOT NULL,
    published_by TEXT NOT NULL REFERENCES principals (id),
    published_at_unix INTEGER NOT NULL CHECK (published_at_unix >= 0),
    PRIMARY KEY (id, revision),
    UNIQUE (id, revision, sha256),
    -- At most 400 days of validity, matching the contract.
    CHECK (expires_at_unix > not_before_unix AND expires_at_unix - not_before_unix <= 34560000)
) STRICT;

-- Revisions below the minimum are stale: sessions, grants, and exceptions
-- bound to them are denied.
CREATE TABLE profile_minimum_revisions (
    profile_id TEXT PRIMARY KEY,
    minimum_revision INTEGER NOT NULL CHECK (minimum_revision >= 1),
    reason TEXT NOT NULL CHECK (length(trim(reason)) BETWEEN 1 AND 1000),
    set_by TEXT NOT NULL REFERENCES principals (id),
    set_at_unix INTEGER NOT NULL CHECK (set_at_unix >= 0),
    FOREIGN KEY (profile_id, minimum_revision) REFERENCES profiles (id, revision)
) STRICT;

-- Admitted sessions and the exact binding they were admitted with.
CREATE TABLE sessions (
    id TEXT PRIMARY KEY CHECK (length(id) = 32 AND id NOT GLOB '*[^0-9a-f]*'),
    principal_id TEXT NOT NULL REFERENCES principals (id),
    project_id TEXT NOT NULL REFERENCES projects (id),
    authority_id TEXT NOT NULL CHECK (
        length(authority_id) BETWEEN 1 AND 128 AND authority_id NOT GLOB '*[^!-~]*'
    ),
    profile_id TEXT NOT NULL,
    profile_revision INTEGER NOT NULL,
    profile_sha256 TEXT NOT NULL,
    effective_policy_sha256 TEXT NOT NULL CHECK (
        length(effective_policy_sha256) = 64 AND effective_policy_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    -- RFC 8785 canonical JSON of the GovernanceBinding, kept byte-exact;
    -- binding_sha256 is its digest.
    binding TEXT NOT NULL CHECK (
        CASE WHEN json_valid(binding)
            THEN json_type(binding) = 'object' AND length(CAST(binding AS BLOB)) <= 16384
            ELSE 0
        END
    ),
    binding_sha256 TEXT NOT NULL CHECK (
        length(binding_sha256) = 64 AND binding_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    status TEXT NOT NULL CHECK (status IN ('admitted', 'completed', 'cancelled', 'failed')),
    -- The worker (SendBox host) that requested admission.
    admitted_by TEXT NOT NULL REFERENCES principals (id),
    admitted_at_unix INTEGER NOT NULL CHECK (admitted_at_unix >= 0),
    ended_at_unix INTEGER,
    FOREIGN KEY (profile_id, profile_revision, profile_sha256)
        REFERENCES profiles (id, revision, sha256),
    UNIQUE (id, principal_id, project_id, binding_sha256, profile_id, profile_revision, profile_sha256),
    CHECK ((status = 'admitted') = (ended_at_unix IS NULL)),
    CHECK (ended_at_unix IS NULL OR ended_at_unix >= admitted_at_unix)
) STRICT;
CREATE INDEX sessions_project ON sessions (project_id);
CREATE INDEX sessions_principal ON sessions (principal_id);

-- Expiring, revocable authorizations for one session to use one brokered
-- service. Deliberately no column can hold credential material: the provider
-- credential stays in the SendBox host broker.
CREATE TABLE credential_grants (
    id TEXT PRIMARY KEY CHECK (length(id) = 32 AND id NOT GLOB '*[^0-9a-f]*'),
    session_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    binding_sha256 TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    profile_revision INTEGER NOT NULL,
    profile_sha256 TEXT NOT NULL,
    service_id TEXT NOT NULL CHECK (
        length(service_id) BETWEEN 1 AND 32
        AND service_id GLOB '[a-z]*'
        AND service_id NOT GLOB '*[^a-z0-9-]*'
    ),
    methods TEXT NOT NULL CHECK (
        CASE WHEN json_valid(methods)
            THEN json_type(methods) = 'array' AND json_array_length(methods) BETWEEN 1 AND 7
            ELSE 0
        END
    ),
    path_prefixes TEXT NOT NULL CHECK (
        CASE WHEN json_valid(path_prefixes)
            THEN json_type(path_prefixes) = 'array' AND json_array_length(path_prefixes) BETWEEN 1 AND 256
            ELSE 0
        END
    ),
    issued_at_unix INTEGER NOT NULL CHECK (issued_at_unix >= 0),
    lease_expires_at_unix INTEGER NOT NULL,
    max_expires_at_unix INTEGER NOT NULL,
    generation INTEGER NOT NULL CHECK (generation >= 1),
    -- A grant carries exactly its session's identity, binding, and profile.
    FOREIGN KEY (session_id, principal_id, project_id, binding_sha256, profile_id, profile_revision, profile_sha256)
        REFERENCES sessions (id, principal_id, project_id, binding_sha256, profile_id, profile_revision, profile_sha256),
    CHECK (issued_at_unix < lease_expires_at_unix AND lease_expires_at_unix <= max_expires_at_unix),
    -- At most 7 days from issue to hard expiry, matching the contract.
    CHECK (max_expires_at_unix - issued_at_unix <= 604800)
) STRICT;
CREATE INDEX credential_grants_session ON credential_grants (session_id);

-- A revoked grant denies new requests immediately. Already-open upstream
-- streams may finish until `grace_expires_at_unix` (at most 60 seconds);
-- revocation does not undo completed external effects.
CREATE TABLE revocations (
    grant_id TEXT PRIMARY KEY REFERENCES credential_grants (id),
    reason TEXT NOT NULL CHECK (
        reason IN ('session_completed', 'session_cancelled', 'session_failed', 'operator_revoked', 'policy_changed')
    ),
    -- NULL when the service revoked the grant itself, for example at session end.
    revoked_by TEXT REFERENCES principals (id),
    revoked_at_unix INTEGER NOT NULL CHECK (revoked_at_unix >= 0),
    grace_expires_at_unix INTEGER NOT NULL,
    generation INTEGER NOT NULL CHECK (generation >= 2),
    CHECK (grace_expires_at_unix >= revoked_at_unix AND grace_expires_at_unix - revoked_at_unix <= 60),
    CHECK (reason <> 'operator_revoked' OR revoked_by IS NOT NULL)
) STRICT;

-- Bounded, expiring exceptions. Each is bound to the exact profile revision it
-- was reviewed against, so a stale approval cannot authorize changed work, and
-- the service rejects any scope outside that revision's ceiling.
CREATE TABLE exceptions (
    id TEXT PRIMARY KEY CHECK (length(id) = 32 AND id NOT GLOB '*[^0-9a-f]*'),
    project_id TEXT NOT NULL REFERENCES projects (id),
    -- NULL covers every member of the project.
    principal_id TEXT REFERENCES principals (id),
    profile_id TEXT NOT NULL,
    profile_revision INTEGER NOT NULL,
    profile_sha256 TEXT NOT NULL,
    scope_kind TEXT NOT NULL CHECK (
        scope_kind IN ('network_domain', 'command', 'mcp_tool', 'credential_service_path')
    ),
    scope_value TEXT NOT NULL CHECK (
        length(scope_value) BETWEEN 1 AND 256 AND scope_value NOT GLOB '*[^!-~]*'
    ),
    reason TEXT NOT NULL CHECK (length(trim(reason)) BETWEEN 1 AND 1000),
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
    requested_by TEXT NOT NULL REFERENCES principals (id),
    requested_at_unix INTEGER NOT NULL CHECK (requested_at_unix >= 0),
    -- The approver (or rejecter); never the requester.
    decided_by TEXT REFERENCES principals (id),
    decided_at_unix INTEGER,
    expires_at_unix INTEGER NOT NULL,
    revoked_by TEXT REFERENCES principals (id),
    revoked_at_unix INTEGER,
    FOREIGN KEY (profile_id, profile_revision, profile_sha256)
        REFERENCES profiles (id, revision, sha256),
    CHECK (decided_by IS NULL OR decided_by <> requested_by),
    CHECK ((status = 'pending') = (decided_by IS NULL)),
    CHECK ((decided_by IS NULL) = (decided_at_unix IS NULL)),
    CHECK (decided_at_unix IS NULL OR decided_at_unix >= requested_at_unix),
    CHECK ((revoked_by IS NULL) = (revoked_at_unix IS NULL)),
    CHECK (revoked_at_unix IS NULL OR status = 'approved'),
    -- At most 7 days from request to expiry.
    CHECK (expires_at_unix > requested_at_unix AND expires_at_unix - requested_at_unix <= 604800)
) STRICT;
CREATE INDEX exceptions_project ON exceptions (project_id);

-- Append-only, hash-chained audit log. Each event_hash is computed by the
-- service over previous_hash and the event's canonical JSON. The first
-- trigger enforces contiguous sequences and chain linkage; the others forbid
-- UPDATE and DELETE.
CREATE TABLE audit_events (
    sequence INTEGER PRIMARY KEY CHECK (sequence >= 1),
    occurred_at_unix INTEGER NOT NULL CHECK (occurred_at_unix >= 0),
    recorded_at_unix INTEGER NOT NULL CHECK (recorded_at_unix >= 0),
    event_type TEXT NOT NULL CHECK (
        length(event_type) BETWEEN 1 AND 64
        AND event_type GLOB '[a-z]*'
        AND event_type NOT GLOB '*[^a-z0-9_.]*'
    ),
    -- The authenticated caller that caused the event.
    actor_id TEXT CHECK (actor_id IS NULL OR length(actor_id) <= 160),
    -- Identifiers are copied, not referenced, so evidence outlives its subjects.
    principal_id TEXT CHECK (principal_id IS NULL OR length(principal_id) <= 160),
    project_id TEXT CHECK (project_id IS NULL OR length(project_id) <= 160),
    session_id TEXT CHECK (
        session_id IS NULL OR (length(session_id) = 32 AND session_id NOT GLOB '*[^0-9a-f]*')
    ),
    grant_id TEXT CHECK (
        grant_id IS NULL OR (length(grant_id) = 32 AND grant_id NOT GLOB '*[^0-9a-f]*')
    ),
    profile_id TEXT CHECK (profile_id IS NULL OR length(profile_id) <= 64),
    profile_revision INTEGER CHECK (profile_revision IS NULL OR profile_revision >= 1),
    decision TEXT CHECK (decision IS NULL OR decision IN ('allow', 'deny')),
    deny_reason TEXT CHECK (
        deny_reason IS NULL OR deny_reason IN (
            'unknown_grant', 'revoked', 'expired', 'lease_expired', 'principal_mismatch',
            'project_mismatch', 'session_mismatch', 'binding_mismatch', 'stale_policy',
            'service_not_granted', 'method_not_granted', 'path_not_granted', 'invalid_path',
            'authority_unavailable'
        )
    ),
    outcome TEXT CHECK (outcome IS NULL OR outcome IN ('succeeded', 'failed', 'unknown')),
    -- Method, host, and path prefix only: never a query string or body.
    target_redacted TEXT CHECK (
        target_redacted IS NULL OR (length(target_redacted) <= 512 AND instr(target_redacted, '?') = 0)
    ),
    previous_hash TEXT NOT NULL CHECK (
        length(previous_hash) = 64 AND previous_hash NOT GLOB '*[^0-9a-f]*'
    ),
    event_hash TEXT NOT NULL UNIQUE CHECK (
        length(event_hash) = 64 AND event_hash NOT GLOB '*[^0-9a-f]*'
    ),
    CHECK (deny_reason IS NULL OR decision = 'deny'),
    CHECK (decision IS NOT 'deny' OR deny_reason IS NOT NULL),
    CHECK (
        (sequence = 1) = (previous_hash = '0000000000000000000000000000000000000000000000000000000000000000')
    )
) STRICT;
CREATE INDEX audit_events_project ON audit_events (project_id, sequence);
CREATE INDEX audit_events_session ON audit_events (session_id, sequence);
CREATE INDEX audit_events_principal ON audit_events (principal_id, sequence);

CREATE TRIGGER audit_events_extend_chain
BEFORE INSERT ON audit_events
WHEN NEW.sequence IS NOT COALESCE((SELECT max(sequence) FROM audit_events), 0) + 1
    OR NEW.previous_hash IS NOT COALESCE(
        (SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1),
        '0000000000000000000000000000000000000000000000000000000000000000'
    )
BEGIN
    SELECT RAISE(ABORT, 'audit_events must extend the hash chain');
END;

CREATE TRIGGER audit_events_reject_update
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

CREATE TRIGGER audit_events_reject_delete
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;
