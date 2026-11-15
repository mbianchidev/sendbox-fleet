-- SendBox fleet schema, version 1 (PostgreSQL).
--
-- Keep migrations/sqlite/0001_init.sql equivalent: same tables, columns, and
-- constraints. Timestamps are Unix seconds to match the sendbox-governance
-- contract. Identifier columns repeat the contract's grammar and bounds so a
-- row stays valid whichever client wrote it. No table stores provider
-- credentials, bearer tokens, authorization headers, request bodies, or any
-- other secret-bearing payload.

-- Authenticated callers: people (`user`) and SendBox hosts (`worker`).
CREATE TABLE principals (
    id TEXT PRIMARY KEY CHECK (
        char_length(id) <= 160
        AND id ~ '^[a-z-]{1,32}:[A-Za-z0-9._@+:-]+$'
        -- Local OS accounts belong to single-host increment 1 and are never
        -- fleet principals.
        AND id NOT LIKE 'local-user:%'
    ),
    kind TEXT NOT NULL CHECK (kind IN ('user', 'worker')),
    display_name TEXT CHECK (display_name IS NULL OR char_length(display_name) BETWEEN 1 AND 200),
    created_at_unix BIGINT NOT NULL CHECK (created_at_unix >= 0),
    disabled_at_unix BIGINT CHECK (disabled_at_unix IS NULL OR disabled_at_unix >= created_at_unix)
);

CREATE TABLE projects (
    id TEXT PRIMARY KEY CHECK (
        char_length(id) <= 160
        AND (
            id ~ '^github:[a-z0-9_-][a-z0-9._-]{0,99}/[a-z0-9_-][a-z0-9._-]{0,99}$'
            OR id ~ '^path-sha256:[0-9a-f]{64}$'
        )
    ),
    display_name TEXT CHECK (display_name IS NULL OR char_length(display_name) BETWEEN 1 AND 200),
    created_at_unix BIGINT NOT NULL CHECK (created_at_unix >= 0),
    archived_at_unix BIGINT CHECK (archived_at_unix IS NULL OR archived_at_unix >= created_at_unix)
);

-- Project-scoped roles: one role per principal per project.
CREATE TABLE role_bindings (
    project_id TEXT NOT NULL REFERENCES projects (id),
    principal_id TEXT NOT NULL REFERENCES principals (id),
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    granted_by TEXT NOT NULL REFERENCES principals (id),
    granted_at_unix BIGINT NOT NULL CHECK (granted_at_unix >= 0),
    PRIMARY KEY (project_id, principal_id)
);
CREATE INDEX role_bindings_principal ON role_bindings (principal_id);

-- Operator-signed profile revisions. `signed_bytes` are the exact bytes the
-- signatures cover and `sha256` is their digest; rows are never edited, a
-- change is a new revision.
CREATE TABLE profiles (
    id TEXT NOT NULL CHECK (id ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    revision BIGINT NOT NULL CHECK (revision >= 1),
    sha256 TEXT NOT NULL UNIQUE CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    signed_bytes BYTEA NOT NULL CHECK (octet_length(signed_bytes) BETWEEN 1 AND 262144),
    signatures JSONB NOT NULL CHECK (
        CASE WHEN jsonb_typeof(signatures) = 'array'
            THEN jsonb_array_length(signatures) BETWEEN 1 AND 16
            ELSE false
        END
    ),
    not_before_unix BIGINT NOT NULL CHECK (not_before_unix >= 0),
    expires_at_unix BIGINT NOT NULL,
    published_by TEXT NOT NULL REFERENCES principals (id),
    published_at_unix BIGINT NOT NULL CHECK (published_at_unix >= 0),
    PRIMARY KEY (id, revision),
    UNIQUE (id, revision, sha256),
    -- At most 400 days of validity, matching the contract.
    CHECK (expires_at_unix > not_before_unix AND expires_at_unix - not_before_unix <= 34560000)
);

-- Revisions below the minimum are stale: sessions, grants, and exceptions
-- bound to them are denied.
CREATE TABLE profile_minimum_revisions (
    profile_id TEXT PRIMARY KEY,
    minimum_revision BIGINT NOT NULL CHECK (minimum_revision >= 1),
    reason TEXT NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 1 AND 1000),
    set_by TEXT NOT NULL REFERENCES principals (id),
    set_at_unix BIGINT NOT NULL CHECK (set_at_unix >= 0),
    FOREIGN KEY (profile_id, minimum_revision) REFERENCES profiles (id, revision)
);

-- Admitted sessions and the exact binding they were admitted with.
CREATE TABLE sessions (
    id TEXT PRIMARY KEY CHECK (id ~ '^[0-9a-f]{32}$'),
    principal_id TEXT NOT NULL REFERENCES principals (id),
    project_id TEXT NOT NULL REFERENCES projects (id),
    authority_id TEXT NOT NULL CHECK (authority_id ~ '^[!-~]{1,128}$'),
    profile_id TEXT NOT NULL,
    profile_revision BIGINT NOT NULL,
    profile_sha256 TEXT NOT NULL,
    effective_policy_sha256 TEXT NOT NULL CHECK (effective_policy_sha256 ~ '^[0-9a-f]{64}$'),
    -- RFC 8785 canonical JSON of the GovernanceBinding, kept byte-exact;
    -- binding_sha256 is its digest.
    binding JSON NOT NULL CHECK (json_typeof(binding) = 'object' AND octet_length(binding::text) <= 16384),
    binding_sha256 TEXT NOT NULL CHECK (binding_sha256 ~ '^[0-9a-f]{64}$'),
    status TEXT NOT NULL CHECK (status IN ('admitted', 'completed', 'cancelled', 'failed')),
    -- The worker (SendBox host) that requested admission.
    admitted_by TEXT NOT NULL REFERENCES principals (id),
    admitted_at_unix BIGINT NOT NULL CHECK (admitted_at_unix >= 0),
    ended_at_unix BIGINT,
    FOREIGN KEY (profile_id, profile_revision, profile_sha256)
        REFERENCES profiles (id, revision, sha256),
    UNIQUE (id, principal_id, project_id, binding_sha256, profile_id, profile_revision, profile_sha256),
    CHECK ((status = 'admitted') = (ended_at_unix IS NULL)),
    CHECK (ended_at_unix IS NULL OR ended_at_unix >= admitted_at_unix)
);
CREATE INDEX sessions_project ON sessions (project_id);
CREATE INDEX sessions_principal ON sessions (principal_id);

-- Expiring, revocable authorizations for one session to use one brokered
-- service. Deliberately no column can hold credential material: the provider
-- credential stays in the SendBox host broker.
CREATE TABLE credential_grants (
    id TEXT PRIMARY KEY CHECK (id ~ '^[0-9a-f]{32}$'),
    session_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    binding_sha256 TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    profile_revision BIGINT NOT NULL,
    profile_sha256 TEXT NOT NULL,
    service_id TEXT NOT NULL CHECK (service_id ~ '^[a-z][a-z0-9-]{0,31}$'),
    methods JSONB NOT NULL CHECK (
        CASE WHEN jsonb_typeof(methods) = 'array'
            THEN jsonb_array_length(methods) BETWEEN 1 AND 7
            ELSE false
        END
    ),
    path_prefixes JSONB NOT NULL CHECK (
        CASE WHEN jsonb_typeof(path_prefixes) = 'array'
            THEN jsonb_array_length(path_prefixes) BETWEEN 1 AND 256
            ELSE false
        END
    ),
    issued_at_unix BIGINT NOT NULL CHECK (issued_at_unix >= 0),
    lease_expires_at_unix BIGINT NOT NULL,
    max_expires_at_unix BIGINT NOT NULL,
    generation BIGINT NOT NULL CHECK (generation >= 1),
    -- A grant carries exactly its session's identity, binding, and profile.
    FOREIGN KEY (session_id, principal_id, project_id, binding_sha256, profile_id, profile_revision, profile_sha256)
        REFERENCES sessions (id, principal_id, project_id, binding_sha256, profile_id, profile_revision, profile_sha256),
    CHECK (issued_at_unix < lease_expires_at_unix AND lease_expires_at_unix <= max_expires_at_unix),
    -- At most 7 days from issue to hard expiry, matching the contract.
    CHECK (max_expires_at_unix - issued_at_unix <= 604800)
);
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
    revoked_at_unix BIGINT NOT NULL CHECK (revoked_at_unix >= 0),
    grace_expires_at_unix BIGINT NOT NULL,
    generation BIGINT NOT NULL CHECK (generation >= 2),
    CHECK (grace_expires_at_unix >= revoked_at_unix AND grace_expires_at_unix - revoked_at_unix <= 60),
    CHECK (reason <> 'operator_revoked' OR revoked_by IS NOT NULL)
);

-- Bounded, expiring exceptions. Each is bound to the exact profile revision it
-- was reviewed against, so a stale approval cannot authorize changed work, and
-- the service rejects any scope outside that revision's ceiling.
CREATE TABLE exceptions (
    id TEXT PRIMARY KEY CHECK (id ~ '^[0-9a-f]{32}$'),
    project_id TEXT NOT NULL REFERENCES projects (id),
    -- NULL covers every member of the project.
    principal_id TEXT REFERENCES principals (id),
    profile_id TEXT NOT NULL,
    profile_revision BIGINT NOT NULL,
    profile_sha256 TEXT NOT NULL,
    scope_kind TEXT NOT NULL CHECK (
        scope_kind IN ('network_domain', 'command', 'mcp_tool', 'credential_service_path')
    ),
    scope_value TEXT NOT NULL CHECK (char_length(scope_value) BETWEEN 1 AND 256 AND scope_value ~ '^[!-~]+$'),
    reason TEXT NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 1 AND 1000),
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
    requested_by TEXT NOT NULL REFERENCES principals (id),
    requested_at_unix BIGINT NOT NULL CHECK (requested_at_unix >= 0),
    -- The approver (or rejecter); never the requester.
    decided_by TEXT REFERENCES principals (id),
    decided_at_unix BIGINT,
    expires_at_unix BIGINT NOT NULL,
    revoked_by TEXT REFERENCES principals (id),
    revoked_at_unix BIGINT,
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
);
CREATE INDEX exceptions_project ON exceptions (project_id);

-- Append-only, hash-chained audit log. Each event_hash is computed by the
-- service over previous_hash and the event's canonical JSON. The trigger
-- below enforces contiguous sequences and chain linkage; a second trigger
-- forbids UPDATE, DELETE, and TRUNCATE. Deployments should additionally run
-- the service with a role that lacks those privileges.
CREATE TABLE audit_events (
    sequence BIGINT PRIMARY KEY CHECK (sequence >= 1),
    occurred_at_unix BIGINT NOT NULL CHECK (occurred_at_unix >= 0),
    recorded_at_unix BIGINT NOT NULL CHECK (recorded_at_unix >= 0),
    event_type TEXT NOT NULL CHECK (event_type ~ '^[a-z][a-z0-9_.]{0,63}$'),
    -- The authenticated caller that caused the event.
    actor_id TEXT CHECK (actor_id IS NULL OR char_length(actor_id) <= 160),
    -- Identifiers are copied, not referenced, so evidence outlives its subjects.
    principal_id TEXT CHECK (principal_id IS NULL OR char_length(principal_id) <= 160),
    project_id TEXT CHECK (project_id IS NULL OR char_length(project_id) <= 160),
    session_id TEXT CHECK (session_id IS NULL OR session_id ~ '^[0-9a-f]{32}$'),
    grant_id TEXT CHECK (grant_id IS NULL OR grant_id ~ '^[0-9a-f]{32}$'),
    profile_id TEXT CHECK (profile_id IS NULL OR char_length(profile_id) <= 64),
    profile_revision BIGINT CHECK (profile_revision IS NULL OR profile_revision >= 1),
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
        target_redacted IS NULL OR (char_length(target_redacted) <= 512 AND position('?' in target_redacted) = 0)
    ),
    previous_hash TEXT NOT NULL CHECK (previous_hash ~ '^[0-9a-f]{64}$'),
    event_hash TEXT NOT NULL UNIQUE CHECK (event_hash ~ '^[0-9a-f]{64}$'),
    CHECK (deny_reason IS NULL OR decision = 'deny'),
    CHECK (decision IS DISTINCT FROM 'deny' OR deny_reason IS NOT NULL),
    CHECK (
        (sequence = 1) = (previous_hash = '0000000000000000000000000000000000000000000000000000000000000000')
    )
);
CREATE INDEX audit_events_project ON audit_events (project_id, sequence);
CREATE INDEX audit_events_session ON audit_events (session_id, sequence);
CREATE INDEX audit_events_principal ON audit_events (principal_id, sequence);

CREATE FUNCTION audit_events_extend_chain() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    last_sequence BIGINT;
    last_hash TEXT;
BEGIN
    SELECT sequence, event_hash INTO last_sequence, last_hash
    FROM audit_events
    ORDER BY sequence DESC
    LIMIT 1;
    IF NEW.sequence <> COALESCE(last_sequence, 0) + 1
        OR NEW.previous_hash <> COALESCE(last_hash, '0000000000000000000000000000000000000000000000000000000000000000') THEN
        RAISE EXCEPTION 'audit_events must extend the hash chain'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER audit_events_extend_chain
    BEFORE INSERT ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_extend_chain();

CREATE FUNCTION audit_events_reject_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only'
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER audit_events_reject_update_delete
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_reject_change();

CREATE TRIGGER audit_events_reject_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION audit_events_reject_change();
