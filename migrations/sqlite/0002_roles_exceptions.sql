-- SendBox fleet schema, version 2 (SQLite): authentication, operator
-- designation, profile-scoped exceptions, and exception-aware audit.
--
-- Keep equivalent to migrations/postgres/0002_roles_exceptions.sql.

-- Fleet-wide operators publish profiles, set minimum revisions, and create
-- projects. Everything else is decided by project-scoped roles.
ALTER TABLE principals ADD COLUMN is_operator INTEGER NOT NULL DEFAULT 0 CHECK (is_operator IN (0, 1));

-- Bearer tokens. Only the SHA-256 of a token is stored, never the token.
CREATE TABLE api_tokens (
    id TEXT PRIMARY KEY CHECK (length(id) = 32 AND id NOT GLOB '*[^0-9a-f]*'),
    principal_id TEXT NOT NULL REFERENCES principals (id),
    token_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(token_sha256) = 64 AND token_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    description TEXT CHECK (description IS NULL OR length(description) BETWEEN 1 AND 200),
    created_at_unix INTEGER NOT NULL CHECK (created_at_unix >= 0),
    expires_at_unix INTEGER NOT NULL,
    revoked_at_unix INTEGER CHECK (revoked_at_unix IS NULL OR revoked_at_unix >= created_at_unix),
    -- At most 90 days from issue to expiry.
    CHECK (expires_at_unix > created_at_unix AND expires_at_unix - created_at_unix <= 7776000)
) STRICT;
CREATE INDEX api_tokens_principal ON api_tokens (principal_id);

-- Version 1 reserved scope kinds that no profile could grant. An exception now
-- lifts exactly one denial the bound profile revision lists as liftable
-- (`command`, `domain`, or `network`); command patterns contain spaces. No
-- version 1 release wrote exceptions, so the table is recreated.
DROP TABLE exceptions;
CREATE TABLE exceptions (
    id TEXT PRIMARY KEY CHECK (length(id) = 32 AND id NOT GLOB '*[^0-9a-f]*'),
    project_id TEXT NOT NULL REFERENCES projects (id),
    -- NULL covers every principal with a role in the project.
    principal_id TEXT REFERENCES principals (id),
    profile_id TEXT NOT NULL,
    profile_revision INTEGER NOT NULL,
    profile_sha256 TEXT NOT NULL,
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('command', 'domain', 'network')),
    scope_value TEXT NOT NULL CHECK (
        length(scope_value) BETWEEN 1 AND 1024
        AND scope_value NOT GLOB '*[^ -~]*'
        AND scope_value = trim(scope_value)
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
CREATE INDEX exceptions_project ON exceptions (project_id, status);

-- Exceptions a session was admitted with. Every grant and request of the
-- session is denied once one of them expires or is revoked.
CREATE TABLE session_exceptions (
    session_id TEXT NOT NULL REFERENCES sessions (id),
    exception_id TEXT NOT NULL REFERENCES exceptions (id),
    PRIMARY KEY (session_id, exception_id)
) STRICT;
CREATE INDEX session_exceptions_exception ON session_exceptions (exception_id);

-- Audit events can name the exception they concern and carry a short,
-- non-secret detail such as `role=admin` or a scope.
ALTER TABLE audit_events ADD COLUMN exception_id TEXT CHECK (
    exception_id IS NULL OR (length(exception_id) = 32 AND exception_id NOT GLOB '*[^0-9a-f]*')
);
ALTER TABLE audit_events ADD COLUMN detail TEXT CHECK (
    detail IS NULL OR (length(detail) BETWEEN 1 AND 1100 AND detail NOT GLOB '*[^ -~]*')
);
CREATE INDEX audit_events_exception ON audit_events (exception_id, sequence);
