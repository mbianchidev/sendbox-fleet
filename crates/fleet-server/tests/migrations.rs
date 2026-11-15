//! Migrations apply cleanly and the schema enforces its invariants.
//!
//! Runs against in-memory SQLite by default. Set `FLEET_TEST_DATABASE_URL` to
//! a PostgreSQL database whose name ends in `_test` to run the same checks
//! against PostgreSQL; its `public` schema is dropped and recreated by every
//! test, so run with `--test-threads=1`.

use fleet_server::config::{DatabaseKind, DatabaseUrl};
use fleet_server::db::Database;

const TABLES: [&str; 10] = [
    "principals",
    "projects",
    "role_bindings",
    "profiles",
    "profile_minimum_revisions",
    "sessions",
    "credential_grants",
    "revocations",
    "exceptions",
    "audit_events",
];
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const SESSION: &str = "0123456789abcdef0123456789abcdef";
const PROFILE_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const BINDING_SHA: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

async fn database() -> Database {
    let url =
        std::env::var("FLEET_TEST_DATABASE_URL").unwrap_or_else(|_| "sqlite::memory:".to_owned());
    let database = Database::connect(&DatabaseUrl::parse(&url).unwrap())
        .await
        .unwrap();
    if let Database::Postgres(pool) = &database {
        let name: String = sqlx::query_scalar("SELECT current_database()")
            .fetch_one(pool)
            .await
            .unwrap();
        assert!(
            name.ends_with("_test"),
            "refusing to reset database `{name}`: FLEET_TEST_DATABASE_URL must name a database ending in `_test`"
        );
        sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
            .execute(pool)
            .await
            .unwrap();
    }
    database.migrate().await.unwrap();
    database
}

async fn exec(database: &Database, sql: &str) -> Result<(), sqlx::Error> {
    match database {
        Database::Postgres(pool) => sqlx::raw_sql(sql).execute(pool).await.map(drop),
        Database::Sqlite(pool) => sqlx::raw_sql(sql).execute(pool).await.map(drop),
    }
}

async fn count(database: &Database, table: &str) -> i64 {
    let sql = format!("SELECT COUNT(*) FROM {table}");
    match database {
        Database::Postgres(pool) => sqlx::query_scalar::<_, i64>(&sql).fetch_one(pool).await,
        Database::Sqlite(pool) => sqlx::query_scalar::<_, i64>(&sql).fetch_one(pool).await,
    }
    .unwrap()
}

async fn accept(database: &Database, sql: &str) {
    if let Err(error) = exec(database, sql).await {
        panic!("rejected valid statement: {error}\n{sql}");
    }
}

async fn reject(database: &Database, sql: &str) {
    assert!(
        exec(database, sql).await.is_err(),
        "accepted invalid statement:\n{sql}"
    );
}

fn bytes_literal(database: &Database, hex: &str) -> String {
    match database.kind() {
        DatabaseKind::Postgres => format!("decode('{hex}', 'hex')"),
        DatabaseKind::Sqlite => format!("X'{hex}'"),
    }
}

/// Synthetic principals, a project, a profile revision, and an admitted session.
async fn seed(database: &Database) {
    for (id, kind) in [
        ("oidc:alice@example.com", "user"),
        ("oidc:bob@example.com", "user"),
        ("worker:host-1", "worker"),
    ] {
        accept(
            database,
            &format!("INSERT INTO principals (id, kind, created_at_unix) VALUES ('{id}', '{kind}', 1790000000)"),
        )
        .await;
    }
    accept(
        database,
        "INSERT INTO projects (id, created_at_unix) VALUES ('github:example/service', 1790000000)",
    )
    .await;
    accept(
        database,
        &format!(
            "INSERT INTO profiles (id, revision, sha256, signed_bytes, signatures, not_before_unix, \
             expires_at_unix, published_by, published_at_unix) VALUES ('example-default', 3, \
             '{PROFILE_SHA}', {}, '[{{\"key_id\":\"operator-2026\",\"signature\":\"c2ln\"}}]', \
             1790000000, 1800000000, 'oidc:bob@example.com', 1790000000)",
            bytes_literal(database, "69643a206578616d706c65")
        ),
    )
    .await;
    accept(
        database,
        &format!(
            "INSERT INTO sessions (id, principal_id, project_id, authority_id, profile_id, \
             profile_revision, profile_sha256, effective_policy_sha256, binding, binding_sha256, \
             status, admitted_by, admitted_at_unix) VALUES ('{SESSION}', 'oidc:alice@example.com', \
             'github:example/service', 'sendbox-fleet', 'example-default', 3, '{PROFILE_SHA}', \
             '{BINDING_SHA}', '{{\"contract_version\":1}}', '{BINDING_SHA}', 'admitted', \
             'worker:host-1', 1790000100)"
        ),
    )
    .await;
}

fn grant_sql(id: &str, principal: &str, issued: i64, max_expires: i64) -> String {
    format!(
        "INSERT INTO credential_grants (id, session_id, principal_id, project_id, binding_sha256, \
         profile_id, profile_revision, profile_sha256, service_id, methods, path_prefixes, \
         issued_at_unix, lease_expires_at_unix, max_expires_at_unix, generation) VALUES ('{id}', \
         '{SESSION}', '{principal}', 'github:example/service', '{BINDING_SHA}', 'example-default', \
         3, '{PROFILE_SHA}', 'anthropic', '[\"POST\"]', '[\"/v1/messages\"]', {issued}, {}, \
         {max_expires}, 1)",
        issued + 300
    )
}

fn audit_sql(sequence: i64, previous: &str, hash: &str) -> String {
    format!(
        "INSERT INTO audit_events (sequence, occurred_at_unix, recorded_at_unix, event_type, \
         project_id, decision, deny_reason, target_redacted, previous_hash, event_hash) VALUES \
         ({sequence}, 1790000200, 1790000200, 'grant.authorize', 'github:example/service', 'deny', \
         'stale_policy', 'POST api.anthropic.com /v1/messages', '{previous}', '{hash}')"
    )
}

#[actix_web::test]
async fn migrations_create_every_table_and_are_idempotent() {
    let database = database().await;
    database.migrate().await.unwrap();
    database.ping().await.unwrap();
    for table in TABLES {
        assert_eq!(count(&database, table).await, 0, "{table}");
    }
}

#[actix_web::test]
async fn audit_events_form_an_append_only_hash_chain() {
    let database = database().await;
    let first = "1".repeat(64);
    let second = "2".repeat(64);

    reject(&database, &audit_sql(1, &first, &first)).await;
    accept(&database, &audit_sql(1, ZERO_HASH, &first)).await;
    reject(&database, &audit_sql(2, ZERO_HASH, &second)).await;
    reject(&database, &audit_sql(3, &first, &second)).await;
    accept(&database, &audit_sql(2, &first, &second)).await;
    reject(
        &database,
        &audit_sql(3, &second, &"3".repeat(64)).replace("'stale_policy'", "NULL"),
    )
    .await;
    reject(
        &database,
        &audit_sql(3, &second, &"3".repeat(64)).replace("/v1/messages'", "/v1/messages?key=x'"),
    )
    .await;

    reject(
        &database,
        "UPDATE audit_events SET outcome = 'failed' WHERE sequence = 1",
    )
    .await;
    reject(&database, "DELETE FROM audit_events WHERE sequence = 2").await;
    assert_eq!(count(&database, "audit_events").await, 2);
}

#[actix_web::test]
async fn identities_are_bound_and_lifetimes_bounded() {
    let database = database().await;
    seed(&database).await;

    reject(
        &database,
        "INSERT INTO principals (id, kind, created_at_unix) VALUES ('local-user:501:alice', 'user', 0)",
    )
    .await;
    reject(
        &database,
        "INSERT INTO projects (id, created_at_unix) VALUES ('github:example/../etc', 0)",
    )
    .await;
    reject(
        &database,
        "INSERT INTO role_bindings (project_id, principal_id, role, granted_by, granted_at_unix) \
         VALUES ('github:example/service', 'oidc:alice@example.com', 'superuser', 'oidc:bob@example.com', 0)",
    )
    .await;

    let grant = "fedcba9876543210fedcba9876543210";
    reject(
        &database,
        &grant_sql(grant, "oidc:bob@example.com", 1790000200, 1790003800),
    )
    .await;
    reject(
        &database,
        &grant_sql(
            grant,
            "oidc:alice@example.com",
            1790000200,
            1790000200 + 604801,
        ),
    )
    .await;
    accept(
        &database,
        &grant_sql(grant, "oidc:alice@example.com", 1790000200, 1790003800),
    )
    .await;

    let revocation = |grace: i64| {
        format!(
            "INSERT INTO revocations (grant_id, reason, revoked_at_unix, grace_expires_at_unix, generation) \
             VALUES ('{grant}', 'session_completed', 1790000300, {}, 2)",
            1790000300 + grace
        )
    };
    reject(&database, &revocation(61)).await;
    accept(&database, &revocation(5)).await;

    let exception = |decided_by: &str, expires: i64| {
        format!(
            "INSERT INTO exceptions (id, project_id, profile_id, profile_revision, profile_sha256, \
             scope_kind, scope_value, reason, status, requested_by, requested_at_unix, decided_by, \
             decided_at_unix, expires_at_unix) VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', \
             'github:example/service', 'example-default', 3, '{PROFILE_SHA}', 'network_domain', \
             'registry.example.com', 'Package mirror outage', 'approved', 'oidc:alice@example.com', \
             1790000000, '{decided_by}', 1790000100, {expires})"
        )
    };
    reject(&database, &exception("oidc:alice@example.com", 1790086400)).await;
    reject(
        &database,
        &exception("oidc:bob@example.com", 1790000000 + 604801),
    )
    .await;
    accept(&database, &exception("oidc:bob@example.com", 1790086400)).await;
}
