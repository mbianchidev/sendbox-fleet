//! Database connection, migrations, and readiness checks.
//!
//! PostgreSQL is the shared deployment target; SQLite serves local
//! development and tests. Each backend has its own migration set under
//! `migrations/` with the same tables and constraints.

use std::str::FromStr;
use std::time::Duration;

use sqlx::migrate::{MigrateError, Migrator};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgRow};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow};
use sqlx::{PgPool, Postgres, Row as _, Sqlite, SqlitePool, Transaction};
use thiserror::Error;

use crate::config::{DatabaseKind, DatabaseUrl};

static POSTGRES_MIGRATIONS: Migrator = sqlx::migrate!("../../migrations/postgres");
static SQLITE_MIGRATIONS: Migrator = sqlx::migrate!("../../migrations/sqlite");

const MAX_CONNECTIONS: u32 = 16;
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);
/// Transaction-scoped PostgreSQL advisory lock that serializes writers, so
/// check-then-write decisions and the audit hash chain never race.
const WRITE_LOCK_KEY: i64 = 0x5345_4e44_424f_5846;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("invalid database URL {url}: {source}")]
    Options { url: String, source: sqlx::Error },
    #[error("cannot connect to {url}: {source}")]
    Connect { url: String, source: sqlx::Error },
    #[error("database migration failed: {0}")]
    Migrate(#[from] MigrateError),
    #[error("database query failed: {0}")]
    Query(#[from] sqlx::Error),
}

#[derive(Debug, Clone)]
pub enum Database {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

impl Database {
    /// Opens a bounded connection pool and establishes one connection
    /// immediately, so a bad URL or unreachable server fails at startup.
    pub async fn connect(url: &DatabaseUrl) -> Result<Self, DbError> {
        let redacted = url.redacted();
        match url.kind() {
            DatabaseKind::Postgres => {
                let options = PgConnectOptions::from_str(url.expose()).map_err(|source| {
                    DbError::Options {
                        url: redacted.clone(),
                        source,
                    }
                })?;
                PgPoolOptions::new()
                    .max_connections(MAX_CONNECTIONS)
                    .acquire_timeout(ACQUIRE_TIMEOUT)
                    .connect_with(options)
                    .await
                    .map(Self::Postgres)
                    .map_err(|source| DbError::Connect {
                        url: redacted,
                        source,
                    })
            }
            DatabaseKind::Sqlite => {
                let in_memory =
                    url.expose().contains(":memory:") || url.expose().contains("mode=memory");
                let options = SqliteConnectOptions::from_str(url.expose())
                    .map_err(|source| DbError::Options {
                        url: redacted.clone(),
                        source,
                    })?
                    .foreign_keys(true)
                    .busy_timeout(ACQUIRE_TIMEOUT)
                    .journal_mode(if in_memory {
                        SqliteJournalMode::Memory
                    } else {
                        SqliteJournalMode::Wal
                    });
                // Every in-memory connection is a separate database, so the
                // pool keeps exactly one connection alive for its lifetime.
                let pool = if in_memory {
                    SqlitePoolOptions::new()
                        .max_connections(1)
                        .min_connections(1)
                        .idle_timeout(None)
                        .max_lifetime(None)
                } else {
                    SqlitePoolOptions::new().max_connections(MAX_CONNECTIONS)
                };
                pool.acquire_timeout(ACQUIRE_TIMEOUT)
                    .connect_with(options)
                    .await
                    .map(Self::Sqlite)
                    .map_err(|source| DbError::Connect {
                        url: redacted,
                        source,
                    })
            }
        }
    }

    #[must_use]
    pub const fn kind(&self) -> DatabaseKind {
        match self {
            Self::Postgres(_) => DatabaseKind::Postgres,
            Self::Sqlite(_) => DatabaseKind::Sqlite,
        }
    }

    /// Applies pending migrations for this backend.
    pub async fn migrate(&self) -> Result<(), DbError> {
        match self {
            Self::Postgres(pool) => POSTGRES_MIGRATIONS.run(pool).await?,
            Self::Sqlite(pool) => SQLITE_MIGRATIONS.run(pool).await?,
        }
        Ok(())
    }

    /// Round-trips a trivial query; used by the readiness probe.
    pub async fn ping(&self) -> Result<(), DbError> {
        match self {
            Self::Postgres(pool) => {
                sqlx::query("SELECT 1").execute(pool).await?;
            }
            Self::Sqlite(pool) => {
                sqlx::query("SELECT 1").execute(pool).await?;
            }
        }
        Ok(())
    }

    pub async fn close(&self) {
        match self {
            Self::Postgres(pool) => pool.close().await,
            Self::Sqlite(pool) => pool.close().await,
        }
    }

    /// Starts a write transaction. Writers are serialized: SQLite takes the
    /// write lock up front (`BEGIN IMMEDIATE`) and PostgreSQL takes a
    /// transaction-scoped advisory lock.
    pub async fn begin_write(&self) -> Result<Tx, DbError> {
        match self {
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                sqlx::query("SELECT pg_advisory_xact_lock($1)")
                    .bind(WRITE_LOCK_KEY)
                    .execute(&mut *transaction)
                    .await?;
                Ok(Tx::Postgres(transaction))
            }
            Self::Sqlite(pool) => Ok(Tx::Sqlite(pool.begin_with("BEGIN IMMEDIATE").await?)),
        }
    }

    /// Runs a read-only query outside a transaction.
    pub async fn fetch_all(&self, sql: &str, args: &[Arg]) -> Result<Vec<Row>, DbError> {
        match self {
            Self::Postgres(pool) => Ok(bind_pg(sqlx::query(sql), args)
                .fetch_all(pool)
                .await?
                .into_iter()
                .map(Row::Postgres)
                .collect()),
            Self::Sqlite(pool) => Ok(bind_sqlite(sqlx::query(sql), args)
                .fetch_all(pool)
                .await?
                .into_iter()
                .map(Row::Sqlite)
                .collect()),
        }
    }

    pub async fn fetch_optional(&self, sql: &str, args: &[Arg]) -> Result<Option<Row>, DbError> {
        Ok(self.fetch_all(sql, args).await?.into_iter().next())
    }

    /// `CAST($n AS JSON)` on PostgreSQL, `$n` on SQLite, for binding JSON text.
    #[must_use]
    pub fn json_param(&self, index: usize, binary: bool) -> String {
        json_param(self.kind(), index, binary)
    }
}

fn json_param(kind: DatabaseKind, index: usize, binary: bool) -> String {
    match (kind, binary) {
        (DatabaseKind::Postgres, true) => format!("CAST(${index} AS JSONB)"),
        (DatabaseKind::Postgres, false) => format!("CAST(${index} AS JSON)"),
        (DatabaseKind::Sqlite, _) => format!("${index}"),
    }
}

/// A bound query parameter. SQL uses `$1`, `$2`, ... on both backends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arg {
    Text(Option<String>),
    Int(Option<i64>),
    Bytes(Vec<u8>),
    Bool(bool),
}

impl From<&str> for Arg {
    fn from(value: &str) -> Self {
        Self::Text(Some(value.to_owned()))
    }
}

impl From<String> for Arg {
    fn from(value: String) -> Self {
        Self::Text(Some(value))
    }
}

impl From<Option<String>> for Arg {
    fn from(value: Option<String>) -> Self {
        Self::Text(value)
    }
}

impl From<i64> for Arg {
    fn from(value: i64) -> Self {
        Self::Int(Some(value))
    }
}

impl From<Option<i64>> for Arg {
    fn from(value: Option<i64>) -> Self {
        Self::Int(value)
    }
}

impl From<bool> for Arg {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<Vec<u8>> for Arg {
    fn from(value: Vec<u8>) -> Self {
        Self::Bytes(value)
    }
}

type PgQuery<'q> = sqlx::query::Query<'q, Postgres, sqlx::postgres::PgArguments>;
type SqliteQuery<'q> = sqlx::query::Query<'q, Sqlite, sqlx::sqlite::SqliteArguments<'q>>;

fn bind_pg<'q>(mut query: PgQuery<'q>, args: &'q [Arg]) -> PgQuery<'q> {
    for arg in args {
        query = match arg {
            Arg::Text(value) => query.bind(value.as_deref()),
            Arg::Int(value) => query.bind(*value),
            Arg::Bytes(value) => query.bind(value.as_slice()),
            Arg::Bool(value) => query.bind(*value),
        };
    }
    query
}

fn bind_sqlite<'q>(mut query: SqliteQuery<'q>, args: &'q [Arg]) -> SqliteQuery<'q> {
    for arg in args {
        query = match arg {
            Arg::Text(value) => query.bind(value.as_deref()),
            Arg::Int(value) => query.bind(*value),
            Arg::Bytes(value) => query.bind(value.as_slice()),
            Arg::Bool(value) => query.bind(*value),
        };
    }
    query
}

/// A write transaction. Dropping it without [`Tx::commit`] rolls back.
pub enum Tx {
    Postgres(Transaction<'static, Postgres>),
    Sqlite(Transaction<'static, Sqlite>),
}

impl Tx {
    #[must_use]
    pub const fn kind(&self) -> DatabaseKind {
        match self {
            Self::Postgres(_) => DatabaseKind::Postgres,
            Self::Sqlite(_) => DatabaseKind::Sqlite,
        }
    }

    #[must_use]
    pub fn json_param(&self, index: usize, binary: bool) -> String {
        json_param(self.kind(), index, binary)
    }

    /// Executes a statement and returns the number of affected rows.
    pub async fn execute(&mut self, sql: &str, args: &[Arg]) -> Result<u64, DbError> {
        Ok(match self {
            Self::Postgres(transaction) => bind_pg(sqlx::query(sql), args)
                .execute(&mut **transaction)
                .await?
                .rows_affected(),
            Self::Sqlite(transaction) => bind_sqlite(sqlx::query(sql), args)
                .execute(&mut **transaction)
                .await?
                .rows_affected(),
        })
    }

    pub async fn fetch_all(&mut self, sql: &str, args: &[Arg]) -> Result<Vec<Row>, DbError> {
        Ok(match self {
            Self::Postgres(transaction) => bind_pg(sqlx::query(sql), args)
                .fetch_all(&mut **transaction)
                .await?
                .into_iter()
                .map(Row::Postgres)
                .collect(),
            Self::Sqlite(transaction) => bind_sqlite(sqlx::query(sql), args)
                .fetch_all(&mut **transaction)
                .await?
                .into_iter()
                .map(Row::Sqlite)
                .collect(),
        })
    }

    pub async fn fetch_optional(
        &mut self,
        sql: &str,
        args: &[Arg],
    ) -> Result<Option<Row>, DbError> {
        Ok(self.fetch_all(sql, args).await?.into_iter().next())
    }

    pub async fn commit(self) -> Result<(), DbError> {
        match self {
            Self::Postgres(transaction) => transaction.commit().await?,
            Self::Sqlite(transaction) => transaction.commit().await?,
        }
        Ok(())
    }
}

/// A result row with typed, backend-neutral accessors.
pub enum Row {
    Postgres(PgRow),
    Sqlite(SqliteRow),
}

macro_rules! row_get {
    ($row:expr, $column:expr, $kind:ty) => {
        match $row {
            Row::Postgres(row) => row.try_get::<$kind, _>($column),
            Row::Sqlite(row) => row.try_get::<$kind, _>($column),
        }
        .map_err(DbError::from)
    };
}

impl Row {
    pub fn text(&self, column: &str) -> Result<String, DbError> {
        row_get!(self, column, String)
    }

    pub fn opt_text(&self, column: &str) -> Result<Option<String>, DbError> {
        row_get!(self, column, Option<String>)
    }

    pub fn int(&self, column: &str) -> Result<i64, DbError> {
        row_get!(self, column, i64)
    }

    pub fn opt_int(&self, column: &str) -> Result<Option<i64>, DbError> {
        row_get!(self, column, Option<i64>)
    }

    pub fn bytes(&self, column: &str) -> Result<Vec<u8>, DbError> {
        row_get!(self, column, Vec<u8>)
    }

    pub fn flag(&self, column: &str) -> Result<bool, DbError> {
        row_get!(self, column, bool)
    }
}
