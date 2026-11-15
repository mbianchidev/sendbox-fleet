//! Database connection, migrations, and readiness checks.
//!
//! PostgreSQL is the shared deployment target; SQLite serves local
//! development and tests. Each backend has its own migration set under
//! `migrations/` with the same tables and constraints.

use std::str::FromStr;
use std::time::Duration;

use sqlx::migrate::{MigrateError, Migrator};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{PgPool, SqlitePool};
use thiserror::Error;

use crate::config::{DatabaseKind, DatabaseUrl};

static POSTGRES_MIGRATIONS: Migrator = sqlx::migrate!("../../migrations/postgres");
static SQLITE_MIGRATIONS: Migrator = sqlx::migrate!("../../migrations/sqlite");

const MAX_CONNECTIONS: u32 = 16;
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

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
}
