//! Process configuration, read once from the environment and validated at startup.

use std::ffi::OsString;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

use thiserror::Error;
use tracing_subscriber::EnvFilter;

pub const BIND_VAR: &str = "FLEET_BIND";
pub const DATABASE_URL_VAR: &str = "FLEET_DATABASE_URL";
pub const LOG_DIR_VAR: &str = "FLEET_LOG_DIR";
pub const LOG_LEVEL_VAR: &str = "FLEET_LOG_LEVEL";
pub const LOG_RETENTION_DAYS_VAR: &str = "FLEET_LOG_RETENTION_DAYS";

const DEFAULT_BIND: &str = "127.0.0.1:8080";
const DEFAULT_LOG_DIR: &str = "./logs";
const DEFAULT_LOG_LEVEL: &str = "info,sqlx=warn";
const DEFAULT_LOG_RETENTION_DAYS: u32 = 30;
const MAX_LOG_RETENTION_DAYS: u32 = 3650;

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub database_url: DatabaseUrl,
    pub logging: LogConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogConfig {
    /// Directory for `.log` files. Relative paths resolve against the process
    /// working directory at startup.
    pub dir: PathBuf,
    /// `tracing_subscriber::EnvFilter` directives, for example `info` or
    /// `fleet_server=debug,actix_web=info`.
    pub filter: String,
    pub retention_days: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseKind {
    Postgres,
    Sqlite,
}

impl DatabaseKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::Sqlite => "sqlite",
        }
    }
}

/// A database connection URL. Its `Debug` and `Display` forms never include
/// the credentials embedded in the URL.
#[derive(Clone, PartialEq, Eq)]
pub struct DatabaseUrl {
    kind: DatabaseKind,
    url: String,
}

impl DatabaseUrl {
    pub fn parse(url: &str) -> Result<Self, ConfigError> {
        let kind = if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            DatabaseKind::Postgres
        } else if url.starts_with("sqlite:") {
            DatabaseKind::Sqlite
        } else {
            return Err(ConfigError::Invalid {
                name: DATABASE_URL_VAR,
                reason: "must start with `postgres://`, `postgresql://`, or `sqlite:`".to_owned(),
            });
        };
        Ok(Self {
            kind,
            url: url.to_owned(),
        })
    }

    #[must_use]
    pub const fn kind(&self) -> DatabaseKind {
        self.kind
    }

    /// The full URL, including credentials. Never log this value.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.url
    }

    #[must_use]
    pub fn redacted(&self) -> String {
        let Some((scheme, rest)) = self.url.split_once("://") else {
            return self.url.clone();
        };
        let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
        match rest[..authority_end].rfind('@') {
            Some(at) => format!("{scheme}://***@{}", &rest[at + 1..]),
            None => self.url.clone(),
        }
    }
}

impl fmt::Debug for DatabaseUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("DatabaseUrl")
            .field(&self.redacted())
            .finish()
    }
}

impl fmt::Display for DatabaseUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.redacted())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error(
        "{name} is required, for example `sqlite://sendbox-fleet.db?mode=rwc` for local development or `postgres://user:password@host/sendbox_fleet` for a shared deployment"
    )]
    Missing { name: &'static str },
    #[error("{name} is invalid: {reason}")]
    Invalid { name: &'static str, reason: String },
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|name| std::env::var_os(name))
    }

    /// Builds a configuration from an arbitrary variable source so callers
    /// and tests do not depend on the process environment.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<OsString>) -> Result<Self, ConfigError> {
        let text = |name: &'static str| -> Result<Option<String>, ConfigError> {
            lookup(name)
                .map(|value| {
                    value.into_string().map_err(|_| ConfigError::Invalid {
                        name,
                        reason: "must be valid UTF-8".to_owned(),
                    })
                })
                .transpose()
        };

        let bind_text = text(BIND_VAR)?.unwrap_or_else(|| DEFAULT_BIND.to_owned());
        let bind = bind_text.parse().map_err(|_| ConfigError::Invalid {
            name: BIND_VAR,
            reason: format!("`{bind_text}` is not a socket address such as `127.0.0.1:8080`"),
        })?;

        let database_url = text(DATABASE_URL_VAR)?
            .filter(|value| !value.is_empty())
            .ok_or(ConfigError::Missing {
                name: DATABASE_URL_VAR,
            })?;
        let database_url = DatabaseUrl::parse(&database_url)?;

        let dir = lookup(LOG_DIR_VAR).map_or_else(|| PathBuf::from(DEFAULT_LOG_DIR), PathBuf::from);
        if dir.as_os_str().is_empty() {
            return Err(ConfigError::Invalid {
                name: LOG_DIR_VAR,
                reason: "must not be empty".to_owned(),
            });
        }

        let filter = text(LOG_LEVEL_VAR)?.unwrap_or_else(|| DEFAULT_LOG_LEVEL.to_owned());
        EnvFilter::try_new(&filter).map_err(|error| ConfigError::Invalid {
            name: LOG_LEVEL_VAR,
            reason: error.to_string(),
        })?;

        let retention_days = match text(LOG_RETENTION_DAYS_VAR)? {
            None => DEFAULT_LOG_RETENTION_DAYS,
            Some(value) => value
                .parse::<u32>()
                .ok()
                .filter(|days| (1..=MAX_LOG_RETENTION_DAYS).contains(days))
                .ok_or_else(|| ConfigError::Invalid {
                    name: LOG_RETENTION_DAYS_VAR,
                    reason: format!(
                        "must be a whole number of days in 1..={MAX_LOG_RETENTION_DAYS}"
                    ),
                })?,
        };

        Ok(Self {
            bind,
            database_url,
            logging: LogConfig {
                dir,
                filter,
                retention_days,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn config(vars: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let vars: HashMap<String, OsString> = vars
            .iter()
            .map(|(name, value)| ((*name).to_owned(), OsString::from(value)))
            .collect();
        Config::from_lookup(|name| vars.get(name).cloned())
    }

    #[test]
    fn defaults_apply_when_only_the_database_is_set() {
        let config = config(&[(DATABASE_URL_VAR, "sqlite::memory:")]).unwrap();
        assert_eq!(config.bind, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(config.database_url.kind(), DatabaseKind::Sqlite);
        assert_eq!(config.logging.dir, PathBuf::from("./logs"));
        assert_eq!(config.logging.retention_days, 30);
    }

    #[test]
    fn missing_or_unsupported_database_is_rejected() {
        assert_eq!(
            config(&[]).unwrap_err(),
            ConfigError::Missing {
                name: DATABASE_URL_VAR
            }
        );
        assert!(matches!(
            config(&[(DATABASE_URL_VAR, "mysql://db/fleet")]),
            Err(ConfigError::Invalid {
                name: DATABASE_URL_VAR,
                ..
            })
        ));
    }

    #[test]
    fn invalid_values_name_the_variable() {
        let base = (DATABASE_URL_VAR, "sqlite::memory:");
        for (name, value) in [
            (BIND_VAR, "localhost"),
            (LOG_DIR_VAR, ""),
            (LOG_LEVEL_VAR, "fleet_server=loud"),
            (LOG_RETENTION_DAYS_VAR, "0"),
            (LOG_RETENTION_DAYS_VAR, "thirty"),
        ] {
            match config(&[base, (name, value)]) {
                Err(ConfigError::Invalid { name: reported, .. }) => assert_eq!(reported, name),
                other => panic!("{name}={value:?} was accepted: {other:?}"),
            }
        }
    }

    #[test]
    fn database_credentials_are_redacted() {
        let url =
            DatabaseUrl::parse("postgres://fleet:hunter2@db:5432/fleet?sslmode=require").unwrap();
        assert_eq!(
            url.redacted(),
            "postgres://***@db:5432/fleet?sslmode=require"
        );
        assert!(!format!("{url:?} {url}").contains("hunter2"));
        let url = DatabaseUrl::parse("sqlite://data/fleet.db?mode=rwc").unwrap();
        assert_eq!(url.redacted(), "sqlite://data/fleet.db?mode=rwc");
    }
}
