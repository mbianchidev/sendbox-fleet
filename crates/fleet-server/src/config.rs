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
pub const LOG_MAX_BYTES_VAR: &str = "FLEET_LOG_MAX_BYTES";
pub const AUTHORITY_ID_VAR: &str = "FLEET_AUTHORITY_ID";
pub const PROFILE_TRUST_VAR: &str = "FLEET_PROFILE_TRUST";
pub const OIDC_CONFIG_VAR: &str = "FLEET_OIDC_CONFIG";
pub const TOKEN_TTL_VAR: &str = "FLEET_TOKEN_TTL_SECONDS";
pub const TOKEN_MAX_TTL_VAR: &str = "FLEET_TOKEN_MAX_TTL_SECONDS";
pub const AUDIT_SIGNING_KEY_VAR: &str = "FLEET_AUDIT_SIGNING_KEY";
pub const RATE_LIMIT_VAR: &str = "FLEET_RATE_LIMIT_PER_MINUTE";
pub const AUTH_FAILURES_VAR: &str = "FLEET_AUTH_FAILURES_PER_MINUTE";
pub const METRICS_BIND_VAR: &str = "FLEET_METRICS_BIND";
pub const MIGRATE_VAR: &str = "FLEET_MIGRATE";
pub const AUDIT_ANCHOR_DIR_VAR: &str = "FLEET_AUDIT_ANCHOR_DIR";
pub const AUDIT_ANCHOR_INTERVAL_VAR: &str = "FLEET_AUDIT_ANCHOR_INTERVAL_SECONDS";

const DEFAULT_BIND: &str = "127.0.0.1:8080";
const DEFAULT_LOG_DIR: &str = "./logs";
const DEFAULT_LOG_LEVEL: &str = "info,sqlx=warn";
const DEFAULT_LOG_RETENTION_DAYS: u32 = 30;
const MAX_LOG_RETENTION_DAYS: u32 = 3650;
const DEFAULT_LOG_MAX_BYTES: u64 = 100 * 1024 * 1024;
const LOG_MAX_BYTES_RANGE: std::ops::RangeInclusive<u64> =
    (1024 * 1024)..=(10 * 1024 * 1024 * 1024);
const DEFAULT_AUTHORITY_ID: &str = "sendbox-fleet";
const DEFAULT_TOKEN_TTL_SECONDS: u64 = 12 * 60 * 60;
const DEFAULT_TOKEN_MAX_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
/// Matches the `api_tokens` lifetime bound in the schema.
pub const HARD_MAX_TOKEN_TTL_SECONDS: u64 = 90 * 24 * 60 * 60;
const MAX_TRUST_BYTES: u64 = 256 * 1024;
const MAX_TRUSTED_SIGNERS: usize = 32;

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub database_url: DatabaseUrl,
    pub logging: LogConfig,
    /// The `authority` id hosts put in their operator configuration and bind
    /// into every session.
    pub authority_id: String,
    /// File listing the operator signers that published profiles must satisfy.
    pub profile_trust: Option<PathBuf>,
    /// File listing trusted OIDC issuers.
    pub oidc: Option<PathBuf>,
    pub tokens: TokenLimits,
    pub audit: AuditAnchoring,
    /// `/v1` requests per principal per minute; `0` disables.
    pub rate_limit_per_minute: u32,
    /// Failed authentications per peer address per minute; `0` disables.
    pub auth_failures_per_minute: u32,
    /// Separate listener for `/metrics`; `None` disables metrics.
    pub metrics_bind: Option<SocketAddr>,
    /// Apply migrations at startup. When false, startup fails unless every
    /// migration was already applied (`sendbox-fleet admin migrate`).
    pub migrate: bool,
}

/// Signing and external anchoring of the audit chain head.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuditAnchoring {
    pub signing_key: Option<PathBuf>,
    pub directory: Option<PathBuf>,
    pub interval_seconds: u64,
}

/// Lifetimes of service tokens exchanged at `POST /v1/tokens`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenLimits {
    pub default_seconds: u64,
    pub max_seconds: u64,
}

impl Default for TokenLimits {
    fn default() -> Self {
        Self {
            default_seconds: DEFAULT_TOKEN_TTL_SECONDS,
            max_seconds: DEFAULT_TOKEN_MAX_TTL_SECONDS,
        }
    }
}

/// The signer set and threshold for profile publication. Same shape as the
/// `trust` section of a host's operator configuration.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileTrust {
    pub threshold: usize,
    pub signers: Vec<sendbox_security::provenance::Identity>,
}

impl ProfileTrust {
    /// Reads and validates the trust file, returning a store that requires
    /// `threshold` distinct, valid signers and never accepts unsigned input.
    pub fn load(
        path: &std::path::Path,
    ) -> Result<sendbox_security::provenance::TrustStore, ConfigError> {
        use std::io::Read as _;
        let invalid = |reason: String| ConfigError::Invalid {
            name: PROFILE_TRUST_VAR,
            reason,
        };
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .and_then(|file| file.take(MAX_TRUST_BYTES + 1).read_to_end(&mut bytes))
            .map_err(|error| invalid(format!("cannot read {}: {error}", path.display())))?;
        if bytes.len() as u64 > MAX_TRUST_BYTES {
            return Err(invalid(format!(
                "{} exceeds {MAX_TRUST_BYTES} bytes",
                path.display()
            )));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| invalid("must be UTF-8".to_owned()))?;
        let trust: Self =
            serde_yaml_ng::from_str(text).map_err(|error| invalid(error.to_string()))?;
        let fingerprints = trust
            .signers
            .iter()
            .map(|signer| signer.fingerprint.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if trust.signers.is_empty()
            || trust.signers.len() > MAX_TRUSTED_SIGNERS
            || fingerprints.len() != trust.signers.len()
        {
            return Err(invalid(format!(
                "signers must list 1 to {MAX_TRUSTED_SIGNERS} distinct identities"
            )));
        }
        if trust.threshold == 0 || trust.threshold > trust.signers.len() {
            return Err(invalid(
                "threshold must be between 1 and the number of signers".to_owned(),
            ));
        }
        let mut store = sendbox_security::provenance::TrustStore::new(
            sendbox_security::provenance::TrustPolicy {
                allow_unsigned: false,
                threshold: trust.threshold,
                required_signers: std::collections::BTreeSet::new(),
            },
        );
        for signer in trust.signers {
            store
                .add_identity(signer)
                .map_err(|error| invalid(format!("signer: {error}")))?;
        }
        Ok(store)
    }
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
    /// Size at which the current day's file continues in a new part.
    pub max_file_bytes: u64,
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

/// `FLEET_MIGRATE`: unset or `true` applies migrations at startup.
pub fn parse_migrate(value: Option<&str>) -> Result<bool, ConfigError> {
    match value {
        None | Some("true") => Ok(true),
        Some("false") => Ok(false),
        Some(_) => Err(ConfigError::Invalid {
            name: MIGRATE_VAR,
            reason: "must be `true` or `false`".to_owned(),
        }),
    }
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

        let authority_id =
            text(AUTHORITY_ID_VAR)?.unwrap_or_else(|| DEFAULT_AUTHORITY_ID.to_owned());
        if authority_id.is_empty()
            || authority_id.len() > 128
            || authority_id == "local"
            || !authority_id.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(ConfigError::Invalid {
                name: AUTHORITY_ID_VAR,
                reason: "must be 1 to 128 printable ASCII bytes and not `local`".to_owned(),
            });
        }
        let profile_trust = lookup(PROFILE_TRUST_VAR)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        let oidc = lookup(OIDC_CONFIG_VAR)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        let seconds = |name: &'static str, default: u64| -> Result<u64, ConfigError> {
            match text(name)? {
                None => Ok(default),
                Some(value) => value
                    .parse::<u64>()
                    .ok()
                    .filter(|seconds| (60..=HARD_MAX_TOKEN_TTL_SECONDS).contains(seconds))
                    .ok_or_else(|| ConfigError::Invalid {
                        name,
                        reason: format!(
                            "must be a whole number of seconds in 60..={HARD_MAX_TOKEN_TTL_SECONDS}"
                        ),
                    }),
            }
        };
        let audit = AuditAnchoring {
            signing_key: lookup(AUDIT_SIGNING_KEY_VAR)
                .filter(|value| !value.is_empty())
                .map(PathBuf::from),
            directory: lookup(AUDIT_ANCHOR_DIR_VAR)
                .filter(|value| !value.is_empty())
                .map(PathBuf::from),
            interval_seconds: match text(AUDIT_ANCHOR_INTERVAL_VAR)? {
                None => 3600,
                Some(value) => value
                    .parse::<u64>()
                    .ok()
                    .filter(|seconds| (60..=86_400).contains(seconds))
                    .ok_or_else(|| ConfigError::Invalid {
                        name: AUDIT_ANCHOR_INTERVAL_VAR,
                        reason: "must be a whole number of seconds in 60..=86400".to_owned(),
                    })?,
            },
        };
        if audit.directory.is_some() && audit.signing_key.is_none() {
            return Err(ConfigError::Invalid {
                name: AUDIT_ANCHOR_DIR_VAR,
                reason: format!("needs {AUDIT_SIGNING_KEY_VAR}"),
            });
        }
        let per_minute = |name: &'static str, default: u32| -> Result<u32, ConfigError> {
            match text(name)? {
                None => Ok(default),
                Some(value) => value
                    .parse::<u32>()
                    .ok()
                    .filter(|value| *value <= 1_000_000)
                    .ok_or_else(|| ConfigError::Invalid {
                        name,
                        reason: "must be a whole number in 0..=1000000 (0 disables)".to_owned(),
                    }),
            }
        };
        let rate_limit_per_minute = per_minute(RATE_LIMIT_VAR, 1200)?;
        let auth_failures_per_minute = per_minute(AUTH_FAILURES_VAR, 60)?;
        let metrics_bind = text(METRICS_BIND_VAR)?
            .filter(|value| !value.is_empty())
            .map(|value| {
                value.parse().map_err(|_| ConfigError::Invalid {
                    name: METRICS_BIND_VAR,
                    reason: format!("`{value}` is not a socket address such as `127.0.0.1:9090`"),
                })
            })
            .transpose()?;
        if metrics_bind.is_some_and(|address| address == bind) {
            return Err(ConfigError::Invalid {
                name: METRICS_BIND_VAR,
                reason: format!("must differ from {BIND_VAR}"),
            });
        }
        let migrate = parse_migrate(text(MIGRATE_VAR)?.as_deref())?;
        let tokens = TokenLimits {
            default_seconds: seconds(TOKEN_TTL_VAR, DEFAULT_TOKEN_TTL_SECONDS)?,
            max_seconds: seconds(TOKEN_MAX_TTL_VAR, DEFAULT_TOKEN_MAX_TTL_SECONDS)?,
        };
        if tokens.default_seconds > tokens.max_seconds {
            return Err(ConfigError::Invalid {
                name: TOKEN_TTL_VAR,
                reason: format!("must not exceed {TOKEN_MAX_TTL_VAR}"),
            });
        }

        let max_file_bytes = match text(LOG_MAX_BYTES_VAR)? {
            None => DEFAULT_LOG_MAX_BYTES,
            Some(value) => value
                .parse::<u64>()
                .ok()
                .filter(|bytes| LOG_MAX_BYTES_RANGE.contains(bytes))
                .ok_or_else(|| ConfigError::Invalid {
                    name: LOG_MAX_BYTES_VAR,
                    reason: format!(
                        "must be a whole number of bytes in {}..={}",
                        LOG_MAX_BYTES_RANGE.start(),
                        LOG_MAX_BYTES_RANGE.end()
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
                max_file_bytes,
            },
            authority_id,
            profile_trust,
            oidc,
            tokens,
            audit,
            rate_limit_per_minute,
            auth_failures_per_minute,
            metrics_bind,
            migrate,
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
        assert_eq!(config.authority_id, "sendbox-fleet");
        assert!(config.profile_trust.is_none());
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
            (AUTHORITY_ID_VAR, "local"),
            (AUTHORITY_ID_VAR, "has space"),
            (TOKEN_TTL_VAR, "59"),
            (TOKEN_MAX_TTL_VAR, "7776001"),
            (TOKEN_TTL_VAR, "700000"),
            (RATE_LIMIT_VAR, "-1"),
            (METRICS_BIND_VAR, "127.0.0.1:8080"),
            (MIGRATE_VAR, "yes"),
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
