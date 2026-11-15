//! Application assembly and the process lifecycle.

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use actix_web::body::MessageBody;
use actix_web::dev::{ServiceFactory, ServiceRequest, ServiceResponse};
use actix_web::middleware::from_fn;
use actix_web::{App, HttpServer, web};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::task::JoinHandle;

use crate::auth::{self, FleetAuthenticator, SharedAuthenticator};
use crate::config::{Config, ConfigError, ProfileTrust};
use crate::db::{Database, DbError};
use crate::logging::{self, retention};
use crate::oidc::{OidcConfig, OidcVerifier};
use crate::problem;
use crate::routes;
use crate::state::{AppState, os_random};

/// Time in-flight requests get to finish after SIGINT or SIGTERM.
const SHUTDOWN_GRACE_SECONDS: u64 = 30;
const RETENTION_INTERVAL: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Error)]
pub enum ServerError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Anchor(#[from] crate::anchor::AnchorError),
    #[error(transparent)]
    Database(#[from] DbError),
    #[error("cannot listen on {address}: {source}")]
    Bind {
        address: SocketAddr,
        source: io::Error,
    },
    #[error("HTTP server failed: {0}")]
    Serve(io::Error),
}

/// Builds the application. Shared by the server and the HTTP tests.
pub fn app(
    state: web::Data<AppState>,
    authenticator: SharedAuthenticator,
) -> App<
    impl ServiceFactory<
        ServiceRequest,
        Config = (),
        Response = ServiceResponse<impl MessageBody>,
        Error = actix_web::Error,
        InitError = (),
    >,
> {
    App::new()
        .app_data(web::Data::new(state.database.clone()))
        .app_data(state)
        .app_data(authenticator)
        .wrap(from_fn(logging::request_log))
        .configure(routes::configure)
        .default_service(web::to(problem::not_found))
}

/// Connects and migrates the database, then serves until SIGINT or SIGTERM.
pub async fn run(config: Config, log_dir: PathBuf) -> Result<(), ServerError> {
    let profile_trust = config
        .profile_trust
        .as_deref()
        .map(ProfileTrust::load)
        .transpose()?;
    let audit_signer = config
        .audit
        .signing_key
        .as_deref()
        .map(crate::anchor::AuditSigner::load)
        .transpose()?
        .map(Arc::new);
    if let Some(directory) = &config.audit.directory {
        std::fs::create_dir_all(directory).map_err(|source| crate::anchor::AnchorError::Io {
            context: "create audit anchor directory",
            path: directory.clone(),
            source,
        })?;
    }
    let retention = spawn_retention(log_dir.clone(), config.logging.retention_days);
    let database = Database::connect(&config.database_url).await?;
    if config.migrate {
        database.migrate().await?;
    } else {
        database.check_migrated().await?;
    }
    match database
        .fetch_optional("SELECT MAX(sequence) AS head FROM audit_events", &[])
        .await
    {
        Ok(Some(row)) => {
            if let Ok(Some(head)) = row.opt_int("head") {
                crate::metrics::METRICS.audit_head(u64::try_from(head).unwrap_or(0));
            }
        }
        Ok(None) => {}
        Err(error) => tracing::warn!(%error, "cannot read the audit chain head for metrics"),
    }
    tracing::info!(
        bind = %config.bind,
        database = %config.database_url,
        log_dir = %log_dir.display(),
        authority_id = %config.authority_id,
        contract_version = crate::CONTRACT_VERSION,
        "sendbox-fleet starting"
    );
    if profile_trust.is_none() {
        tracing::warn!(
            "FLEET_PROFILE_TRUST is not set; profile publication is refused until it is configured"
        );
    }

    let clock: Arc<dyn sendbox_governance::Clock> = Arc::new(sendbox_governance::SystemClock);
    let oidc = config
        .oidc
        .as_deref()
        .map(OidcConfig::load)
        .transpose()?
        .map(|oidc| OidcVerifier::new(oidc, Arc::clone(&clock)))
        .transpose()?;
    if oidc.is_none() {
        tracing::info!("FLEET_OIDC_CONFIG is not set; only service tokens authenticate");
    }
    let state = web::Data::new(AppState {
        database: database.clone(),
        clock: Arc::clone(&clock),
        random: Arc::new(os_random),
        authority_id: config.authority_id.clone(),
        profile_trust,
        tokens: config.tokens,
        audit_signer: audit_signer.clone(),
        limits: Arc::new(crate::ratelimit::Limits {
            requests: crate::ratelimit::RateLimiter::new(config.rate_limit_per_minute),
            auth_failures: crate::ratelimit::RateLimiter::new(config.auth_failures_per_minute),
        }),
    });
    let metrics = match config.metrics_bind {
        Some(address) => {
            let server = HttpServer::new(|| App::new().configure(crate::metrics::configure))
                .workers(1)
                .shutdown_timeout(5)
                .bind(address)
                .map_err(|source| ServerError::Bind { address, source })?
                .run();
            let handle = server.handle();
            actix_web::rt::spawn(server);
            tracing::info!(%address, "serving metrics");
            Some(handle)
        }
        None => None,
    };
    let anchoring = match (&audit_signer, &config.audit.directory) {
        (Some(signer), Some(directory)) => {
            tracing::info!(
                directory = %directory.display(),
                fingerprint = %signer.identity.fingerprint,
                "anchoring the audit chain head"
            );
            Some(crate::anchor::spawn_anchoring(
                database.clone(),
                Arc::clone(signer),
                config.authority_id.clone(),
                directory.clone(),
                Duration::from_secs(config.audit.interval_seconds),
                Arc::clone(&clock),
            ))
        }
        _ => None,
    };
    let authenticator = auth::shared(Arc::new(FleetAuthenticator::new(
        database.clone(),
        clock,
        oidc,
    )));
    let server = HttpServer::new(move || app(state.clone(), authenticator.clone()))
        .shutdown_timeout(SHUTDOWN_GRACE_SECONDS)
        .bind(config.bind)
        .map_err(|source| ServerError::Bind {
            address: config.bind,
            source,
        })?
        .run();
    let served = server.await.map_err(ServerError::Serve);

    if let Some(metrics) = metrics {
        metrics.stop(true).await;
    }
    retention.abort();
    if let Some(anchoring) = anchoring {
        anchoring.abort();
    }
    database.close().await;
    tracing::info!("sendbox-fleet stopped");
    served
}

/// Applies log retention now and then hourly while the server runs.
fn spawn_retention(dir: PathBuf, retention_days: u32) -> JoinHandle<()> {
    actix_web::rt::spawn(async move {
        let mut interval = tokio::time::interval(RETENTION_INTERVAL);
        loop {
            interval.tick().await;
            let dir = dir.clone();
            let outcome = tokio::task::spawn_blocking(move || {
                retention::enforce(&dir, retention_days, OffsetDateTime::now_utc())
            })
            .await;
            match outcome {
                Ok(Ok(report)) => {
                    for path in &report.deleted {
                        tracing::info!(path = %path.display(), "deleted expired log file");
                    }
                    for (path, error) in &report.failures {
                        tracing::warn!(path = %path.display(), %error, "cannot delete expired log file");
                    }
                }
                Ok(Err(error)) => {
                    tracing::warn!(%error, "cannot list the log directory for retention")
                }
                Err(error) => tracing::warn!(%error, "log retention task failed"),
            }
        }
    })
}
