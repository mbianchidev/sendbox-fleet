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

use crate::auth::{self, SharedAuthenticator, UnconfiguredAuthenticator};
use crate::config::Config;
use crate::db::{Database, DbError};
use crate::logging::{self, retention};
use crate::problem;
use crate::routes;

/// Time in-flight requests get to finish after SIGINT or SIGTERM.
const SHUTDOWN_GRACE_SECONDS: u64 = 30;
const RETENTION_INTERVAL: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Error)]
pub enum ServerError {
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
    database: web::Data<Database>,
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
        .app_data(database)
        .app_data(authenticator)
        .wrap(from_fn(logging::request_log))
        .configure(routes::configure)
        .default_service(web::to(problem::not_found))
}

/// Connects and migrates the database, then serves until SIGINT or SIGTERM.
pub async fn run(config: Config, log_dir: PathBuf) -> Result<(), ServerError> {
    let retention = spawn_retention(log_dir.clone(), config.logging.retention_days);
    let database = Database::connect(&config.database_url).await?;
    database.migrate().await?;
    tracing::info!(
        bind = %config.bind,
        database = %config.database_url,
        log_dir = %log_dir.display(),
        contract_version = crate::CONTRACT_VERSION,
        "sendbox-fleet starting"
    );
    tracing::warn!(
        "no authentication provider is configured; every /v1 request is rejected with 401"
    );

    let data = web::Data::new(database.clone());
    let authenticator = auth::shared(Arc::new(UnconfiguredAuthenticator));
    let server = HttpServer::new(move || app(data.clone(), authenticator.clone()))
        .shutdown_timeout(SHUTDOWN_GRACE_SECONDS)
        .bind(config.bind)
        .map_err(|source| ServerError::Bind {
            address: config.bind,
            source,
        })?
        .run();
    let served = server.await.map_err(ServerError::Serve);

    retention.abort();
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
