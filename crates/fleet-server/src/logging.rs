//! Structured logging to stdout and a daily-rotated `.log` file.
//!
//! Both sinks receive the same JSON-lines events. The file sink rotates at
//! each UTC calendar day (`sendbox-fleet.YYYY-MM-DD.log`) and
//! [`retention`] removes inactive files once they are older than the
//! configured retention window. Request bodies, headers, and query strings are
//! never logged.

pub mod retention;

use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use actix_web::Error;
use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::Next;
use thiserror::Error;
use tracing_appender::non_blocking::{NonBlockingBuilder, WorkerGuard};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

use crate::config::LogConfig;

pub const LOG_FILE_PREFIX: &str = "sendbox-fleet";
pub const LOG_FILE_SUFFIX: &str = "log";
/// Events queued for the file writer before producers wait for it to drain.
/// The writer is not lossy: a full queue applies backpressure instead of
/// silently dropping events.
const FILE_QUEUE_LINES: usize = 16_384;

#[derive(Debug, Error)]
pub enum LoggingError {
    #[error("cannot resolve log directory {path}: {source}")]
    Resolve { path: PathBuf, source: io::Error },
    #[error("cannot create log directory {path}: {source}")]
    CreateDir { path: PathBuf, source: io::Error },
    #[error("cannot open log file in {path}: {source}")]
    Appender {
        path: PathBuf,
        source: tracing_appender::rolling::InitError,
    },
    #[error("invalid log filter: {0}")]
    Filter(String),
    #[error("a global tracing subscriber is already installed: {0}")]
    AlreadyInstalled(String),
}

/// Keeps the file writer alive; dropping it flushes queued events.
#[must_use = "dropping the guard stops file logging"]
pub struct LoggingGuard {
    pub dir: PathBuf,
    _file: WorkerGuard,
}

/// Installs the global subscriber. Call once, before serving requests.
pub fn init(config: &LogConfig) -> Result<LoggingGuard, LoggingError> {
    let dir = resolve_dir(&config.dir)?;
    create_private_dir(&dir)?;
    let appender = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix(LOG_FILE_PREFIX)
        .filename_suffix(LOG_FILE_SUFFIX)
        .build(&dir)
        .map_err(|source| LoggingError::Appender {
            path: dir.clone(),
            source,
        })?;
    let (file_writer, guard) = NonBlockingBuilder::default()
        .lossy(false)
        .buffered_lines_limit(FILE_QUEUE_LINES)
        .thread_name("fleet-log-writer")
        .finish(appender);
    let filter = EnvFilter::try_new(&config.filter)
        .map_err(|error| LoggingError::Filter(error.to_string()))?;

    tracing_subscriber::registry()
        .with(filter)
        .with(
            fmt::layer()
                .json()
                .with_current_span(false)
                .with_writer(io::stdout),
        )
        .with(
            fmt::layer()
                .json()
                .with_current_span(false)
                .with_ansi(false)
                .with_writer(file_writer),
        )
        .try_init()
        .map_err(|error| LoggingError::AlreadyInstalled(error.to_string()))?;

    Ok(LoggingGuard { dir, _file: guard })
}

fn resolve_dir(dir: &Path) -> Result<PathBuf, LoggingError> {
    let absolute = if dir.is_absolute() {
        dir.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(dir))
            .map_err(|source| LoggingError::Resolve {
                path: dir.to_path_buf(),
                source,
            })?
    };
    Ok(absolute
        .components()
        .filter(|component| !matches!(component, Component::CurDir))
        .collect())
}

fn create_private_dir(dir: &Path) -> Result<(), LoggingError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(dir)
        .map_err(|source| LoggingError::CreateDir {
            path: dir.to_path_buf(),
            source,
        })
}

static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Logs one event per request with method, path (without query string),
/// status, and latency. Headers and bodies are never recorded.
pub async fn request_log(
    request: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    let request_id = REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let method = request.method().clone();
    let path = request.path().to_owned();
    let started = Instant::now();
    let response = next.call(request).await;
    let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    match &response {
        Ok(response) => tracing::info!(
            request_id,
            %method,
            path,
            status = response.status().as_u16(),
            latency_ms,
            "request completed"
        ),
        Err(error) => tracing::warn!(
            request_id,
            %method,
            path,
            status = error.as_response_error().status_code().as_u16(),
            latency_ms,
            "request failed"
        ),
    }
    response
}
