//! Liveness and readiness probes. Both are unauthenticated and reveal only
//! process and database availability.

use actix_web::http::header::{CACHE_CONTROL, HeaderValue};
use actix_web::{HttpResponse, web};
use serde::Serialize;

use super::resource;
use crate::db::Database;
use crate::problem::Problem;

#[derive(Debug, Serialize)]
struct Status {
    status: &'static str,
}

pub fn configure(config: &mut web::ServiceConfig) {
    config
        .service(resource("/healthz").route(web::get().to(healthz)))
        .service(resource("/readyz").route(web::get().to(readyz)));
}

/// The process is running and serving HTTP.
async fn healthz() -> HttpResponse {
    status("ok")
}

/// The service can reach its database.
async fn readyz(database: web::Data<Database>) -> Result<HttpResponse, Problem> {
    database.ping().await.map_err(|error| {
        tracing::warn!(%error, "readiness check failed");
        Problem::service_unavailable("the database is not reachable")
    })?;
    Ok(status("ready"))
}

fn status(status: &'static str) -> HttpResponse {
    HttpResponse::Ok()
        .insert_header((CACHE_CONTROL, HeaderValue::from_static("no-store")))
        .json(Status { status })
}
