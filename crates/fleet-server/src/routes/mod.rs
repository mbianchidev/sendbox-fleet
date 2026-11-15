//! HTTP routes: unauthenticated probes plus the authenticated `/v1` API.

pub mod health;
pub mod v1;

use actix_web::error::{JsonPayloadError, PathError, QueryPayloadError};
use actix_web::middleware::from_fn;
use actix_web::{HttpRequest, Resource, web};

use crate::auth;
use crate::problem::{self, Problem};

/// Request body limit for ordinary JSON requests.
const JSON_LIMIT_BYTES: usize = 64 * 1024;

pub fn configure(config: &mut web::ServiceConfig) {
    config
        .app_data(json_config(JSON_LIMIT_BYTES))
        .app_data(web::PathConfig::default().error_handler(path_error))
        .app_data(web::QueryConfig::default().error_handler(query_error))
        .configure(health::configure)
        .service(
            web::scope("/v1")
                .wrap(from_fn(auth::require_bearer))
                .configure(v1::configure)
                .default_service(web::to(problem::not_found)),
        );
}

/// A resource whose unsupported methods return a 405 problem.
pub(crate) fn resource(path: &str) -> Resource {
    web::resource(path).default_service(web::to(problem::method_not_allowed))
}

pub(crate) fn json_config(limit: usize) -> web::JsonConfig {
    web::JsonConfig::default()
        .limit(limit)
        .error_handler(json_error)
}

fn json_error(error: JsonPayloadError, _request: &HttpRequest) -> actix_web::Error {
    let problem = match &error {
        JsonPayloadError::Overflow { limit }
        | JsonPayloadError::OverflowKnownLength { limit, .. } => {
            Problem::payload_too_large(format!("request body exceeds {limit} bytes"))
        }
        JsonPayloadError::ContentType => {
            Problem::unsupported_media_type("request body must be `application/json`")
        }
        JsonPayloadError::Deserialize(error) => {
            Problem::bad_request(format!("invalid request body: {error}"))
        }
        _ => Problem::bad_request("request body could not be read"),
    };
    problem.into()
}

fn path_error(error: PathError, _request: &HttpRequest) -> actix_web::Error {
    Problem::bad_request(format!("invalid path parameter: {error}")).into()
}

fn query_error(error: QueryPayloadError, _request: &HttpRequest) -> actix_web::Error {
    Problem::bad_request(format!("invalid query string: {error}")).into()
}
