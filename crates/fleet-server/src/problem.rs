//! RFC 9457 problem details (`application/problem+json`).

use actix_web::http::StatusCode;
use actix_web::http::header::{self, HeaderValue};
use actix_web::{HttpRequest, HttpResponse, ResponseError};
use serde::Serialize;
use thiserror::Error;

pub const PROBLEM_CONTENT_TYPE: &str = "application/problem+json";
/// Maximum characters of a parser message echoed back in `detail`.
const MAX_DETAIL_CHARS: usize = 512;

/// A problem response. `type` is always `about:blank`, so `title` is the
/// standard reason phrase for `status` and `detail` explains this occurrence.
#[derive(Debug, Clone, Serialize, Error)]
#[error("{status} {title}: {detail}")]
pub struct Problem {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub title: &'static str,
    pub status: u16,
    pub detail: String,
    /// Stable identifier of the unimplemented capability for 501 responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<&'static str>,
    #[serde(skip)]
    challenge: Option<&'static str>,
}

impl Problem {
    fn new(status: StatusCode, detail: impl Into<String>) -> Self {
        let mut detail: String = detail.into();
        if let Some((index, _)) = detail.char_indices().nth(MAX_DETAIL_CHARS) {
            detail.truncate(index);
            detail.push_str("...");
        }
        Self {
            kind: "about:blank",
            title: status.canonical_reason().unwrap_or("Error"),
            status: status.as_u16(),
            detail,
            capability: None,
            challenge: None,
        }
    }

    #[must_use]
    pub fn bad_request(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, detail)
    }

    /// A 401 carrying a `WWW-Authenticate` challenge (RFC 6750).
    #[must_use]
    pub fn unauthorized(detail: impl Into<String>, challenge: &'static str) -> Self {
        Self {
            challenge: Some(challenge),
            ..Self::new(StatusCode::UNAUTHORIZED, detail)
        }
    }

    #[must_use]
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "no resource exists at this path")
    }

    #[must_use]
    pub fn method_not_allowed() -> Self {
        Self::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "this resource does not support the request method",
        )
    }

    #[must_use]
    pub fn payload_too_large(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, detail)
    }

    #[must_use]
    pub fn unsupported_media_type(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, detail)
    }

    #[must_use]
    pub fn not_implemented(capability: &'static str, detail: impl Into<String>) -> Self {
        Self {
            capability: Some(capability),
            ..Self::new(StatusCode::NOT_IMPLEMENTED, detail)
        }
    }

    #[must_use]
    pub fn service_unavailable(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, detail)
    }
}

impl ResponseError for Problem {
    fn status_code(&self) -> StatusCode {
        StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }

    fn error_response(&self) -> HttpResponse {
        let mut response = HttpResponse::build(self.status_code());
        response
            .content_type(PROBLEM_CONTENT_TYPE)
            .insert_header((header::CACHE_CONTROL, HeaderValue::from_static("no-store")));
        if let Some(challenge) = self.challenge {
            response.insert_header((header::WWW_AUTHENTICATE, challenge));
        }
        response.json(self)
    }
}

/// Default service: unknown paths become a 404 problem.
pub async fn not_found(_request: HttpRequest) -> Problem {
    Problem::not_found()
}

/// Per-resource default service: unsupported methods become a 405 problem.
pub async fn method_not_allowed(_request: HttpRequest) -> Problem {
    Problem::method_not_allowed()
}

impl actix_web::Responder for Problem {
    type Body = actix_web::body::BoxBody;

    fn respond_to(self, _request: &HttpRequest) -> HttpResponse {
        self.error_response()
    }
}
