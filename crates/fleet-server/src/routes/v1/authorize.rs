//! `POST /v1/authorize`: decide one brokered upstream request.

use actix_web::web;
use sendbox_governance::{Decision, RequestContext};

use super::Capability;
use crate::auth::Authenticated;
use crate::problem::Problem;
use crate::routes::resource;

pub fn configure(config: &mut web::ServiceConfig) {
    config.service(resource("/authorize").route(web::post().to(authorize)));
}

/// Takes the enforcement point's trusted [`RequestContext`] and will answer
/// with a [`Decision`]. A malformed path is a `deny` decision, not a request
/// error, so only the contract schema is validated here. Callers must treat
/// any non-200 response as `authority_unavailable` and deny.
async fn authorize(
    _caller: Authenticated,
    _context: web::Json<RequestContext>,
) -> Result<web::Json<Decision>, Problem> {
    Err(Capability::RequestAuthorization.problem())
}
