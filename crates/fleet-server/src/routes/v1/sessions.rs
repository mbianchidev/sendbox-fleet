//! `POST /v1/sessions:admit`: admit a session under a governance profile.

use actix_web::web;
use sendbox_governance::{GovernanceBinding, SessionRef, Sha256Digest};
use serde::{Deserialize, Serialize};

use super::{Capability, invalid};
use crate::auth::Authenticated;
use crate::problem::Problem;
use crate::routes::resource;

/// Submitted by a SendBox host (an authenticated worker) before it starts a
/// governed session. The binding's principal and project are claims to be
/// checked against the caller and its project roles, never trusted as-is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionAdmissionRequest {
    pub session: SessionRef,
    pub binding: GovernanceBinding,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionAdmission {
    pub session: SessionRef,
    pub binding_sha256: Sha256Digest,
    pub admitted_at_unix: u64,
}

pub fn configure(config: &mut web::ServiceConfig) {
    config.service(resource("/sessions:admit").route(web::post().to(admit)));
}

async fn admit(
    _caller: Authenticated,
    request: web::Json<SessionAdmissionRequest>,
) -> Result<web::Json<SessionAdmission>, Problem> {
    request.binding.validate().map_err(invalid)?;
    Err(Capability::SessionAdmission.problem())
}
