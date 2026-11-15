//! Credential grants: issue, renew, and revoke. Grants authorize one session
//! to use one brokered service; they never carry credential material.

use actix_web::{HttpResponse, web};
use sendbox_governance::grant::{validate_method, validate_path_prefix};
use sendbox_governance::{CredentialGrant, GrantId, GrantRequest, RevocationReason};
use serde::{Deserialize, Serialize};

use super::{Capability, invalid};
use crate::auth::Authenticated;
use crate::problem::Problem;
use crate::routes::resource;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeGrantRequest {
    pub reason: RevocationReason,
}

pub fn configure(config: &mut web::ServiceConfig) {
    config
        .service(resource("/grants").route(web::post().to(issue)))
        .service(resource("/grants/{grant_id:[^/:]+}:renew").route(web::post().to(renew)))
        .service(resource("/grants/{grant_id:[^/:]+}:revoke").route(web::post().to(revoke)));
}

async fn issue(
    _caller: Authenticated,
    request: web::Json<GrantRequest>,
) -> Result<web::Json<CredentialGrant>, Problem> {
    request.binding.validate().map_err(invalid)?;
    if request.methods.is_empty() || request.path_prefixes.is_empty() {
        return Err(Problem::bad_request(
            "grants require at least one method and path prefix",
        ));
    }
    for method in &request.methods {
        validate_method(method).map_err(invalid)?;
    }
    for prefix in &request.path_prefixes {
        validate_path_prefix(prefix).map_err(invalid)?;
    }
    if request.max_ttl_seconds == 0 {
        return Err(Problem::bad_request("max_ttl_seconds must be positive"));
    }
    Err(Capability::GrantIssuance.problem())
}

async fn renew(
    _caller: Authenticated,
    _grant: web::Path<GrantId>,
) -> Result<web::Json<CredentialGrant>, Problem> {
    Err(Capability::GrantRenewal.problem())
}

async fn revoke(
    _caller: Authenticated,
    _grant: web::Path<GrantId>,
    _request: web::Json<RevokeGrantRequest>,
) -> Result<HttpResponse, Problem> {
    Err(Capability::GrantRevocation.problem())
}
