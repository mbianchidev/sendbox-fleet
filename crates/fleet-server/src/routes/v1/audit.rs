//! `GET /v1/audit/events`: page through the central, hash-chained audit log.
//! Events carry a redacted request target and never credentials, headers,
//! or request bodies.

use actix_web::web;
use sendbox_governance::{
    DenyReason, GrantId, PrincipalId, ProfileRef, ProjectId, SessionRef, Sha256Digest,
};
use serde::{Deserialize, Serialize};

use super::Capability;
use crate::auth::Authenticated;
use crate::problem::Problem;
use crate::routes::resource;

const MAX_PAGE_SIZE: u32 = 500;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditQuery {
    pub project: Option<ProjectId>,
    pub session: Option<SessionRef>,
    pub principal: Option<PrincipalId>,
    /// Return events with a sequence number greater than this cursor.
    pub after_sequence: Option<u64>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Succeeded,
    Failed,
    /// The external effect could not be confirmed, for example a revoked
    /// grant whose in-flight upstream request may still have completed.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    pub sequence: u64,
    pub occurred_at_unix: u64,
    pub event_type: String,
    pub principal: Option<PrincipalId>,
    pub project: Option<ProjectId>,
    pub session: Option<SessionRef>,
    pub grant: Option<GrantId>,
    pub profile: Option<ProfileRef>,
    pub decision: Option<AuditDecision>,
    pub deny_reason: Option<DenyReason>,
    pub outcome: Option<AuditOutcome>,
    /// Method, host, and path prefix only; never a query string or body.
    pub target: Option<String>,
    pub previous_hash: Sha256Digest,
    pub event_hash: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditPage {
    pub events: Vec<AuditEvent>,
    pub next_after_sequence: Option<u64>,
}

pub fn configure(config: &mut web::ServiceConfig) {
    config.service(resource("/audit/events").route(web::get().to(list)));
}

async fn list(
    _caller: Authenticated,
    query: web::Query<AuditQuery>,
) -> Result<web::Json<AuditPage>, Problem> {
    if query
        .limit
        .is_some_and(|limit| !(1..=MAX_PAGE_SIZE).contains(&limit))
    {
        return Err(Problem::bad_request(format!(
            "limit must be between 1 and {MAX_PAGE_SIZE}"
        )));
    }
    Err(Capability::AuditQuery.problem())
}
