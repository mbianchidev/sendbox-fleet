//! Central audit: page through events and verify the hash chain.
//!
//! Operators read every event. Anyone else must name a project in which they
//! hold a role, and sees only that project's events.

use actix_web::web;
use sendbox_governance::{ExceptionId, PrincipalId, ProjectId, SessionRef};
use serde::{Deserialize, Serialize};

use super::{State, caller_role, require_operator};
use crate::audit::{self, AuditEvent, ChainVerification, EventFilter};
use crate::auth::Authenticated;
use crate::problem::Problem;
use crate::routes::resource;

const DEFAULT_PAGE_SIZE: u32 = 100;
const MAX_PAGE_SIZE: u32 = 500;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditQuery {
    pub project: Option<ProjectId>,
    pub session: Option<SessionRef>,
    pub principal: Option<PrincipalId>,
    pub exception: Option<ExceptionId>,
    /// Return events with a sequence number greater than this cursor.
    pub after_sequence: Option<u64>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditPage {
    pub events: Vec<AuditEvent>,
    pub next_after_sequence: Option<u64>,
}

pub fn configure(config: &mut web::ServiceConfig) {
    config
        .service(resource("/audit/events").route(web::get().to(list)))
        .service(resource("/audit/verify").route(web::get().to(verify)))
        .service(resource("/audit/head").route(web::get().to(head)));
}

async fn list(
    state: State,
    Authenticated(caller): Authenticated,
    query: web::Query<AuditQuery>,
) -> Result<web::Json<AuditPage>, Problem> {
    let query = query.into_inner();
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE);
    if !(1..=MAX_PAGE_SIZE).contains(&limit) {
        return Err(Problem::bad_request(format!(
            "limit must be between 1 and {MAX_PAGE_SIZE}"
        )));
    }
    if !caller.operator {
        let Some(project) = &query.project else {
            return Err(Problem::forbidden(
                "name a project you hold a role in; only operators read the whole log",
            ));
        };
        let mut database = state.database.clone();
        if caller_role(&mut database, project, &caller)
            .await?
            .is_none()
        {
            return Err(Problem::forbidden(format!(
                "you hold no role in project `{project}`"
            )));
        }
    }
    let events = audit::query(
        &state.database,
        &EventFilter {
            project: query.project.map(|value| value.to_string()),
            session: query.session.map(|value| value.to_string()),
            principal: query.principal.map(|value| value.to_string()),
            exception: query.exception.map(|value| value.to_string()),
            after_sequence: query.after_sequence.unwrap_or(0),
            limit,
        },
    )
    .await?;
    let next_after_sequence = (events.len() == limit as usize)
        .then(|| events.last().map(|event| event.sequence))
        .flatten();
    Ok(web::Json(AuditPage {
        events,
        next_after_sequence,
    }))
}

async fn verify(
    state: State,
    Authenticated(caller): Authenticated,
) -> Result<web::Json<ChainVerification>, Problem> {
    require_operator(&caller, "verify the audit chain")?;
    Ok(web::Json(audit::verify_chain(&state.database).await?))
}

/// The current chain head, signed with the service's audit key, for storage
/// outside the database.
async fn head(
    state: State,
    Authenticated(caller): Authenticated,
) -> Result<web::Json<crate::anchor::SignedAuditHead>, Problem> {
    require_operator(&caller, "read the signed audit head")?;
    let signer = state.audit_signer.as_ref().ok_or_else(|| {
        Problem::service_unavailable(
            "the audit signing key is not configured; set FLEET_AUDIT_SIGNING_KEY",
        )
    })?;
    let head =
        crate::anchor::current_head(&state.database, &state.authority_id, state.now()).await?;
    signer.sign(head).map(web::Json).map_err(|error| {
        tracing::error!(%error, "audit head signing failed");
        Problem::internal()
    })
}
