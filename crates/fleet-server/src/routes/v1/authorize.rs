//! `POST /v1/authorize`: decide one brokered upstream request.
//!
//! The decision uses the same rules as the single-host authority
//! (`sendbox_governance::evaluate_request`) against shared state, and also
//! denies once the session ended or an exception it depends on is no longer
//! active. A malformed path is a `deny` decision, not a request error. Hosts
//! treat any non-200 answer as `authority_unavailable` and deny.

use actix_web::web;
use sendbox_governance::{Decision, DenyReason, RequestContext, evaluate_request};

use super::State;
use crate::audit::{self, AuditDecision, AuditRecord};
use crate::auth::Authenticated;
use crate::governance::{self, SessionStatus};
use crate::problem::Problem;
use crate::routes::resource;

const MAX_TARGET_PATH_BYTES: usize = 400;

pub fn configure(config: &mut web::ServiceConfig) {
    config.service(resource("/authorize").route(web::post().to(authorize)));
}

fn deny(reason: DenyReason) -> Decision {
    Decision::Deny { reason }
}

/// Method, service, and path without query; truncated to fit the schema.
fn target(context: &RequestContext) -> String {
    let path = if sendbox_governance::validate_request_path(&context.path).is_ok() {
        let mut path = context.path.clone();
        path.truncate(MAX_TARGET_PATH_BYTES);
        path
    } else {
        "<invalid path>".to_owned()
    };
    format!(
        "{} {}{}",
        context.method.chars().take(16).collect::<String>(),
        context.service,
        path
    )
}

async fn authorize(
    state: State,
    Authenticated(caller): Authenticated,
    context: web::Json<RequestContext>,
) -> Result<web::Json<Decision>, Problem> {
    let context = context.into_inner();
    let now = state.now();
    let mut tx = state.database.begin_write().await?;
    let stored = governance::grant(&mut tx, &context.grant_id).await?;
    let decision = match &stored {
        None => deny(DenyReason::UnknownGrant),
        Some(_) if context.principal != caller.principal => deny(DenyReason::PrincipalMismatch),
        Some(stored) => {
            let current = governance::current_profile(&mut tx, &stored.grant.profile.id, now)
                .await
                .ok()
                .flatten()
                .map(|profile| profile.current());
            match evaluate_request(
                &stored.grant,
                stored.revoked.is_some(),
                &context,
                now,
                current.as_ref(),
            ) {
                Decision::Allow(allowed) => {
                    match governance::session(&mut tx, &stored.grant.session).await? {
                        Some(session) if session.status == SessionStatus::Admitted => {
                            match governance::session_exceptions(&mut tx, &session, now).await {
                                Ok(_) => Decision::Allow(allowed),
                                Err(reason) => deny(reason),
                            }
                        }
                        _ => deny(DenyReason::Revoked),
                    }
                }
                denied @ Decision::Deny { .. } => denied,
            }
        }
    };
    let (decision_code, deny_reason) = match &decision {
        Decision::Allow(_) => {
            crate::metrics::METRICS.decision("allow", "none");
            (AuditDecision::Allow, None)
        }
        Decision::Deny { reason } => {
            crate::metrics::METRICS.decision("deny", reason.code());
            (AuditDecision::Deny, Some(*reason))
        }
    };
    let grant = stored.as_ref().map(|stored| &stored.grant);
    audit::append(
        &mut tx,
        now,
        AuditRecord {
            event_type: "request.authorized",
            actor: Some(caller.principal.to_string()),
            principal: Some(context.principal.to_string()),
            project: Some(context.project.to_string()),
            session: Some(context.session.to_string()),
            grant: Some(context.grant_id.to_string()),
            profile: grant.map(|grant| (grant.profile.id.to_string(), grant.profile.revision)),
            decision: Some(decision_code),
            deny_reason,
            target: Some(target(&context)),
            ..AuditRecord::default()
        },
    )
    .await?;
    tx.commit().await?;
    Ok(web::Json(decision))
}
