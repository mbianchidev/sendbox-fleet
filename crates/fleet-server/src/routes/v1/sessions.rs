//! Session admission and end.
//!
//! A SendBox host admits each governed session before it starts. The binding
//! principal must be the authenticated caller, who needs at least the
//! `member` role in the project. The binding must name this authority and the
//! profile's current revision, and every exception it lifts must be approved,
//! unrevoked, unexpired, bound to that exact revision, and permitted by it.

use actix_web::{HttpResponse, web};
use sendbox_governance::api::{SessionAdmission, SessionAdmissionRequest, SessionEnd};
use sendbox_governance::{DenyReason, SessionRef};

use super::{State, actor, caller_role, invalid, refuse};
use crate::audit::{self, AuditDecision, AuditRecord};
use crate::auth::Authenticated;
use crate::governance::{self, ProjectRole, SessionStatus};
use crate::problem::Problem;
use crate::routes::resource;
use crate::state::to_db;

pub fn configure(config: &mut web::ServiceConfig) {
    config
        .service(resource("/sessions:admit").route(web::post().to(admit)))
        .service(resource("/sessions/{session_id:[^/:]+}:end").route(web::post().to(end)));
}

async fn admit(
    state: State,
    Authenticated(caller): Authenticated,
    request: web::Json<SessionAdmissionRequest>,
) -> Result<web::Json<SessionAdmission>, Problem> {
    let SessionAdmissionRequest { session, binding } = request.into_inner();
    let binding_sha256 = binding.digest().map_err(invalid)?;
    let now = state.now();
    let mut tx = state.database.begin_write().await?;
    let record = AuditRecord {
        event_type: "session.refused",
        actor: Some(caller.principal.to_string()),
        principal: Some(binding.principal.to_string()),
        project: Some(binding.project.to_string()),
        session: Some(session.to_string()),
        profile: Some((binding.profile.id.to_string(), binding.profile.revision)),
        ..AuditRecord::default()
    };
    if binding.principal != caller.principal {
        return refuse(
            &state,
            tx,
            record,
            Problem::forbidden(
                "the binding principal must be the authenticated caller; a host cannot claim another identity",
            ),
        )
        .await;
    }
    if binding.authority.id != state.authority_id {
        return refuse(
            &state,
            tx,
            record,
            Problem::forbidden(format!(
                "the binding names authority `{}`, but this service is `{}`",
                binding.authority.id, state.authority_id
            )),
        )
        .await;
    }
    let role = caller_role(&mut tx, &binding.project, &caller).await?;
    if !role.is_some_and(|role| role.at_least(ProjectRole::Member)) {
        return refuse(
            &state,
            tx,
            record,
            Problem::forbidden(format!(
                "running governed sessions in `{}` requires the member role or higher",
                binding.project
            )),
        )
        .await;
    }
    let profile = match governance::require_current(&mut tx, &binding.profile, now).await {
        Ok(profile) => profile.parse()?,
        Err(reason) => {
            return refuse(
                &state,
                tx,
                AuditRecord {
                    decision: Some(AuditDecision::Deny),
                    deny_reason: Some(reason),
                    ..record
                },
                Problem::conflict(format!(
                    "profile `{}` revision {} is not the current revision ({})",
                    binding.profile.id,
                    binding.profile.revision,
                    reason.code()
                )),
            )
            .await;
        }
    };
    if let Some(service) = binding
        .brokered_services
        .iter()
        .find(|service| profile.credential_service(service).is_none())
    {
        return refuse(
            &state,
            tx,
            record,
            Problem::forbidden(format!(
                "credential service `{service}` is not offered by the profile"
            )),
        )
        .await;
    }
    let mut exceptions = Vec::with_capacity(binding.exceptions.len());
    for id in &binding.exceptions {
        let exception = governance::exception(&mut tx, id).await?;
        let usable = exception.as_ref().is_some_and(|exception| {
            exception.applies_to(&binding.project, &binding.principal, &binding.profile, now)
                && profile.permits_exception(&exception.scope)
        });
        let Some(exception) = exception.filter(|_| usable) else {
            return refuse(
                &state,
                tx,
                AuditRecord {
                    exception: Some(id.to_string()),
                    decision: Some(AuditDecision::Deny),
                    deny_reason: Some(DenyReason::StalePolicy),
                    ..record
                },
                Problem::conflict(format!(
                    "exception `{id}` is not an approved, active exception for this session and profile revision"
                )),
            )
            .await;
        };
        exceptions.push(exception);
    }
    if governance::session(&mut tx, &session).await?.is_some() {
        return Err(Problem::conflict(format!(
            "session `{session}` was already admitted"
        )));
    }
    let canonical = serde_json_canonicalizer::to_string(&binding).map_err(|error| {
        tracing::error!(%error, "binding encoding failed");
        Problem::internal()
    })?;
    tx.execute(
        &format!(
            "INSERT INTO sessions (id, principal_id, project_id, authority_id, profile_id, \
             profile_revision, profile_sha256, effective_policy_sha256, binding, binding_sha256, \
             status, admitted_by, admitted_at_unix) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, {}, \
             $10, 'admitted', $11, $12)",
            tx.json_param(9, false)
        ),
        &[
            session.as_str().into(),
            binding.principal.as_str().into(),
            binding.project.as_str().into(),
            binding.authority.id.clone().into(),
            binding.profile.id.as_str().into(),
            to_db(binding.profile.revision)?.into(),
            binding.profile.sha256.to_string().into(),
            binding.effective_policy_sha256.to_string().into(),
            canonical.into(),
            binding_sha256.to_string().into(),
            caller.principal.as_str().into(),
            to_db(now)?.into(),
        ],
    )
    .await?;
    audit::append(
        &mut tx,
        now,
        AuditRecord {
            event_type: "session.admitted",
            decision: Some(AuditDecision::Allow),
            detail: Some(format!(
                "binding_sha256={binding_sha256} services={}",
                binding
                    .brokered_services
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            )),
            ..record.clone()
        },
    )
    .await?;
    for exception in &exceptions {
        tx.execute(
            "INSERT INTO session_exceptions (session_id, exception_id) VALUES ($1, $2)",
            &[session.as_str().into(), exception.id.as_str().into()],
        )
        .await?;
        audit::append(
            &mut tx,
            now,
            AuditRecord {
                event_type: "exception.applied",
                exception: Some(exception.id.to_string()),
                detail: Some(format!("scope={}", exception.scope)),
                ..record.clone()
            },
        )
        .await?;
    }
    tx.commit().await?;
    Ok(web::Json(SessionAdmission {
        session,
        binding_sha256,
        admitted_at_unix: now,
    }))
}

async fn end(
    state: State,
    Authenticated(caller): Authenticated,
    session: web::Path<SessionRef>,
    request: web::Json<SessionEnd>,
) -> Result<HttpResponse, Problem> {
    let session = session.into_inner();
    let outcome = request.outcome;
    let now = state.now();
    let mut tx = state.database.begin_write().await?;
    let stored = governance::session(&mut tx, &session)
        .await?
        .ok_or_else(|| Problem::missing(format!("session `{session}` was not admitted")))?;
    if stored.binding.principal != caller.principal {
        return Err(Problem::forbidden(
            "only the session's principal can end it",
        ));
    }
    if stored.status == SessionStatus::Ended {
        return Ok(HttpResponse::NoContent().finish());
    }
    tx.execute(
        "UPDATE sessions SET status = $2, ended_at_unix = $3 WHERE id = $1",
        &[
            session.as_str().into(),
            outcome.code().into(),
            to_db(now)?.into(),
        ],
    )
    .await?;
    let base = AuditRecord {
        actor: actor(&caller),
        principal: Some(stored.binding.principal.to_string()),
        project: Some(stored.binding.project.to_string()),
        session: Some(session.to_string()),
        profile: Some((
            stored.binding.profile.id.to_string(),
            stored.binding.profile.revision,
        )),
        ..AuditRecord::default()
    };
    audit::append(
        &mut tx,
        now,
        AuditRecord {
            event_type: "session.ended",
            detail: Some(format!("outcome={}", outcome.code())),
            ..base.clone()
        },
    )
    .await?;
    let grace = governance::profile_revision(
        &mut tx,
        &stored.binding.profile.id,
        stored.binding.profile.revision,
    )
    .await?
    .map(|profile| profile.parse())
    .transpose()?
    .map_or(0, |profile| profile.grants.revocation_grace_seconds);
    let reason = outcome.revocation_reason();
    for grant_id in governance::live_grants(&mut tx, &session).await? {
        let Some(grant) = governance::grant(&mut tx, &grant_id).await? else {
            continue;
        };
        governance::revoke_grant(&mut tx, &grant.grant, reason, None, grace, now).await?;
        audit::append(
            &mut tx,
            now,
            AuditRecord {
                event_type: "grant.revoked",
                grant: Some(grant_id.to_string()),
                detail: Some(format!("reason={}", reason.code())),
                ..base.clone()
            },
        )
        .await?;
    }
    tx.commit().await?;
    Ok(HttpResponse::NoContent().finish())
}
