//! Bounded, expiring policy exceptions.
//!
//! A project member asks to lift one denial that the current profile revision
//! lists as liftable. A different principal holding the `owner` or `admin`
//! role approves or rejects it. An approval is bound to the exact revision it
//! was reviewed against: a newer revision or a raised minimum makes it stale,
//! so it can no longer admit sessions or keep their grants alive. Lifting a
//! denial never adds a capability; sessions must still fit the ceiling.

use actix_web::{HttpResponse, web};
use sendbox_governance::api::ExceptionList;
use sendbox_governance::exception::{MAX_EXCEPTION_TTL_SECONDS, validate_reason};
use sendbox_governance::{
    ExceptionId, ExceptionScope, ExceptionStatus, PolicyException, PrincipalId, ProfileRef,
    ProjectId,
};
use serde::{Deserialize, Serialize};

use super::{State, actor, caller_role, invalid, refuse, require_user};
use crate::audit::{self, AuditRecord};
use crate::auth::{Authenticated, Caller};
use crate::db::Tx;
use crate::governance::{self, ExceptionState, ProjectRole};
use crate::problem::Problem;
use crate::routes::resource;
use crate::state::to_db;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExceptionRequest {
    pub project: ProjectId,
    /// Limits the exception to one principal; omit to cover the project.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<PrincipalId>,
    /// The exact profile revision the exception is reviewed against. It must
    /// be the current revision.
    pub profile: ProfileRef,
    pub scope: ExceptionScope,
    pub reason: String,
    pub expires_at_unix: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    project: ProjectId,
    #[serde(default)]
    state: ExceptionState,
}

pub fn configure(config: &mut web::ServiceConfig) {
    config
        .service(
            resource("/exceptions")
                .route(web::post().to(request))
                .route(web::get().to(list)),
        )
        .service(resource("/exceptions/{exception_id:[^/:]+}").route(web::get().to(read)))
        .service(
            resource("/exceptions/{exception_id:[^/:]+}:approve").route(web::post().to(approve)),
        )
        .service(resource("/exceptions/{exception_id:[^/:]+}:reject").route(web::post().to(reject)))
        .service(
            resource("/exceptions/{exception_id:[^/:]+}:revoke").route(web::post().to(revoke)),
        );
}

fn record(caller: &Caller, exception: &PolicyException, event_type: &'static str) -> AuditRecord {
    AuditRecord {
        event_type,
        actor: actor(caller),
        principal: exception.principal.as_ref().map(ToString::to_string),
        project: Some(exception.project.to_string()),
        exception: Some(exception.id.to_string()),
        profile: Some((exception.profile.id.to_string(), exception.profile.revision)),
        detail: Some(format!("scope={}", exception.scope)),
        ..AuditRecord::default()
    }
}

async fn request(
    state: State,
    Authenticated(caller): Authenticated,
    request: web::Json<ExceptionRequest>,
) -> Result<HttpResponse, Problem> {
    let request = request.into_inner();
    require_user(&caller, "request policy exceptions")?;
    request.scope.validate().map_err(invalid)?;
    validate_reason(&request.reason).map_err(invalid)?;
    let now = state.now();
    let mut tx = state.database.begin_write().await?;
    let role = caller_role(&mut tx, &request.project, &caller).await?;
    if !role.is_some_and(|role| role.at_least(ProjectRole::Member)) {
        return Err(Problem::forbidden(format!(
            "requesting exceptions in `{}` requires the member role or higher",
            request.project
        )));
    }
    if let Some(principal) = &request.principal
        && !governance::role_of(&mut tx, &request.project, principal)
            .await?
            .is_some_and(|role| role.at_least(ProjectRole::Member))
    {
        return Err(Problem::bad_request(format!(
            "`{principal}` cannot run sessions in `{}`",
            request.project
        )));
    }
    let profile = governance::require_current(&mut tx, &request.profile, now)
        .await
        .map_err(|reason| {
            Problem::conflict(format!(
                "exceptions must be reviewed against the current profile revision ({reason})"
            ))
        })?;
    let parsed = profile.parse()?;
    if !parsed.permits_exception(&request.scope) {
        return Err(Problem::forbidden(format!(
            "profile `{}` revision {} does not permit an exception for `{}`",
            request.profile.id, request.profile.revision, request.scope
        )));
    }
    let longest = parsed
        .exceptions
        .max_ttl_seconds
        .min(MAX_EXCEPTION_TTL_SECONDS);
    if request.expires_at_unix <= now
        || request.expires_at_unix > now.saturating_add(longest)
        || request.expires_at_unix > profile.expires_at_unix
    {
        return Err(Problem::bad_request(format!(
            "expires_at_unix must be in the future, at most {longest} seconds away, and before the profile expires"
        )));
    }
    let exception = PolicyException {
        id: ExceptionId::from_bytes(state.new_id()?),
        project: request.project,
        principal: request.principal,
        profile: request.profile,
        scope: request.scope,
        reason: request.reason,
        status: ExceptionStatus::Pending,
        requested_by: caller.principal.clone(),
        requested_at_unix: now,
        decided_by: None,
        decided_at_unix: None,
        expires_at_unix: request.expires_at_unix,
        revoked_by: None,
        revoked_at_unix: None,
    };
    tx.execute(
        "INSERT INTO exceptions (id, project_id, principal_id, profile_id, profile_revision, \
         profile_sha256, scope_kind, scope_value, reason, status, requested_by, \
         requested_at_unix, expires_at_unix) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, \
         'pending', $10, $11, $12)",
        &[
            exception.id.as_str().into(),
            exception.project.as_str().into(),
            exception.principal.as_ref().map(ToString::to_string).into(),
            exception.profile.id.as_str().into(),
            to_db(exception.profile.revision)?.into(),
            exception.profile.sha256.to_string().into(),
            exception.scope.kind.code().into(),
            exception.scope.value.clone().into(),
            exception.reason.clone().into(),
            exception.requested_by.as_str().into(),
            to_db(now)?.into(),
            to_db(exception.expires_at_unix)?.into(),
        ],
    )
    .await?;
    audit::append(
        &mut tx,
        now,
        AuditRecord {
            detail: Some(format!(
                "scope={} expires_at_unix={}",
                exception.scope, exception.expires_at_unix
            )),
            ..record(&caller, &exception, "exception.requested")
        },
    )
    .await?;
    tx.commit().await?;
    Ok(HttpResponse::Created().json(exception))
}

async fn list(
    state: State,
    Authenticated(caller): Authenticated,
    query: web::Query<ListQuery>,
) -> Result<web::Json<ExceptionList>, Problem> {
    let ListQuery {
        project,
        state: wanted,
    } = query.into_inner();
    let mut database = state.database.clone();
    let role = caller_role(&mut database, &project, &caller).await?;
    if !caller.operator && role.is_none() {
        return Err(Problem::forbidden(format!(
            "you hold no role in project `{project}`"
        )));
    }
    let exceptions =
        governance::project_exceptions(&mut database, &project, wanted, state.now()).await?;
    Ok(web::Json(ExceptionList { exceptions }))
}

async fn read(
    state: State,
    Authenticated(caller): Authenticated,
    id: web::Path<ExceptionId>,
) -> Result<web::Json<PolicyException>, Problem> {
    let mut database = state.database.clone();
    let exception = governance::exception(&mut database, &id)
        .await?
        .ok_or_else(|| Problem::missing(format!("exception `{id}` does not exist")))?;
    let role = governance::role_of(&mut database, &exception.project, &caller.principal).await?;
    if !caller.operator && role.is_none() {
        return Err(Problem::forbidden(format!(
            "you hold no role in project `{}`",
            exception.project
        )));
    }
    Ok(web::Json(exception))
}

/// Loads an exception and checks that the caller may decide it: a person
/// holding `owner` or `admin` in its project who did not request it. Refusals
/// are audited.
async fn decider(
    state: &State,
    mut tx: Tx,
    caller: &Caller,
    id: &ExceptionId,
    event_type: &'static str,
) -> Result<(Tx, PolicyException), Problem> {
    require_user(caller, "decide policy exceptions")?;
    let exception = governance::exception(&mut tx, id)
        .await?
        .ok_or_else(|| Problem::missing(format!("exception `{id}` does not exist")))?;
    let role = governance::role_of(&mut tx, &exception.project, &caller.principal).await?;
    let refusal = if exception.requested_by == caller.principal {
        Some("an exception cannot be decided by the principal who requested it")
    } else if !role.is_some_and(|role| role.at_least(ProjectRole::Admin)) {
        Some("deciding exceptions requires the owner or admin role in the project")
    } else {
        None
    };
    if let Some(refusal) = refusal {
        let record = record(caller, &exception, event_type);
        return refuse(state, tx, record, Problem::forbidden(refusal)).await;
    }
    if exception.status != ExceptionStatus::Pending {
        return Err(Problem::conflict(format!(
            "exception `{id}` was already decided"
        )));
    }
    Ok((tx, exception))
}

async fn approve(
    state: State,
    Authenticated(caller): Authenticated,
    id: web::Path<ExceptionId>,
) -> Result<web::Json<PolicyException>, Problem> {
    let now = state.now();
    let tx = state.database.begin_write().await?;
    let (mut tx, mut exception) =
        decider(&state, tx, &caller, &id, "exception.approval_refused").await?;
    if now >= exception.expires_at_unix {
        return Err(Problem::conflict(format!(
            "exception `{id}` already expired"
        )));
    }
    if let Err(reason) = governance::require_current(&mut tx, &exception.profile, now).await {
        return refuse(
            &state,
            tx,
            record(&caller, &exception, "exception.approval_refused"),
            Problem::conflict(format!(
                "exception `{id}` was reviewed against a profile revision that is no longer current ({reason}); request it again"
            )),
        )
        .await;
    }
    decide(
        &mut tx,
        &mut exception,
        &caller,
        ExceptionStatus::Approved,
        now,
    )
    .await?;
    audit::append(
        &mut tx,
        now,
        record(&caller, &exception, "exception.approved"),
    )
    .await?;
    tx.commit().await?;
    Ok(web::Json(exception))
}

async fn reject(
    state: State,
    Authenticated(caller): Authenticated,
    id: web::Path<ExceptionId>,
) -> Result<web::Json<PolicyException>, Problem> {
    let now = state.now();
    let tx = state.database.begin_write().await?;
    let (mut tx, mut exception) =
        decider(&state, tx, &caller, &id, "exception.rejection_refused").await?;
    decide(
        &mut tx,
        &mut exception,
        &caller,
        ExceptionStatus::Rejected,
        now,
    )
    .await?;
    audit::append(
        &mut tx,
        now,
        record(&caller, &exception, "exception.rejected"),
    )
    .await?;
    tx.commit().await?;
    Ok(web::Json(exception))
}

async fn decide(
    tx: &mut Tx,
    exception: &mut PolicyException,
    caller: &Caller,
    status: ExceptionStatus,
    now: u64,
) -> Result<(), Problem> {
    let code = match status {
        ExceptionStatus::Approved => "approved",
        ExceptionStatus::Rejected => "rejected",
        ExceptionStatus::Pending => return Err(Problem::internal()),
    };
    tx.execute(
        "UPDATE exceptions SET status = $2, decided_by = $3, decided_at_unix = $4 \
         WHERE id = $1 AND status = 'pending'",
        &[
            exception.id.as_str().into(),
            code.into(),
            caller.principal.as_str().into(),
            to_db(now)?.into(),
        ],
    )
    .await?;
    exception.status = status;
    exception.decided_by = Some(caller.principal.clone());
    exception.decided_at_unix = Some(now);
    Ok(())
}

/// Revokes an approved exception. Sessions admitted with it lose their
/// grants on the next renewal or request. Its requester, the project's owners
/// and admins, and operators may revoke it.
async fn revoke(
    state: State,
    Authenticated(caller): Authenticated,
    id: web::Path<ExceptionId>,
) -> Result<web::Json<PolicyException>, Problem> {
    require_user(&caller, "revoke policy exceptions")?;
    let now = state.now();
    let mut tx = state.database.begin_write().await?;
    let mut exception = governance::exception(&mut tx, &id)
        .await?
        .ok_or_else(|| Problem::missing(format!("exception `{id}` does not exist")))?;
    let role = governance::role_of(&mut tx, &exception.project, &caller.principal).await?;
    let allowed = caller.operator
        || exception.requested_by == caller.principal
        || role.is_some_and(|role| role.at_least(ProjectRole::Admin));
    if !allowed {
        return refuse(
            &state,
            tx,
            record(&caller, &exception, "exception.revocation_refused"),
            Problem::forbidden(
                "only the requester, the project's owners and admins, or operators can revoke an exception",
            ),
        )
        .await;
    }
    if exception.status != ExceptionStatus::Approved || exception.revoked_at_unix.is_some() {
        return Err(Problem::conflict(format!(
            "exception `{id}` is not an active approval"
        )));
    }
    tx.execute(
        "UPDATE exceptions SET revoked_by = $2, revoked_at_unix = $3 WHERE id = $1",
        &[
            exception.id.as_str().into(),
            caller.principal.as_str().into(),
            to_db(now)?.into(),
        ],
    )
    .await?;
    exception.revoked_by = Some(caller.principal.clone());
    exception.revoked_at_unix = Some(now);
    audit::append(
        &mut tx,
        now,
        record(&caller, &exception, "exception.revoked"),
    )
    .await?;
    tx.commit().await?;
    Ok(web::Json(exception))
}
