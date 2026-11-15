//! Credential grants: issue, renew, and revoke. A grant authorizes one
//! admitted session to use one brokered service. It carries no credential
//! material; the provider credential stays in the SendBox host broker.

use actix_web::{HttpResponse, web};
use sendbox_governance::api::RevokeGrantRequest;
use sendbox_governance::grant::{validate_method, validate_path_prefix};
use sendbox_governance::{
    CONTRACT_VERSION, CredentialGrant, DenyReason, GrantId, GrantRequest, RevocationReason,
    path_permitted,
};

use super::{State, actor, invalid, refuse};
use crate::audit::{self, AuditDecision, AuditRecord};
use crate::auth::{Authenticated, Caller};
use crate::db::Tx;
use crate::governance::{self, ProjectRole, SessionStatus, StoredGrant};
use crate::problem::Problem;
use crate::routes::resource;
use crate::state::to_db;

/// Hard cap from the contract: 7 days from issue to expiry.
const MAX_GRANT_SECONDS: u64 = 7 * 24 * 60 * 60;

pub fn configure(config: &mut web::ServiceConfig) {
    config
        .service(resource("/grants").route(web::post().to(issue)))
        .service(resource("/grants/{grant_id:[^/:]+}:renew").route(web::post().to(renew)))
        .service(resource("/grants/{grant_id:[^/:]+}:revoke").route(web::post().to(revoke)));
}

fn base(caller: &Caller, grant: &CredentialGrant) -> AuditRecord {
    AuditRecord {
        actor: actor(caller),
        principal: Some(grant.principal.to_string()),
        project: Some(grant.project.to_string()),
        session: Some(grant.session.to_string()),
        grant: Some(grant.grant_id.to_string()),
        profile: Some((grant.profile.id.to_string(), grant.profile.revision)),
        ..AuditRecord::default()
    }
}

async fn issue(
    state: State,
    Authenticated(caller): Authenticated,
    request: web::Json<GrantRequest>,
) -> Result<web::Json<CredentialGrant>, Problem> {
    let request = request.into_inner();
    let binding_sha256 = request.binding.digest().map_err(invalid)?;
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
    let now = state.now();
    let mut tx = state.database.begin_write().await?;
    let record = AuditRecord {
        event_type: "grant.refused",
        actor: actor(&caller),
        principal: Some(request.principal.to_string()),
        project: Some(request.project.to_string()),
        session: Some(request.session.to_string()),
        profile: Some((
            request.binding.profile.id.to_string(),
            request.binding.profile.revision,
        )),
        detail: Some(format!("service={}", request.service)),
        ..AuditRecord::default()
    };
    let Some(session) = governance::session(&mut tx, &request.session).await? else {
        return Err(Problem::missing(format!(
            "session `{}` was not admitted",
            request.session
        )));
    };
    let identity_matches = caller.principal == session.binding.principal
        && request.principal == session.binding.principal
        && request.project == session.binding.project
        && request.binding == session.binding
        && binding_sha256 == session.binding_sha256;
    if !identity_matches {
        return refuse(
            &state,
            tx,
            record,
            Problem::forbidden(
                "the grant request does not match the caller and the admitted session binding",
            ),
        )
        .await;
    }
    if session.status != SessionStatus::Admitted {
        return refuse(
            &state,
            tx,
            record,
            Problem::conflict("the session has ended"),
        )
        .await;
    }
    if !session.binding.brokered_services.contains(&request.service) {
        return refuse(
            &state,
            tx,
            record,
            Problem::forbidden("the service is not admitted by the session binding"),
        )
        .await;
    }
    let deny = |reason: DenyReason, record: AuditRecord| AuditRecord {
        decision: Some(AuditDecision::Deny),
        deny_reason: Some(reason),
        ..record
    };
    let profile = match governance::require_current(&mut tx, &session.binding.profile, now).await {
        Ok(profile) => profile,
        Err(reason) => {
            return refuse(
                &state,
                tx,
                deny(reason, record),
                Problem::conflict(format!(
                    "the session's profile revision is stale ({reason})"
                )),
            )
            .await;
        }
    };
    let earliest_exception = match governance::session_exceptions(&mut tx, &session, now).await {
        Ok(earliest) => earliest,
        Err(reason) => {
            return refuse(
                &state,
                tx,
                deny(reason, record),
                Problem::conflict("an exception the session depends on is no longer active"),
            )
            .await;
        }
    };
    let parsed = profile.parse()?;
    let Some(service) = parsed.credential_service(&request.service) else {
        return refuse(
            &state,
            tx,
            record,
            Problem::forbidden("the profile does not offer this service"),
        )
        .await;
    };
    let allowed_prefixes = service.effective_path_prefixes();
    let within_profile = request.methods.is_subset(&service.effective_methods())
        && request
            .path_prefixes
            .iter()
            .all(|prefix| path_permitted(&allowed_prefixes, prefix));
    if !within_profile {
        return refuse(
            &state,
            tx,
            record,
            Problem::forbidden("requested methods or path prefixes exceed the profile"),
        )
        .await;
    }
    let mut max_expires_at_unix = now
        .saturating_add(request.max_ttl_seconds.min(parsed.grants.max_ttl_seconds))
        .min(profile.expires_at_unix)
        .min(now.saturating_add(MAX_GRANT_SECONDS));
    if let Some(earliest) = earliest_exception {
        max_expires_at_unix = max_expires_at_unix.min(earliest);
    }
    if max_expires_at_unix <= now {
        return Err(Problem::conflict("the grant would expire immediately"));
    }
    let grant = CredentialGrant {
        contract_version: CONTRACT_VERSION,
        grant_id: GrantId::from_bytes(state.new_id()?),
        principal: request.principal,
        project: request.project,
        session: request.session,
        binding_sha256,
        profile: session.binding.profile.clone(),
        service: request.service,
        methods: request.methods,
        path_prefixes: request.path_prefixes,
        issued_at_unix: now,
        lease_expires_at_unix: now
            .saturating_add(parsed.grants.lease_seconds)
            .min(max_expires_at_unix),
        max_expires_at_unix,
        generation: 1,
    };
    grant.validate().map_err(invalid)?;
    let methods = serde_json::to_string(&grant.methods).map_err(|_| Problem::internal())?;
    let prefixes = serde_json::to_string(&grant.path_prefixes).map_err(|_| Problem::internal())?;
    tx.execute(
        &format!(
            "INSERT INTO credential_grants (id, session_id, principal_id, project_id, \
             binding_sha256, profile_id, profile_revision, profile_sha256, service_id, methods, \
             path_prefixes, issued_at_unix, lease_expires_at_unix, max_expires_at_unix, \
             generation) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, {}, {}, $12, $13, $14, 1)",
            tx.json_param(10, true),
            tx.json_param(11, true)
        ),
        &[
            grant.grant_id.as_str().into(),
            grant.session.as_str().into(),
            grant.principal.as_str().into(),
            grant.project.as_str().into(),
            grant.binding_sha256.to_string().into(),
            grant.profile.id.as_str().into(),
            to_db(grant.profile.revision)?.into(),
            grant.profile.sha256.to_string().into(),
            grant.service.as_str().into(),
            methods.into(),
            prefixes.into(),
            to_db(grant.issued_at_unix)?.into(),
            to_db(grant.lease_expires_at_unix)?.into(),
            to_db(grant.max_expires_at_unix)?.into(),
        ],
    )
    .await?;
    audit::append(
        &mut tx,
        now,
        AuditRecord {
            event_type: "grant.issued",
            decision: Some(AuditDecision::Allow),
            detail: Some(format!(
                "service={} lease_expires_at_unix={} max_expires_at_unix={}",
                grant.service, grant.lease_expires_at_unix, grant.max_expires_at_unix
            )),
            ..base(&caller, &grant)
        },
    )
    .await?;
    tx.commit().await?;
    Ok(web::Json(grant))
}

/// Why a stored grant can no longer be renewed, if it cannot.
async fn lapse_reason(
    tx: &mut Tx,
    stored: &StoredGrant,
    now: u64,
) -> Result<Option<DenyReason>, Problem> {
    let grant = &stored.grant;
    if stored.revoked.is_some() {
        return Ok(Some(DenyReason::Revoked));
    }
    if now >= grant.max_expires_at_unix {
        return Ok(Some(DenyReason::Expired));
    }
    if now >= grant.lease_expires_at_unix {
        return Ok(Some(DenyReason::LeaseExpired));
    }
    let Some(session) = governance::session(tx, &grant.session).await? else {
        return Ok(Some(DenyReason::SessionMismatch));
    };
    if session.status != SessionStatus::Admitted {
        return Ok(Some(DenyReason::Revoked));
    }
    if let Err(reason) = governance::require_current(tx, &grant.profile, now).await {
        return Ok(Some(reason));
    }
    Ok(governance::session_exceptions(tx, &session, now)
        .await
        .err())
}

async fn renew(
    state: State,
    Authenticated(caller): Authenticated,
    grant_id: web::Path<GrantId>,
) -> Result<web::Json<CredentialGrant>, Problem> {
    let grant_id = grant_id.into_inner();
    let now = state.now();
    let mut tx = state.database.begin_write().await?;
    let stored = governance::grant(&mut tx, &grant_id)
        .await?
        .ok_or_else(|| Problem::missing(format!("grant `{grant_id}` does not exist")))?;
    if stored.grant.principal != caller.principal {
        return Err(Problem::forbidden(
            "only the grant's principal can renew it",
        ));
    }
    if let Some(reason) = lapse_reason(&mut tx, &stored, now).await? {
        return refuse(
            &state,
            tx,
            AuditRecord {
                event_type: "grant.renewal_denied",
                decision: Some(AuditDecision::Deny),
                deny_reason: Some(reason),
                ..base(&caller, &stored.grant)
            },
            Problem::conflict(format!("the grant cannot be renewed ({reason})")),
        )
        .await;
    }
    let session = governance::session(&mut tx, &stored.grant.session)
        .await?
        .ok_or_else(Problem::internal)?;
    let profile = governance::profile_revision(
        &mut tx,
        &stored.grant.profile.id,
        stored.grant.profile.revision,
    )
    .await?
    .ok_or_else(Problem::internal)?
    .parse()?;
    let mut lease = now
        .saturating_add(profile.grants.lease_seconds)
        .min(stored.grant.max_expires_at_unix);
    if let Ok(Some(earliest)) = governance::session_exceptions(&mut tx, &session, now).await {
        lease = lease.min(earliest);
    }
    let mut grant = stored.grant;
    grant.lease_expires_at_unix = lease;
    grant.generation = grant.generation.saturating_add(1);
    tx.execute(
        "UPDATE credential_grants SET lease_expires_at_unix = $2, generation = $3 WHERE id = $1",
        &[
            grant.grant_id.as_str().into(),
            to_db(grant.lease_expires_at_unix)?.into(),
            to_db(grant.generation)?.into(),
        ],
    )
    .await?;
    audit::append(
        &mut tx,
        now,
        AuditRecord {
            event_type: "grant.renewed",
            decision: Some(AuditDecision::Allow),
            detail: Some(format!(
                "lease_expires_at_unix={} generation={}",
                grant.lease_expires_at_unix, grant.generation
            )),
            ..base(&caller, &grant)
        },
    )
    .await?;
    tx.commit().await?;
    Ok(web::Json(grant))
}

async fn revoke(
    state: State,
    Authenticated(caller): Authenticated,
    grant_id: web::Path<GrantId>,
    request: web::Json<RevokeGrantRequest>,
) -> Result<HttpResponse, Problem> {
    let grant_id = grant_id.into_inner();
    let reason = request.reason;
    let now = state.now();
    let mut tx = state.database.begin_write().await?;
    let stored = governance::grant(&mut tx, &grant_id)
        .await?
        .ok_or_else(|| Problem::missing(format!("grant `{grant_id}` does not exist")))?;
    let own = stored.grant.principal == caller.principal;
    let authorized = match reason {
        RevocationReason::SessionCompleted
        | RevocationReason::SessionCancelled
        | RevocationReason::SessionFailed => own,
        RevocationReason::OperatorRevoked | RevocationReason::PolicyChanged => {
            caller.operator
                || governance::role_of(&mut tx, &stored.grant.project, &caller.principal)
                    .await?
                    .is_some_and(|role| role.at_least(ProjectRole::Admin))
        }
    };
    if !authorized {
        return refuse(
            &state,
            tx,
            AuditRecord {
                event_type: "grant.revocation_refused",
                detail: Some(format!("reason={}", reason.code())),
                ..base(&caller, &stored.grant)
            },
            Problem::forbidden(
                "session reasons are for the grant's principal; operator and policy revocations need an admin, owner, or operator",
            ),
        )
        .await;
    }
    if stored.revoked.is_some() {
        return Ok(HttpResponse::NoContent().finish());
    }
    let grace = governance::profile_revision(
        &mut tx,
        &stored.grant.profile.id,
        stored.grant.profile.revision,
    )
    .await?
    .map(|profile| profile.parse())
    .transpose()?
    .map_or(0, |profile| profile.grants.revocation_grace_seconds);
    let revoked_by = (reason == RevocationReason::OperatorRevoked
        || reason == RevocationReason::PolicyChanged)
        .then_some(&caller.principal);
    governance::revoke_grant(&mut tx, &stored.grant, reason, revoked_by, grace, now).await?;
    audit::append(
        &mut tx,
        now,
        AuditRecord {
            event_type: "grant.revoked",
            detail: Some(format!("reason={}", reason.code())),
            ..base(&caller, &stored.grant)
        },
    )
    .await?;
    tx.commit().await?;
    Ok(HttpResponse::NoContent().finish())
}
