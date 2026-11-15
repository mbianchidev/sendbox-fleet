//! Governance profiles: publish a signed revision, read the current (or a
//! given) revision, and raise the minimum accepted revision.
//!
//! Publication takes the exact profile bytes and the signature bundle that
//! `sendbox governance sign` writes, and verifies them against the operator
//! signers in `FLEET_PROFILE_TRUST`. Hosts verify the same bytes locally, so
//! a session is only admitted when both agree on the exact revision.

use actix_web::{HttpResponse, web};
use sendbox_governance::{GovernanceProfile, ProfileId, ProfileRef};
use sendbox_security::provenance::{DetachedSignature, SubjectKind};
use serde::{Deserialize, Serialize};

use super::{State, actor, invalid, require_operator};
use crate::audit::{self, AuditRecord};
use crate::auth::Authenticated;
use crate::governance::{self, StoredProfile};
use crate::problem::Problem;
use crate::routes::{json_config, resource};
use crate::state::to_db;

/// Generous enough for a maximum-size profile document after JSON escaping.
const PUBLICATION_LIMIT_BYTES: usize = 1024 * 1024;
const MAX_SIGNATURES: usize = 16;
pub const SIGNATURES_FORMAT: &str = "sendbox.governance-signatures";
const SIGNATURES_VERSION: u32 = 1;
const MAX_REASON_CHARS: usize = 1000;

/// The detached signature file `sendbox governance sign` produces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureBundle {
    pub format: String,
    pub version: u32,
    pub signatures: Vec<DetachedSignature>,
}

/// A profile revision as published by an operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfilePublication {
    /// The exact signed YAML document.
    pub document: String,
    pub signatures: SignatureBundle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRecord {
    pub reference: ProfileRef,
    pub minimum_revision: u64,
    pub not_before_unix: u64,
    pub expires_at_unix: u64,
    pub document: String,
    pub signatures: SignatureBundle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinimumRevision {
    pub revision: u64,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevisionQuery {
    revision: Option<u64>,
}

impl ProfilePublication {
    /// Parses the document with the shared contract and checks the envelope.
    pub fn validate(&self, path_id: &ProfileId) -> Result<GovernanceProfile, Problem> {
        let profile = GovernanceProfile::parse(self.document.as_bytes()).map_err(invalid)?;
        if &profile.id != path_id {
            return Err(Problem::bad_request(format!(
                "profile document id `{}` does not match the request path id `{path_id}`",
                profile.id
            )));
        }
        if self.signatures.format != SIGNATURES_FORMAT
            || self.signatures.version != SIGNATURES_VERSION
        {
            return Err(Problem::bad_request(format!(
                "signatures must use format `{SIGNATURES_FORMAT}` version {SIGNATURES_VERSION}"
            )));
        }
        if self.signatures.signatures.is_empty()
            || self.signatures.signatures.len() > MAX_SIGNATURES
        {
            return Err(Problem::bad_request(format!(
                "a publication needs 1 to {MAX_SIGNATURES} signatures"
            )));
        }
        for signature in &self.signatures.signatures {
            let canonical = signature
                .encode()
                .map_err(|error| Problem::bad_request(format!("invalid signature: {error}")))?;
            DetachedSignature::decode(&canonical)
                .map_err(|error| Problem::bad_request(format!("invalid signature: {error}")))?;
        }
        Ok(profile)
    }
}

pub fn configure(config: &mut web::ServiceConfig) {
    config
        .service(
            resource("/profiles/{profile_id}")
                .app_data(json_config(PUBLICATION_LIMIT_BYTES))
                .route(web::get().to(read))
                .route(web::put().to(publish)),
        )
        .service(
            resource("/profiles/{profile_id}/minimum-revision").route(web::put().to(set_minimum)),
        );
}

async fn record(
    stored: StoredProfile,
    database: &mut crate::db::Database,
) -> Result<ProfileRecord, Problem> {
    let row = database
        .fetch_optional(
            "SELECT CAST(signatures AS TEXT) AS signatures FROM profiles \
             WHERE id = $1 AND revision = $2",
            &[
                stored.reference.id.as_str().into(),
                to_db(stored.reference.revision)?.into(),
            ],
        )
        .await?
        .ok_or_else(Problem::internal)?;
    let signatures = serde_json::from_str(&row.text("signatures")?).map_err(|error| {
        tracing::error!(%error, "stored profile signatures are invalid");
        Problem::internal()
    })?;
    Ok(ProfileRecord {
        document: String::from_utf8(stored.document).map_err(|_| Problem::internal())?,
        reference: stored.reference,
        minimum_revision: stored.minimum_revision,
        not_before_unix: stored.not_before_unix,
        expires_at_unix: stored.expires_at_unix,
        signatures: SignatureBundle {
            format: SIGNATURES_FORMAT.to_owned(),
            version: SIGNATURES_VERSION,
            signatures,
        },
    })
}

async fn read(
    state: State,
    Authenticated(_caller): Authenticated,
    profile: web::Path<ProfileId>,
    query: web::Query<RevisionQuery>,
) -> Result<web::Json<ProfileRecord>, Problem> {
    let profile = profile.into_inner();
    let mut database = state.database.clone();
    let stored = match query.revision {
        Some(revision) => governance::profile_revision(&mut database, &profile, revision).await?,
        None => governance::current_profile(&mut database, &profile, state.now()).await?,
    }
    .ok_or_else(|| Problem::missing(format!("profile `{profile}` has no such revision")))?;
    Ok(web::Json(record(stored, &mut database).await?))
}

async fn publish(
    state: State,
    Authenticated(caller): Authenticated,
    profile_id: web::Path<ProfileId>,
    publication: web::Json<ProfilePublication>,
) -> Result<HttpResponse, Problem> {
    let profile_id = profile_id.into_inner();
    require_operator(&caller, "publish governance profiles")?;
    let profile = publication.validate(&profile_id)?;
    let now = state.now();
    if now >= profile.expires_at_unix {
        return Err(Problem::bad_request(format!(
            "profile `{profile_id}` revision {} has already expired",
            profile.revision
        )));
    }
    let trust = state.profile_trust.as_ref().ok_or_else(|| {
        Problem::service_unavailable(
            "profile signers are not configured; set FLEET_PROFILE_TRUST before publishing",
        )
    })?;
    let bytes = publication.document.as_bytes();
    let verified = trust
        .verify(
            bytes,
            SubjectKind::Configuration,
            &publication.signatures.signatures,
            now,
        )
        .map_err(|error| {
            Problem::forbidden(format!("profile signature verification failed: {error}"))
        })?;
    let reference = profile.reference(bytes);
    let mut tx = state.database.begin_write().await?;
    let newest = tx
        .fetch_optional(
            "SELECT MAX(revision) AS revision FROM profiles WHERE id = $1",
            &[profile_id.as_str().into()],
        )
        .await?
        .and_then(|row| row.opt_int("revision").ok().flatten());
    if newest.is_some_and(|newest| newest >= to_db(profile.revision).unwrap_or(i64::MAX)) {
        return Err(Problem::conflict(format!(
            "profile `{profile_id}` already has revision {} or newer; publish a higher revision",
            profile.revision
        )));
    }
    let signatures = serde_json::to_string(&publication.signatures.signatures)
        .map_err(|_| Problem::internal())?;
    tx.execute(
        &format!(
            "INSERT INTO profiles (id, revision, sha256, signed_bytes, signatures, \
             not_before_unix, expires_at_unix, published_by, published_at_unix) \
             VALUES ($1, $2, $3, $4, {}, $6, $7, $8, $9)",
            tx.json_param(5, true)
        ),
        &[
            profile_id.as_str().into(),
            to_db(profile.revision)?.into(),
            reference.sha256.to_string().into(),
            bytes.to_vec().into(),
            signatures.into(),
            to_db(profile.not_before_unix)?.into(),
            to_db(profile.expires_at_unix)?.into(),
            caller.principal.as_str().into(),
            to_db(now)?.into(),
        ],
    )
    .await?;
    audit::append(
        &mut tx,
        now,
        AuditRecord {
            event_type: "profile.published",
            actor: actor(&caller),
            profile: Some((profile_id.to_string(), profile.revision)),
            detail: Some(format!(
                "sha256={} signers={}",
                reference.sha256,
                verified
                    .valid_signers
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(",")
            )),
            ..AuditRecord::default()
        },
    )
    .await?;
    tx.commit().await?;
    let mut database = state.database.clone();
    let stored = governance::profile_revision(&mut database, &profile_id, profile.revision)
        .await?
        .ok_or_else(Problem::internal)?;
    Ok(HttpResponse::Created().json(record(stored, &mut database).await?))
}

async fn set_minimum(
    state: State,
    Authenticated(caller): Authenticated,
    profile_id: web::Path<ProfileId>,
    request: web::Json<MinimumRevision>,
) -> Result<web::Json<ProfileRecord>, Problem> {
    let profile_id = profile_id.into_inner();
    let request = request.into_inner();
    require_operator(&caller, "set minimum profile revisions")?;
    let reason = request.reason.trim();
    if reason.is_empty()
        || request.reason.chars().count() > MAX_REASON_CHARS
        || request.reason.chars().any(char::is_control)
    {
        return Err(Problem::bad_request(format!(
            "reason must be 1 to {MAX_REASON_CHARS} characters without control characters"
        )));
    }
    let now = state.now();
    let mut tx = state.database.begin_write().await?;
    let Some(target) = governance::profile_revision(&mut tx, &profile_id, request.revision).await?
    else {
        return Err(Problem::missing(format!(
            "profile `{profile_id}` has no revision {}",
            request.revision
        )));
    };
    if request.revision < target.minimum_revision {
        return Err(Problem::conflict(format!(
            "the minimum revision of `{profile_id}` is already {}; it can only be raised",
            target.minimum_revision
        )));
    }
    tx.execute(
        "DELETE FROM profile_minimum_revisions WHERE profile_id = $1",
        &[profile_id.as_str().into()],
    )
    .await?;
    tx.execute(
        "INSERT INTO profile_minimum_revisions (profile_id, minimum_revision, reason, set_by, \
         set_at_unix) VALUES ($1, $2, $3, $4, $5)",
        &[
            profile_id.as_str().into(),
            to_db(request.revision)?.into(),
            request.reason.clone().into(),
            caller.principal.as_str().into(),
            to_db(now)?.into(),
        ],
    )
    .await?;
    audit::append(
        &mut tx,
        now,
        AuditRecord {
            event_type: "profile.minimum_revision_set",
            actor: actor(&caller),
            profile: Some((profile_id.to_string(), request.revision)),
            detail: Some(format!("previous={}", target.minimum_revision)),
            ..AuditRecord::default()
        },
    )
    .await?;
    tx.commit().await?;
    let mut database = state.database.clone();
    let stored = governance::profile_revision(&mut database, &profile_id, request.revision)
        .await?
        .ok_or_else(Problem::internal)?;
    Ok(web::Json(record(stored, &mut database).await?))
}
