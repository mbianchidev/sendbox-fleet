//! Domain lookups shared by the `/v1` handlers: project roles, profile
//! revisions, sessions, grants, and exceptions.
//!
//! Every check reads stored state. Request bodies only ever supply claims to
//! compare against it.

use std::future::Future;
use std::pin::Pin;

use sendbox_governance::{
    CredentialGrant, CurrentProfile, DenyReason, ExceptionId, ExceptionKind, ExceptionScope,
    ExceptionStatus, GovernanceBinding, GovernanceProfile, GrantId, PolicyException, PrincipalId,
    ProfileId, ProfileRef, ProjectId, RevocationReason, SessionRef, Sha256Digest,
};
use serde::{Deserialize, Serialize};

use crate::db::{Arg, Database, DbError, Row, Tx};
use crate::problem::Problem;
use crate::state::{from_db, to_db};

/// Ordered from most to least privileged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectRole {
    /// Manages roles, approves exceptions, and runs sessions.
    Owner,
    /// Approves exceptions, revokes grants, and runs sessions.
    Admin,
    /// Runs governed sessions and requests exceptions.
    Member,
    /// Reads roles, exceptions, and audit events.
    Viewer,
}

impl ProjectRole {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
            Self::Viewer => "viewer",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "owner" => Some(Self::Owner),
            "admin" => Some(Self::Admin),
            "member" => Some(Self::Member),
            "viewer" => Some(Self::Viewer),
            _ => None,
        }
    }

    /// Whether this role grants at least `minimum`.
    #[must_use]
    pub fn at_least(self, minimum: Self) -> bool {
        self <= minimum
    }
}

type RowsFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<Row>, DbError>> + 'a>>;

/// Runs read queries on a pool or inside a write transaction.
pub trait Reader {
    fn rows<'a>(&'a mut self, sql: &'a str, args: &'a [Arg]) -> RowsFuture<'a>;
}

impl Reader for Tx {
    fn rows<'a>(&'a mut self, sql: &'a str, args: &'a [Arg]) -> RowsFuture<'a> {
        Box::pin(self.fetch_all(sql, args))
    }
}

impl Reader for Database {
    fn rows<'a>(&'a mut self, sql: &'a str, args: &'a [Arg]) -> RowsFuture<'a> {
        Box::pin(self.fetch_all(sql, args))
    }
}

async fn first(reader: &mut impl Reader, sql: &str, args: &[Arg]) -> Result<Option<Row>, Problem> {
    Ok(reader.rows(sql, args).await?.into_iter().next())
}

fn corrupt(what: &str) -> Problem {
    tracing::error!(what, "stored record is invalid");
    Problem::internal()
}

pub async fn role_of(
    reader: &mut impl Reader,
    project: &ProjectId,
    principal: &PrincipalId,
) -> Result<Option<ProjectRole>, Problem> {
    first(
        reader,
        "SELECT role FROM role_bindings WHERE project_id = $1 AND principal_id = $2",
        &[project.as_str().into(), principal.as_str().into()],
    )
    .await?
    .map(|row| ProjectRole::parse(&row.text("role")?).ok_or_else(|| corrupt("role")))
    .transpose()
}

pub async fn project_exists(
    reader: &mut impl Reader,
    project: &ProjectId,
) -> Result<bool, Problem> {
    Ok(first(
        reader,
        "SELECT id FROM projects WHERE id = $1 AND archived_at_unix IS NULL",
        &[project.as_str().into()],
    )
    .await?
    .is_some())
}

pub async fn principal_active(
    reader: &mut impl Reader,
    principal: &PrincipalId,
) -> Result<bool, Problem> {
    Ok(first(
        reader,
        "SELECT id FROM principals WHERE id = $1 AND disabled_at_unix IS NULL",
        &[principal.as_str().into()],
    )
    .await?
    .is_some())
}

/// The newest revision of a profile that has reached `not_before_unix`.
#[derive(Debug, Clone)]
pub struct StoredProfile {
    pub reference: ProfileRef,
    pub minimum_revision: u64,
    pub not_before_unix: u64,
    pub expires_at_unix: u64,
    pub document: Vec<u8>,
}

impl StoredProfile {
    #[must_use]
    pub fn current(&self) -> CurrentProfile {
        CurrentProfile {
            reference: self.reference.clone(),
            minimum_revision: self.minimum_revision,
            expires_at_unix: self.expires_at_unix,
        }
    }

    pub fn parse(&self) -> Result<GovernanceProfile, Problem> {
        GovernanceProfile::parse(&self.document).map_err(|_| corrupt("profile"))
    }
}

const SELECT_PROFILE: &str = "SELECT p.id, p.revision, p.sha256, p.signed_bytes, \
     p.not_before_unix, p.expires_at_unix, COALESCE(m.minimum_revision, 1) AS minimum_revision \
     FROM profiles p LEFT JOIN profile_minimum_revisions m ON m.profile_id = p.id";

fn profile_from_row(row: &Row) -> Result<StoredProfile, Problem> {
    Ok(StoredProfile {
        reference: ProfileRef {
            id: ProfileId::new(row.text("id")?).map_err(|_| corrupt("profile id"))?,
            revision: from_db(row.int("revision")?)?,
            sha256: Sha256Digest::parse_hex(&row.text("sha256")?)
                .map_err(|_| corrupt("profile digest"))?,
        },
        minimum_revision: from_db(row.int("minimum_revision")?)?,
        not_before_unix: from_db(row.int("not_before_unix")?)?,
        expires_at_unix: from_db(row.int("expires_at_unix")?)?,
        document: row.bytes("signed_bytes")?,
    })
}

pub async fn current_profile(
    reader: &mut impl Reader,
    id: &ProfileId,
    now_unix: u64,
) -> Result<Option<StoredProfile>, Problem> {
    first(
        reader,
        &format!(
            "{SELECT_PROFILE} WHERE p.id = $1 AND p.not_before_unix <= $2 \
             ORDER BY p.revision DESC LIMIT 1"
        ),
        &[id.as_str().into(), to_db(now_unix)?.into()],
    )
    .await?
    .map(|row| profile_from_row(&row))
    .transpose()
}

pub async fn profile_revision(
    reader: &mut impl Reader,
    id: &ProfileId,
    revision: u64,
) -> Result<Option<StoredProfile>, Problem> {
    first(
        reader,
        &format!("{SELECT_PROFILE} WHERE p.id = $1 AND p.revision = $2"),
        &[id.as_str().into(), to_db(revision)?.into()],
    )
    .await?
    .map(|row| profile_from_row(&row))
    .transpose()
}

/// Loads the current revision and requires `reference` to be exactly it,
/// at or above the minimum and unexpired.
pub async fn require_current(
    reader: &mut impl Reader,
    reference: &ProfileRef,
    now_unix: u64,
) -> Result<StoredProfile, DenyReason> {
    let current = current_profile(reader, &reference.id, now_unix)
        .await
        .map_err(|_| DenyReason::AuthorityUnavailable)?
        .ok_or(DenyReason::StalePolicy)?;
    sendbox_governance::check_current(reference, &current.current(), now_unix)?;
    Ok(current)
}

const SELECT_EXCEPTION: &str = "SELECT id, project_id, principal_id, profile_id, \
     profile_revision, profile_sha256, scope_kind, scope_value, reason, status, requested_by, \
     requested_at_unix, decided_by, decided_at_unix, expires_at_unix, revoked_by, \
     revoked_at_unix FROM exceptions";

fn exception_from_row(row: &Row) -> Result<PolicyException, Problem> {
    let principal = |value: Option<String>| {
        value
            .map(|value| PrincipalId::new(value).map_err(|_| corrupt("exception principal")))
            .transpose()
    };
    Ok(PolicyException {
        id: ExceptionId::new(row.text("id")?).map_err(|_| corrupt("exception id"))?,
        project: ProjectId::new(row.text("project_id")?).map_err(|_| corrupt("project"))?,
        principal: principal(row.opt_text("principal_id")?)?,
        profile: ProfileRef {
            id: ProfileId::new(row.text("profile_id")?).map_err(|_| corrupt("profile id"))?,
            revision: from_db(row.int("profile_revision")?)?,
            sha256: Sha256Digest::parse_hex(&row.text("profile_sha256")?)
                .map_err(|_| corrupt("profile digest"))?,
        },
        scope: ExceptionScope {
            kind: match row.text("scope_kind")?.as_str() {
                "command" => ExceptionKind::Command,
                "domain" => ExceptionKind::Domain,
                "network" => ExceptionKind::Network,
                _ => return Err(corrupt("exception kind")),
            },
            value: row.text("scope_value")?,
        },
        reason: row.text("reason")?,
        status: match row.text("status")?.as_str() {
            "pending" => ExceptionStatus::Pending,
            "approved" => ExceptionStatus::Approved,
            "rejected" => ExceptionStatus::Rejected,
            _ => return Err(corrupt("exception status")),
        },
        requested_by: PrincipalId::new(row.text("requested_by")?)
            .map_err(|_| corrupt("requester"))?,
        requested_at_unix: from_db(row.int("requested_at_unix")?)?,
        decided_by: principal(row.opt_text("decided_by")?)?,
        decided_at_unix: row.opt_int("decided_at_unix")?.map(from_db).transpose()?,
        expires_at_unix: from_db(row.int("expires_at_unix")?)?,
        revoked_by: principal(row.opt_text("revoked_by")?)?,
        revoked_at_unix: row.opt_int("revoked_at_unix")?.map(from_db).transpose()?,
    })
}

pub async fn exception(
    reader: &mut impl Reader,
    id: &ExceptionId,
) -> Result<Option<PolicyException>, Problem> {
    first(
        reader,
        &format!("{SELECT_EXCEPTION} WHERE id = $1"),
        &[id.as_str().into()],
    )
    .await?
    .map(|row| exception_from_row(&row))
    .transpose()
}

/// Which exceptions a listing returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionState {
    /// Approved, unrevoked, and unexpired.
    Active,
    Pending,
    #[default]
    All,
}

pub async fn project_exceptions(
    reader: &mut impl Reader,
    project: &ProjectId,
    state: ExceptionState,
    now_unix: u64,
) -> Result<Vec<PolicyException>, Problem> {
    let (filter, args): (&str, Vec<Arg>) = match state {
        ExceptionState::Active => (
            " AND status = 'approved' AND revoked_at_unix IS NULL AND expires_at_unix > $2",
            vec![project.as_str().into(), to_db(now_unix)?.into()],
        ),
        ExceptionState::Pending => (" AND status = 'pending'", vec![project.as_str().into()]),
        ExceptionState::All => ("", vec![project.as_str().into()]),
    };
    reader
        .rows(
            &format!(
                "{SELECT_EXCEPTION} WHERE project_id = $1{filter} ORDER BY requested_at_unix, id LIMIT 500"
            ),
            &args,
        )
        .await?
        .iter()
        .map(exception_from_row)
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    Admitted,
    Ended,
}

/// An admitted session as stored.
#[derive(Debug, Clone)]
pub struct StoredSession {
    pub session: SessionRef,
    pub binding: GovernanceBinding,
    pub binding_sha256: Sha256Digest,
    pub status: SessionStatus,
}

pub async fn session(
    reader: &mut impl Reader,
    id: &SessionRef,
) -> Result<Option<StoredSession>, Problem> {
    let Some(row) = first(
        reader,
        "SELECT id, CAST(binding AS TEXT) AS binding, binding_sha256, status FROM sessions \
         WHERE id = $1",
        &[id.as_str().into()],
    )
    .await?
    else {
        return Ok(None);
    };
    Ok(Some(StoredSession {
        session: SessionRef::new(row.text("id")?).map_err(|_| corrupt("session id"))?,
        binding: serde_json::from_str(&row.text("binding")?).map_err(|_| corrupt("binding"))?,
        binding_sha256: Sha256Digest::parse_hex(&row.text("binding_sha256")?)
            .map_err(|_| corrupt("binding digest"))?,
        status: if row.text("status")? == "admitted" {
            SessionStatus::Admitted
        } else {
            SessionStatus::Ended
        },
    }))
}

/// Checks that every exception a session was admitted with is still
/// approved, unrevoked, unexpired, and bound to the session's revision.
/// Returns the earliest exception expiry, which caps grant lifetimes.
pub async fn session_exceptions(
    reader: &mut impl Reader,
    session: &StoredSession,
    now_unix: u64,
) -> Result<Option<u64>, DenyReason> {
    let mut earliest = None;
    for id in &session.binding.exceptions {
        let exception = exception(reader, id)
            .await
            .map_err(|_| DenyReason::AuthorityUnavailable)?
            .ok_or(DenyReason::StalePolicy)?;
        if !exception.applies_to(
            &session.binding.project,
            &session.binding.principal,
            &session.binding.profile,
            now_unix,
        ) {
            return Err(DenyReason::StalePolicy);
        }
        earliest = Some(earliest.map_or(exception.expires_at_unix, |current: u64| {
            current.min(exception.expires_at_unix)
        }));
    }
    Ok(earliest)
}

/// A grant as stored, with its revocation state.
#[derive(Debug, Clone)]
pub struct StoredGrant {
    pub grant: CredentialGrant,
    pub revoked: Option<RevocationReason>,
}

pub async fn grant(reader: &mut impl Reader, id: &GrantId) -> Result<Option<StoredGrant>, Problem> {
    let Some(row) = first(
        reader,
        "SELECT g.id, g.session_id, g.principal_id, g.project_id, g.binding_sha256, \
         g.profile_id, g.profile_revision, g.profile_sha256, g.service_id, \
         CAST(g.methods AS TEXT) AS methods, CAST(g.path_prefixes AS TEXT) AS path_prefixes, \
         g.issued_at_unix, g.lease_expires_at_unix, g.max_expires_at_unix, g.generation, \
         r.reason AS revocation FROM credential_grants g \
         LEFT JOIN revocations r ON r.grant_id = g.id WHERE g.id = $1",
        &[id.as_str().into()],
    )
    .await?
    else {
        return Ok(None);
    };
    let text = |column: &str| row.text(column);
    let grant = CredentialGrant {
        contract_version: sendbox_governance::CONTRACT_VERSION,
        grant_id: GrantId::new(text("id")?).map_err(|_| corrupt("grant id"))?,
        principal: PrincipalId::new(text("principal_id")?).map_err(|_| corrupt("principal"))?,
        project: ProjectId::new(text("project_id")?).map_err(|_| corrupt("project"))?,
        session: SessionRef::new(text("session_id")?).map_err(|_| corrupt("session"))?,
        binding_sha256: Sha256Digest::parse_hex(&text("binding_sha256")?)
            .map_err(|_| corrupt("binding digest"))?,
        profile: ProfileRef {
            id: ProfileId::new(text("profile_id")?).map_err(|_| corrupt("profile id"))?,
            revision: from_db(row.int("profile_revision")?)?,
            sha256: Sha256Digest::parse_hex(&text("profile_sha256")?)
                .map_err(|_| corrupt("profile digest"))?,
        },
        service: sendbox_governance::ServiceId::new(text("service_id")?)
            .map_err(|_| corrupt("service"))?,
        methods: serde_json::from_str(&text("methods")?).map_err(|_| corrupt("methods"))?,
        path_prefixes: serde_json::from_str(&text("path_prefixes")?)
            .map_err(|_| corrupt("path prefixes"))?,
        issued_at_unix: from_db(row.int("issued_at_unix")?)?,
        lease_expires_at_unix: from_db(row.int("lease_expires_at_unix")?)?,
        max_expires_at_unix: from_db(row.int("max_expires_at_unix")?)?,
        generation: from_db(row.int("generation")?)?,
    };
    let revoked = row
        .opt_text("revocation")?
        .map(|reason| {
            serde_json::from_value(serde_json::Value::String(reason))
                .map_err(|_| corrupt("revocation reason"))
        })
        .transpose()?;
    Ok(Some(StoredGrant { grant, revoked }))
}

/// Unrevoked grants of one session.
pub async fn live_grants(
    reader: &mut impl Reader,
    session: &SessionRef,
) -> Result<Vec<GrantId>, Problem> {
    reader
        .rows(
            "SELECT g.id FROM credential_grants g LEFT JOIN revocations r ON r.grant_id = g.id \
             WHERE g.session_id = $1 AND r.grant_id IS NULL ORDER BY g.id",
            &[session.as_str().into()],
        )
        .await?
        .iter()
        .map(|row| GrantId::new(row.text("id")?).map_err(|_| corrupt("grant id")))
        .collect()
}

/// Revokes one grant inside `tx`. New requests are denied at once; open
/// streams may finish within the profile's grace window (at most 60 seconds).
pub async fn revoke_grant(
    tx: &mut Tx,
    grant: &CredentialGrant,
    reason: RevocationReason,
    actor: Option<&PrincipalId>,
    grace_seconds: u64,
    now_unix: u64,
) -> Result<(), Problem> {
    let generation = grant.generation.saturating_add(1);
    tx.execute(
        "INSERT INTO revocations (grant_id, reason, revoked_by, revoked_at_unix, \
         grace_expires_at_unix, generation) VALUES ($1, $2, $3, $4, $5, $6)",
        &[
            grant.grant_id.as_str().into(),
            reason.code().into(),
            actor.map(ToString::to_string).into(),
            to_db(now_unix)?.into(),
            to_db(now_unix.saturating_add(grace_seconds.min(60)))?.into(),
            to_db(generation)?.into(),
        ],
    )
    .await?;
    tx.execute(
        "UPDATE credential_grants SET generation = $2 WHERE id = $1",
        &[grant.grant_id.as_str().into(), to_db(generation)?.into()],
    )
    .await?;
    Ok(())
}
