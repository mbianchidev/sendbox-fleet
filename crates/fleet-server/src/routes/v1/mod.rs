//! Versioned management API. Every route is mounted behind
//! [`crate::auth::require_bearer`], validates its input against the shared
//! `sendbox-governance` contract, authorizes the authenticated caller from
//! stored roles, and records an audit event for every decision it makes.

pub mod audit;
pub mod authorize;
pub mod exceptions;
pub mod grants;
pub mod profiles;
pub mod projects;
pub mod sessions;
pub mod whoami;

use actix_web::web;
use sendbox_governance::{GovernanceError, ProjectId};

use crate::audit::AuditRecord;
use crate::auth::{Caller, CallerKind};
use crate::db::Tx;
use crate::governance::{self, ProjectRole, Reader};
use crate::problem::Problem;
use crate::state::AppState;

pub fn configure(config: &mut web::ServiceConfig) {
    config
        .configure(whoami::configure)
        .configure(sessions::configure)
        .configure(grants::configure)
        .configure(authorize::configure)
        .configure(profiles::configure)
        .configure(projects::configure)
        .configure(exceptions::configure)
        .configure(audit::configure);
}

/// Maps a contract validation failure to a 400 problem.
pub(crate) fn invalid(error: GovernanceError) -> Problem {
    Problem::bad_request(error.to_string())
}

pub(crate) type State = web::Data<AppState>;

pub(crate) fn actor(caller: &Caller) -> Option<String> {
    Some(caller.principal.to_string())
}

/// People manage projects, roles, profiles, and exceptions; workers only run
/// sessions.
pub(crate) fn require_user(caller: &Caller, action: &str) -> Result<(), Problem> {
    if caller.kind == CallerKind::User {
        Ok(())
    } else {
        Err(Problem::forbidden(format!("workers cannot {action}")))
    }
}

pub(crate) fn require_operator(caller: &Caller, action: &str) -> Result<(), Problem> {
    require_user(caller, action)?;
    if caller.operator {
        Ok(())
    } else {
        Err(Problem::forbidden(format!(
            "only fleet operators can {action}"
        )))
    }
}

/// The caller's role in `project`, or a 404 when the project does not exist.
pub(crate) async fn caller_role(
    reader: &mut impl Reader,
    project: &ProjectId,
    caller: &Caller,
) -> Result<Option<ProjectRole>, Problem> {
    if !governance::project_exists(reader, project).await? {
        return Err(Problem::missing(format!(
            "project `{project}` does not exist"
        )));
    }
    governance::role_of(reader, project, &caller.principal).await
}

/// Records a refused, security-relevant request and returns its problem. The
/// transaction holds no other change, so only the audit event is committed.
pub(crate) async fn refuse<T>(
    state: &AppState,
    mut tx: Tx,
    record: AuditRecord,
    problem: Problem,
) -> Result<T, Problem> {
    let record = AuditRecord {
        detail: Some(match record.detail {
            Some(detail) => format!("{detail} refused={}", problem.detail),
            None => format!("refused={}", problem.detail),
        }),
        ..record
    };
    crate::audit::append(&mut tx, state.now(), record).await?;
    tx.commit().await?;
    Err(problem)
}
