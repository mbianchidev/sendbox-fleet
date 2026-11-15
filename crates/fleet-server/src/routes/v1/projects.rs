//! Projects and project-scoped roles. Roles decide what an authenticated
//! caller may do within one project; they are never derived from
//! workload-supplied fields. Operators create projects with a first owner;
//! owners (and operators) assign and remove roles. Every change is audited.

use actix_web::{HttpResponse, web};
use sendbox_governance::{PrincipalId, ProjectId};
use serde::{Deserialize, Serialize};

use super::{State, actor, caller_role, refuse, require_operator, require_user};
use crate::audit::{self, AuditRecord};
use crate::auth::{Authenticated, Caller};
use crate::db::Tx;
use crate::governance::{self, ProjectRole, Reader};
use crate::problem::Problem;
use crate::routes::resource;
use crate::state::to_db;

/// Principal kind used by single-host increment 1 for local OS accounts. A
/// shared service authenticates its own principals and never binds these.
const LOCAL_PRINCIPAL_KIND: &str = "local-user";
const MAX_DISPLAY_NAME_CHARS: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleBinding {
    pub principal: PrincipalId,
    pub role: ProjectRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectRoles {
    pub project: ProjectId,
    pub bindings: Vec<RoleBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateProject {
    pub project: ProjectId,
    pub owner: PrincipalId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

pub fn configure(config: &mut web::ServiceConfig) {
    config
        .service(resource("/projects").route(web::post().to(create)))
        .service(
            resource("/projects/{project_id}/roles")
                .route(web::get().to(list))
                .route(web::post().to(assign)),
        )
        .service(
            resource("/projects/{project_id}/roles/{principal_id}").route(web::delete().to(remove)),
        );
}

fn reject_local(principal: &PrincipalId) -> Result<(), Problem> {
    if principal.kind() == LOCAL_PRINCIPAL_KIND {
        return Err(Problem::bad_request(
            "local-user principals belong to a single host and cannot hold project roles",
        ));
    }
    Ok(())
}

async fn bindings(reader: &mut impl Reader, project: &ProjectId) -> Result<ProjectRoles, Problem> {
    let rows = reader
        .rows(
            "SELECT principal_id, role FROM role_bindings WHERE project_id = $1 \
             ORDER BY principal_id",
            &[project.as_str().into()],
        )
        .await?;
    let mut bindings = Vec::with_capacity(rows.len());
    for row in rows {
        let principal =
            PrincipalId::new(row.text("principal_id")?).map_err(|_| Problem::internal())?;
        let role = serde_json::from_value(serde_json::Value::String(row.text("role")?))
            .map_err(|_| Problem::internal())?;
        bindings.push(RoleBinding { principal, role });
    }
    Ok(ProjectRoles {
        project: project.clone(),
        bindings,
    })
}

async fn create(
    state: State,
    Authenticated(caller): Authenticated,
    request: web::Json<CreateProject>,
) -> Result<HttpResponse, Problem> {
    let request = request.into_inner();
    require_operator(&caller, "create projects")?;
    reject_local(&request.owner)?;
    if let Some(name) = &request.display_name
        && (name.trim().is_empty()
            || name.chars().count() > MAX_DISPLAY_NAME_CHARS
            || name.chars().any(char::is_control))
    {
        return Err(Problem::bad_request(format!(
            "display_name must be 1 to {MAX_DISPLAY_NAME_CHARS} characters without control characters"
        )));
    }
    let now = state.now();
    let mut tx = state.database.begin_write().await?;
    if governance::project_exists(&mut tx, &request.project).await? {
        return Err(Problem::conflict(format!(
            "project `{}` already exists",
            request.project
        )));
    }
    if !governance::principal_active(&mut tx, &request.owner).await? {
        return Err(Problem::missing(format!(
            "principal `{}` does not exist or is disabled",
            request.owner
        )));
    }
    tx.execute(
        "INSERT INTO projects (id, display_name, created_at_unix) VALUES ($1, $2, $3)",
        &[
            request.project.as_str().into(),
            request.display_name.clone().into(),
            to_db(now)?.into(),
        ],
    )
    .await?;
    tx.execute(
        "INSERT INTO role_bindings (project_id, principal_id, role, granted_by, granted_at_unix) \
         VALUES ($1, $2, 'owner', $3, $4)",
        &[
            request.project.as_str().into(),
            request.owner.as_str().into(),
            caller.principal.as_str().into(),
            to_db(now)?.into(),
        ],
    )
    .await?;
    for (event_type, principal, detail) in [
        ("project.created", None, None),
        (
            "role.assigned",
            Some(request.owner.to_string()),
            Some("role=owner".to_owned()),
        ),
    ] {
        audit::append(
            &mut tx,
            now,
            AuditRecord {
                event_type,
                actor: actor(&caller),
                principal,
                project: Some(request.project.to_string()),
                detail,
                ..AuditRecord::default()
            },
        )
        .await?;
    }
    let roles = bindings(&mut tx, &request.project).await?;
    tx.commit().await?;
    Ok(HttpResponse::Created().json(roles))
}

async fn list(
    state: State,
    Authenticated(caller): Authenticated,
    project: web::Path<ProjectId>,
) -> Result<web::Json<ProjectRoles>, Problem> {
    let project = project.into_inner();
    let mut database = state.database.clone();
    let role = caller_role(&mut database, &project, &caller).await?;
    if !caller.operator && role.is_none() {
        return Err(Problem::forbidden(format!(
            "you hold no role in project `{project}`"
        )));
    }
    Ok(web::Json(bindings(&mut database, &project).await?))
}

/// Owners manage roles; operators may too, for example to recover ownership.
async fn authorize_role_change(
    state: &State,
    mut tx: Tx,
    caller: &Caller,
    project: &ProjectId,
    principal: &PrincipalId,
    detail: String,
) -> Result<Tx, Problem> {
    let role = caller_role(&mut tx, project, caller).await?;
    if caller.operator || role == Some(ProjectRole::Owner) {
        return Ok(tx);
    }
    refuse(
        state,
        tx,
        AuditRecord {
            event_type: "role.change_refused",
            actor: actor(caller),
            principal: Some(principal.to_string()),
            project: Some(project.to_string()),
            detail: Some(detail),
            ..AuditRecord::default()
        },
        Problem::forbidden(format!("only owners of `{project}` can change its roles")),
    )
    .await
}

/// Refuses to leave a project without an owner.
async fn keep_an_owner(
    tx: &mut Tx,
    project: &ProjectId,
    principal: &PrincipalId,
    new_role: Option<ProjectRole>,
) -> Result<(), Problem> {
    if governance::role_of(tx, project, principal).await? != Some(ProjectRole::Owner)
        || new_role == Some(ProjectRole::Owner)
    {
        return Ok(());
    }
    let owners = tx
        .fetch_all(
            "SELECT principal_id FROM role_bindings WHERE project_id = $1 AND role = 'owner'",
            &[project.as_str().into()],
        )
        .await?
        .len();
    if owners <= 1 {
        return Err(Problem::conflict(format!(
            "`{principal}` is the last owner of `{project}`; assign another owner first"
        )));
    }
    Ok(())
}

async fn assign(
    state: State,
    Authenticated(caller): Authenticated,
    project: web::Path<ProjectId>,
    binding: web::Json<RoleBinding>,
) -> Result<web::Json<ProjectRoles>, Problem> {
    let project = project.into_inner();
    let binding = binding.into_inner();
    require_user(&caller, "change project roles")?;
    reject_local(&binding.principal)?;
    let now = state.now();
    let tx = state.database.begin_write().await?;
    let mut tx = authorize_role_change(
        &state,
        tx,
        &caller,
        &project,
        &binding.principal,
        format!("role={}", binding.role.code()),
    )
    .await?;
    if !governance::principal_active(&mut tx, &binding.principal).await? {
        return Err(Problem::missing(format!(
            "principal `{}` does not exist or is disabled",
            binding.principal
        )));
    }
    keep_an_owner(&mut tx, &project, &binding.principal, Some(binding.role)).await?;
    let previous = governance::role_of(&mut tx, &project, &binding.principal).await?;
    if previous != Some(binding.role) {
        tx.execute(
            "DELETE FROM role_bindings WHERE project_id = $1 AND principal_id = $2",
            &[project.as_str().into(), binding.principal.as_str().into()],
        )
        .await?;
        tx.execute(
            "INSERT INTO role_bindings (project_id, principal_id, role, granted_by, \
             granted_at_unix) VALUES ($1, $2, $3, $4, $5)",
            &[
                project.as_str().into(),
                binding.principal.as_str().into(),
                binding.role.code().into(),
                caller.principal.as_str().into(),
                to_db(now)?.into(),
            ],
        )
        .await?;
        audit::append(
            &mut tx,
            now,
            AuditRecord {
                event_type: "role.assigned",
                actor: actor(&caller),
                principal: Some(binding.principal.to_string()),
                project: Some(project.to_string()),
                detail: Some(match previous {
                    Some(previous) => {
                        format!("role={} previous={}", binding.role.code(), previous.code())
                    }
                    None => format!("role={}", binding.role.code()),
                }),
                ..AuditRecord::default()
            },
        )
        .await?;
    }
    let roles = bindings(&mut tx, &project).await?;
    tx.commit().await?;
    Ok(web::Json(roles))
}

async fn remove(
    state: State,
    Authenticated(caller): Authenticated,
    path: web::Path<(ProjectId, PrincipalId)>,
) -> Result<web::Json<ProjectRoles>, Problem> {
    let (project, principal) = path.into_inner();
    require_user(&caller, "change project roles")?;
    let now = state.now();
    let tx = state.database.begin_write().await?;
    let mut tx = authorize_role_change(
        &state,
        tx,
        &caller,
        &project,
        &principal,
        "role=none".to_owned(),
    )
    .await?;
    let Some(previous) = governance::role_of(&mut tx, &project, &principal).await? else {
        return Err(Problem::missing(format!(
            "`{principal}` holds no role in `{project}`"
        )));
    };
    keep_an_owner(&mut tx, &project, &principal, None).await?;
    tx.execute(
        "DELETE FROM role_bindings WHERE project_id = $1 AND principal_id = $2",
        &[project.as_str().into(), principal.as_str().into()],
    )
    .await?;
    audit::append(
        &mut tx,
        now,
        AuditRecord {
            event_type: "role.removed",
            actor: actor(&caller),
            principal: Some(principal.to_string()),
            project: Some(project.to_string()),
            detail: Some(format!("previous={}", previous.code())),
            ..AuditRecord::default()
        },
    )
    .await?;
    let roles = bindings(&mut tx, &project).await?;
    tx.commit().await?;
    Ok(web::Json(roles))
}
