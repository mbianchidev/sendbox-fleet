//! Project-scoped roles. Roles authorize what an authenticated caller may do
//! within one project; they are never derived from workload-supplied fields.

use actix_web::web;
use sendbox_governance::{PrincipalId, ProjectId};
use serde::{Deserialize, Serialize};

use super::Capability;
use crate::auth::Authenticated;
use crate::problem::Problem;
use crate::routes::resource;

/// Ordered from most to least privileged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectRole {
    /// Manages roles and approves exceptions for the project.
    Owner,
    /// Approves exceptions and revokes grants.
    Admin,
    /// Starts governed sessions within the profile ceiling.
    Member,
    /// Reads sessions and audit events.
    Viewer,
}

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

/// Principal kind used by single-host increment 1 for local OS accounts. A
/// shared service authenticates its own principals and never binds these.
const LOCAL_PRINCIPAL_KIND: &str = "local-user";

pub fn configure(config: &mut web::ServiceConfig) {
    config.service(
        resource("/projects/{project_id}/roles")
            .route(web::get().to(list))
            .route(web::post().to(assign)),
    );
}

async fn list(
    _caller: Authenticated,
    _project: web::Path<ProjectId>,
) -> Result<web::Json<ProjectRoles>, Problem> {
    Err(Capability::RoleListing.problem())
}

async fn assign(
    _caller: Authenticated,
    _project: web::Path<ProjectId>,
    binding: web::Json<RoleBinding>,
) -> Result<web::Json<ProjectRoles>, Problem> {
    if binding.principal.kind() == LOCAL_PRINCIPAL_KIND {
        return Err(Problem::bad_request(
            "local-user principals belong to a single host and cannot hold project roles",
        ));
    }
    Err(Capability::RoleAssignment.problem())
}
