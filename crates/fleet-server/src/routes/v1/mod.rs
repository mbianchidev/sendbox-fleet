//! Versioned management API. Every route is mounted behind
//! [`crate::auth::require_bearer`], validates its input against the shared
//! `sendbox-governance` contract, and then answers `501 Not Implemented`
//! naming the increment-2 capability it will provide.

pub mod audit;
pub mod authorize;
pub mod exceptions;
pub mod grants;
pub mod profiles;
pub mod projects;
pub mod sessions;

use actix_web::web;
use sendbox_governance::GovernanceError;

use crate::problem::Problem;

pub fn configure(config: &mut web::ServiceConfig) {
    config
        .configure(sessions::configure)
        .configure(grants::configure)
        .configure(authorize::configure)
        .configure(profiles::configure)
        .configure(projects::configure)
        .configure(exceptions::configure)
        .configure(audit::configure);
}

/// Increment-2 capabilities that this scaffold does not implement yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    SessionAdmission,
    GrantIssuance,
    GrantRenewal,
    GrantRevocation,
    RequestAuthorization,
    ProfileRead,
    ProfilePublication,
    RoleListing,
    RoleAssignment,
    ExceptionRequest,
    AuditQuery,
}

impl Capability {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SessionAdmission => "session_admission",
            Self::GrantIssuance => "grant_issuance",
            Self::GrantRenewal => "grant_renewal",
            Self::GrantRevocation => "grant_revocation",
            Self::RequestAuthorization => "request_authorization",
            Self::ProfileRead => "profile_read",
            Self::ProfilePublication => "profile_publication",
            Self::RoleListing => "role_listing",
            Self::RoleAssignment => "role_assignment",
            Self::ExceptionRequest => "exception_request",
            Self::AuditQuery => "audit_query",
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::SessionAdmission => {
                "Session admission (checking the caller's project role and the current profile revision, then recording the session binding)"
            }
            Self::GrantIssuance => "Credential grant issuance",
            Self::GrantRenewal => "Credential grant lease renewal",
            Self::GrantRevocation => "Credential grant revocation",
            Self::RequestAuthorization => "Per-request grant authorization",
            Self::ProfileRead => "Governance profile retrieval",
            Self::ProfilePublication => "Signed governance profile publication",
            Self::RoleListing => "Project role listing",
            Self::RoleAssignment => "Project role assignment",
            Self::ExceptionRequest => "Expiring policy exception requests",
            Self::AuditQuery => "Central audit event queries",
        }
    }

    #[must_use]
    pub fn problem(self) -> Problem {
        Problem::not_implemented(
            self.code(),
            format!(
                "{} is not implemented yet. It is part of governed sessions increment 2 \
                 (https://github.com/mbianchidev/sendbox/issues/87); this scaffold only \
                 authenticates and validates the request.",
                self.description()
            ),
        )
    }
}

/// Maps a contract validation failure to a 400 problem.
pub(crate) fn invalid(error: GovernanceError) -> Problem {
    Problem::bad_request(error.to_string())
}
