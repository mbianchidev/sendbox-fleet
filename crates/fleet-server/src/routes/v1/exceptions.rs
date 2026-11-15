//! `POST /v1/exceptions`: request a bounded, expiring policy exception.
//!
//! The requester is the authenticated caller; approval by a different,
//! authorized principal is a separate step. An exception is bound to the exact
//! profile revision it was reviewed against and can never exceed that
//! profile's ceiling.

use actix_web::web;
use sendbox_governance::{PrincipalId, ProfileRef, ProjectId};
use serde::{Deserialize, Serialize};

use super::Capability;
use crate::auth::Authenticated;
use crate::problem::Problem;
use crate::routes::resource;

const MAX_SCOPE_VALUE_BYTES: usize = 256;
const MAX_REASON_CHARS: usize = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionScopeKind {
    NetworkDomain,
    Command,
    McpTool,
    CredentialServicePath,
}

/// One narrowly scoped permission, such as a single domain or command pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExceptionScope {
    pub kind: ExceptionScopeKind,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExceptionRequest {
    pub project: ProjectId,
    /// Limits the exception to one principal; omit to cover the project.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<PrincipalId>,
    /// The exact profile revision the exception was reviewed against.
    pub profile: ProfileRef,
    pub scope: ExceptionScope,
    pub reason: String,
    pub expires_at_unix: u64,
}

impl ExceptionRequest {
    pub fn validate(&self) -> Result<(), Problem> {
        let value = &self.scope.value;
        if value.is_empty()
            || value.len() > MAX_SCOPE_VALUE_BYTES
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(Problem::bad_request(format!(
                "scope.value must be 1 to {MAX_SCOPE_VALUE_BYTES} printable ASCII bytes without spaces"
            )));
        }
        let reason = self.reason.trim();
        if reason.is_empty()
            || self.reason.chars().count() > MAX_REASON_CHARS
            || self.reason.chars().any(char::is_control)
        {
            return Err(Problem::bad_request(format!(
                "reason must be 1 to {MAX_REASON_CHARS} characters without control characters"
            )));
        }
        if self.expires_at_unix == 0 {
            return Err(Problem::bad_request("expires_at_unix must be set"));
        }
        Ok(())
    }
}

pub fn configure(config: &mut web::ServiceConfig) {
    config.service(resource("/exceptions").route(web::post().to(request_exception)));
}

async fn request_exception(
    _caller: Authenticated,
    request: web::Json<ExceptionRequest>,
) -> Result<web::Json<ExceptionRequest>, Problem> {
    request.validate()?;
    Err(Capability::ExceptionRequest.problem())
}
