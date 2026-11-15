//! Caller authentication for the management API.
//!
//! Authentication (who is calling) is separate from capability authorization
//! (what that caller may do). Every `/v1` request must carry
//! `Authorization: Bearer <token>`; the configured [`Authenticator`] maps the
//! token to a [`Caller`]. Identity claims supplied any other way, such as
//! `X-Forwarded-User` or a principal field inside a request body, are never
//! treated as authenticated identity.
//!
//! The production authenticator, [`FleetAuthenticator`], accepts:
//!
//! - opaque `sbf_` service tokens, issued by `sendbox-fleet admin token issue`
//!   or exchanged at `POST /v1/tokens`. Only their SHA-256 is stored; a token
//!   is accepted while it is unexpired, unrevoked, and its principal is not
//!   disabled;
//! - JWTs from identity providers listed in `FLEET_OIDC_CONFIG` (see
//!   [`crate::oidc`]). The principal must be registered and active, unless its
//!   issuer allows automatic provisioning.

use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::sync::Arc;

use actix_web::body::{EitherBody, MessageBody};
use actix_web::dev::{Payload, ServiceRequest, ServiceResponse};
use actix_web::http::header;
use actix_web::middleware::Next;
use actix_web::{Error, FromRequest, HttpMessage, HttpRequest, ResponseError, web};
use base64::Engine as _;
pub use sendbox_governance::api::CallerKind;
use sendbox_governance::{Clock, PrincipalId};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::audit::{self, AuditRecord};
use crate::db::{Arg, Database};
use crate::oidc::{OidcError, OidcIdentity, OidcVerifier};
use crate::problem::Problem;

/// Prefix of tokens this service issues, so leaked tokens are recognizable.
pub const TOKEN_PREFIX: &str = "sbf_";

const MAX_TOKEN_BYTES: usize = 4096;
const CHALLENGE: &str = r#"Bearer realm="sendbox-fleet""#;
const CHALLENGE_INVALID_REQUEST: &str = r#"Bearer realm="sendbox-fleet", error="invalid_request""#;
const CHALLENGE_INVALID_TOKEN: &str = r#"Bearer realm="sendbox-fleet", error="invalid_token""#;

/// How the caller proved its identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    /// An opaque service token.
    ServiceToken,
    /// A JWT from a configured identity provider.
    IdentityProvider,
}

/// An authenticated caller. Only an [`Authenticator`] creates one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub principal: PrincipalId,
    pub kind: CallerKind,
    /// Fleet-wide operator: publishes profiles and creates projects.
    pub operator: bool,
    pub method: AuthMethod,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuthError {
    #[error("authentication provider not configured")]
    NotConfigured,
    #[error("bearer token was not accepted")]
    InvalidToken,
    #[error("authentication is temporarily unavailable")]
    Unavailable,
    #[error("the identity is not registered with this service")]
    NotRegistered,
}

pub type AuthFuture<'a> = Pin<Box<dyn Future<Output = Result<Caller, AuthError>> + Send + 'a>>;

/// Verifies a bearer token and returns the caller it identifies.
pub trait Authenticator: Send + Sync + 'static {
    fn authenticate<'a>(&'a self, bearer_token: &'a str) -> AuthFuture<'a>;
}

/// Accepts tokens recorded in `api_tokens`.
pub struct DatabaseAuthenticator {
    database: Database,
    clock: Arc<dyn Clock>,
}

impl DatabaseAuthenticator {
    #[must_use]
    pub fn new(database: Database, clock: Arc<dyn Clock>) -> Self {
        Self { database, clock }
    }
}

impl Authenticator for DatabaseAuthenticator {
    fn authenticate<'a>(&'a self, bearer_token: &'a str) -> AuthFuture<'a> {
        Box::pin(async move {
            if !bearer_token.starts_with(TOKEN_PREFIX) {
                return Err(AuthError::InvalidToken);
            }
            let now = i64::try_from(self.clock.now_unix()).map_err(|_| AuthError::Unavailable)?;
            let row = self
                .database
                .fetch_optional(
                    "SELECT p.id AS principal, p.kind AS kind, p.is_operator AS operator \
                     FROM api_tokens t JOIN principals p ON p.id = t.principal_id \
                     WHERE t.token_sha256 = $1 AND t.revoked_at_unix IS NULL \
                     AND t.expires_at_unix > $2 AND p.disabled_at_unix IS NULL",
                    &[Arg::from(token_digest(bearer_token)), Arg::from(now)],
                )
                .await
                .map_err(|error| {
                    tracing::error!(%error, "token lookup failed");
                    AuthError::Unavailable
                })?
                .ok_or(AuthError::InvalidToken)?;
            let caller = (|| {
                let principal = PrincipalId::new(row.text("principal").ok()?).ok()?;
                let kind = match row.text("kind").ok()?.as_str() {
                    "user" => CallerKind::User,
                    "worker" => CallerKind::Worker,
                    _ => return None,
                };
                Some(Caller {
                    principal,
                    kind,
                    operator: row.flag("operator").ok()?,
                    method: AuthMethod::ServiceToken,
                })
            })();
            caller.ok_or_else(|| {
                tracing::error!("stored principal row is invalid");
                AuthError::Unavailable
            })
        })
    }
}

/// Service tokens and, when configured, identity-provider JWTs.
pub struct FleetAuthenticator {
    tokens: DatabaseAuthenticator,
    oidc: Option<OidcVerifier>,
    database: Database,
    clock: Arc<dyn Clock>,
}

impl FleetAuthenticator {
    #[must_use]
    pub fn new(database: Database, clock: Arc<dyn Clock>, oidc: Option<OidcVerifier>) -> Self {
        Self {
            tokens: DatabaseAuthenticator::new(database.clone(), Arc::clone(&clock)),
            oidc,
            database,
            clock,
        }
    }

    async fn resolve(&self, identity: OidcIdentity) -> Result<Caller, AuthError> {
        let unavailable = |error: crate::db::DbError| {
            tracing::error!(%error, "principal lookup failed");
            AuthError::Unavailable
        };
        let lookup = "SELECT kind, is_operator AS operator, disabled_at_unix FROM principals \
                      WHERE id = $1";
        let row = self
            .database
            .fetch_optional(lookup, &[identity.principal.as_str().into()])
            .await
            .map_err(unavailable)?;
        let expected = match identity.kind {
            CallerKind::User => "user",
            CallerKind::Worker => "worker",
        };
        if let Some(row) = row {
            let active = row
                .opt_int("disabled_at_unix")
                .map_err(unavailable)?
                .is_none();
            let kind = row.text("kind").map_err(unavailable)?;
            if !active || kind != expected {
                tracing::info!(
                    principal = %identity.principal,
                    issuer = %identity.issuer,
                    reason = if active { "kind_mismatch" } else { "principal_disabled" },
                    "identity-provider sign-in refused"
                );
                return Err(AuthError::InvalidToken);
            }
            return Ok(Caller {
                principal: identity.principal,
                kind: identity.kind,
                operator: row.flag("operator").map_err(unavailable)?,
                method: AuthMethod::IdentityProvider,
            });
        }
        if !identity.auto_provision {
            tracing::info!(
                principal = %identity.principal,
                issuer = %identity.issuer,
                reason = "not_registered",
                "identity-provider sign-in refused"
            );
            return Err(AuthError::NotRegistered);
        }
        let now = self.clock.now_unix();
        let mut tx = self.database.begin_write().await.map_err(unavailable)?;
        let exists = tx
            .fetch_optional(
                "SELECT id FROM principals WHERE id = $1",
                &[identity.principal.as_str().into()],
            )
            .await
            .map_err(unavailable)?
            .is_some();
        if !exists {
            let created = i64::try_from(now).map_err(|_| AuthError::Unavailable)?;
            tx.execute(
                "INSERT INTO principals (id, kind, created_at_unix) VALUES ($1, $2, $3)",
                &[
                    identity.principal.as_str().into(),
                    expected.into(),
                    created.into(),
                ],
            )
            .await
            .map_err(unavailable)?;
            audit::append(
                &mut tx,
                now,
                AuditRecord {
                    event_type: "principal.provisioned",
                    actor: Some(identity.principal.to_string()),
                    principal: Some(identity.principal.to_string()),
                    detail: Some(format!("kind={expected} issuer={}", identity.issuer)),
                    ..AuditRecord::default()
                },
            )
            .await
            .map_err(|_| AuthError::Unavailable)?;
            tx.commit().await.map_err(unavailable)?;
        }
        Box::pin(self.resolve(OidcIdentity {
            auto_provision: false,
            ..identity
        }))
        .await
    }
}

impl Authenticator for FleetAuthenticator {
    fn authenticate<'a>(&'a self, bearer_token: &'a str) -> AuthFuture<'a> {
        Box::pin(async move {
            if bearer_token.starts_with(TOKEN_PREFIX) {
                return self.tokens.authenticate(bearer_token).await;
            }
            let Some(oidc) = self
                .oidc
                .as_ref()
                .filter(|_| OidcVerifier::handles(bearer_token))
            else {
                return Err(AuthError::InvalidToken);
            };
            let identity = oidc
                .verify(bearer_token)
                .await
                .map_err(|error| match error {
                    OidcError::Rejected(reason) => {
                        tracing::info!(reason, "identity-provider token rejected");
                        AuthError::InvalidToken
                    }
                    OidcError::Unavailable => AuthError::Unavailable,
                })?;
            self.resolve(identity).await
        })
    }
}

/// A new token and the SHA-256 digest that is stored in its place.
#[must_use]
pub fn token_from_bytes(bytes: &[u8; 32]) -> (String, String) {
    let token = format!(
        "{TOKEN_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    );
    let digest = token_digest(&token);
    (token, digest)
}

#[must_use]
pub fn token_digest(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Shared handle stored in application data.
pub type SharedAuthenticator = web::Data<dyn Authenticator>;

#[must_use]
pub fn shared(authenticator: Arc<dyn Authenticator>) -> SharedAuthenticator {
    web::Data::from(authenticator)
}

/// Middleware for the `/v1` scope. It runs before routing to a handler, so an
/// unauthenticated request is rejected before its body is read or validated.
pub async fn require_bearer(
    request: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<EitherBody<impl MessageBody>>, Error> {
    match authenticate(&request).await {
        Ok(caller) => {
            request.extensions_mut().insert(caller);
            next.call(request)
                .await
                .map(ServiceResponse::map_into_left_body)
        }
        Err(problem) => Ok(request
            .into_response(problem.error_response())
            .map_into_right_body()),
    }
}

async fn authenticate(request: &ServiceRequest) -> Result<Caller, Problem> {
    let limits = request
        .app_data::<web::Data<crate::state::AppState>>()
        .map(|state| std::sync::Arc::clone(&state.limits));
    let peer = request
        .peer_addr()
        .map_or_else(|| "unknown".to_owned(), |address| address.ip().to_string());
    let now = std::time::Instant::now();
    if let Some(wait) = limits
        .as_ref()
        .and_then(|limits| limits.auth_failures.exhausted(&peer, now))
    {
        crate::metrics::METRICS.rate_limited();
        return Err(Problem::too_many_requests(wait));
    }
    let failed = |problem: Problem| {
        crate::metrics::METRICS.auth_failure();
        if let Some(limits) = &limits {
            let _ = limits.auth_failures.spend(&peer, now);
        }
        problem
    };
    let token = bearer_token(request.request()).map_err(failed)?;
    let authenticator = request
        .app_data::<SharedAuthenticator>()
        .cloned()
        .ok_or_else(|| rejection(AuthError::NotConfigured))?;
    let caller = match authenticator.authenticate(&token).await {
        Ok(caller) => caller,
        Err(AuthError::Unavailable) => return Err(rejection(AuthError::Unavailable)),
        Err(error) => return Err(failed(rejection(error))),
    };
    if let Some(limits) = &limits
        && let Err(wait) = limits.requests.spend(caller.principal.as_str(), now)
    {
        crate::metrics::METRICS.rate_limited();
        return Err(Problem::too_many_requests(wait));
    }
    Ok(caller)
}

fn bearer_token(request: &HttpRequest) -> Result<String, Problem> {
    let mut values = request.headers().get_all(header::AUTHORIZATION);
    let Some(value) = values.next() else {
        return Err(Problem::unauthorized(
            "authentication required: send `Authorization: Bearer <token>`",
            CHALLENGE,
        ));
    };
    let malformed = || {
        Problem::unauthorized(
            "the Authorization header must contain exactly one `Bearer <token>` credential",
            CHALLENGE_INVALID_REQUEST,
        )
    };
    if values.next().is_some() {
        return Err(malformed());
    }
    let value = value.to_str().map_err(|_| malformed())?;
    let (scheme, token) = value.split_once(' ').ok_or_else(malformed)?;
    if !scheme.eq_ignore_ascii_case("bearer") || !valid_token(token) {
        return Err(malformed());
    }
    Ok(token.to_owned())
}

/// RFC 6750 `b64token`: `1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`.
fn valid_token(token: &str) -> bool {
    let body = token.trim_end_matches('=');
    !body.is_empty()
        && token.len() <= MAX_TOKEN_BYTES
        && body
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~+/".contains(&byte))
}

fn rejection(error: AuthError) -> Problem {
    match error {
        AuthError::Unavailable => Problem::service_unavailable(error.to_string()),
        AuthError::NotConfigured | AuthError::InvalidToken | AuthError::NotRegistered => {
            Problem::unauthorized(error.to_string(), CHALLENGE_INVALID_TOKEN)
        }
    }
}

/// Extracts the caller authenticated by [`require_bearer`]. Rejects the
/// request when the middleware did not run, so a handler mounted outside the
/// authenticated scope cannot accidentally serve anonymous callers.
#[derive(Debug, Clone)]
pub struct Authenticated(pub Caller);

impl FromRequest for Authenticated {
    type Error = Problem;
    type Future = Ready<Result<Self, Problem>>;

    fn from_request(request: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        ready(
            request
                .extensions()
                .get::<Caller>()
                .cloned()
                .map(Self)
                .ok_or_else(|| Problem::unauthorized("authentication required", CHALLENGE)),
        )
    }
}

#[cfg(test)]
mod tests {
    use actix_web::test::TestRequest;

    use super::*;

    #[test]
    fn issued_tokens_are_bearer_tokens_stored_only_as_digests() {
        let (token, digest) = token_from_bytes(&[7; 32]);
        assert!(token.starts_with(TOKEN_PREFIX));
        assert!(valid_token(&token));
        assert_eq!(digest.len(), 64);
        assert!(!digest.contains(&token[TOKEN_PREFIX.len()..]));
        assert_eq!(token_digest(&token), digest);
        assert_ne!(token_from_bytes(&[8; 32]).1, digest);
    }

    #[test]
    fn bearer_token_grammar_is_enforced() {
        let token = |value: &str| {
            bearer_token(
                &TestRequest::default()
                    .insert_header((header::AUTHORIZATION, value))
                    .to_http_request(),
            )
        };
        assert_eq!(
            token("Bearer abc.DEF-123_~+/==").unwrap(),
            "abc.DEF-123_~+/=="
        );
        assert_eq!(token("bearer abc").unwrap(), "abc");
        for rejected in [
            "Basic dXNlcjpwYXNz",
            "Bearer",
            "Bearer ",
            "Bearer two words",
            "Bearer ===",
            "Bearer a\"b",
        ] {
            assert!(token(rejected).is_err(), "{rejected:?} was accepted");
        }
        assert!(token(&format!("Bearer {}", "a".repeat(MAX_TOKEN_BYTES + 1))).is_err());
        assert!(bearer_token(&TestRequest::default().to_http_request()).is_err());
    }
}
