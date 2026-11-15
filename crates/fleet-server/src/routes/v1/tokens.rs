//! Self-service tokens: exchange an identity-provider login for a service
//! token that a SendBox host can store, and list or revoke your own tokens.
//!
//! Only callers authenticated by an identity provider may exchange, so a
//! leaked service token cannot mint fresh ones. Only the token's SHA-256 is
//! stored.

use actix_web::{HttpResponse, web};
use serde::{Deserialize, Serialize};

use sendbox_governance::api::{IssuedToken, TokenRequest};

use super::{State, actor};
use crate::audit::{self, AuditRecord};
use crate::auth::{AuthMethod, Authenticated, token_from_bytes};
use crate::problem::Problem;
use crate::routes::resource;
use crate::state::{from_db, to_db};

/// Live tokens one principal may hold at once.
const MAX_LIVE_TOKENS: usize = 20;
const MAX_DESCRIPTION_CHARS: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenSummary {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenList {
    pub tokens: Vec<TokenSummary>,
}

pub fn configure(config: &mut web::ServiceConfig) {
    config
        .service(
            resource("/tokens")
                .route(web::post().to(exchange))
                .route(web::get().to(list)),
        )
        .service(resource("/tokens/{token_id}").route(web::delete().to(revoke)));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn exchange(
    state: State,
    Authenticated(caller): Authenticated,
    request: web::Json<TokenRequest>,
) -> Result<HttpResponse, Problem> {
    let request = request.into_inner();
    if caller.method != AuthMethod::IdentityProvider {
        return Err(Problem::forbidden(
            "exchange needs an identity-provider token; a service token cannot mint another",
        ));
    }
    if let Some(description) = &request.description
        && (description.trim().is_empty()
            || description.chars().count() > MAX_DESCRIPTION_CHARS
            || description.chars().any(char::is_control))
    {
        return Err(Problem::bad_request(format!(
            "description must be 1 to {MAX_DESCRIPTION_CHARS} characters without control characters"
        )));
    }
    let limits = state.tokens;
    let ttl = request.ttl_seconds.unwrap_or(limits.default_seconds);
    if !(60..=limits.max_seconds).contains(&ttl) {
        return Err(Problem::bad_request(format!(
            "ttl_seconds must be between 60 and {}",
            limits.max_seconds
        )));
    }
    let now = state.now();
    let expires_at_unix = now.saturating_add(ttl);
    let mut tx = state.database.begin_write().await?;
    let live = tx
        .fetch_all(
            "SELECT id FROM api_tokens WHERE principal_id = $1 AND revoked_at_unix IS NULL \
             AND expires_at_unix > $2",
            &[caller.principal.as_str().into(), to_db(now)?.into()],
        )
        .await?
        .len();
    if live >= MAX_LIVE_TOKENS {
        return Err(Problem::conflict(format!(
            "you already hold {MAX_LIVE_TOKENS} live tokens; revoke one first"
        )));
    }
    let id = hex(&state.new_id()?);
    let mut secret = [0_u8; 32];
    getrandom::fill(&mut secret).map_err(|error| {
        tracing::error!(%error, "token generation failed");
        Problem::internal()
    })?;
    let (token, digest) = token_from_bytes(&secret);
    tx.execute(
        "INSERT INTO api_tokens (id, principal_id, token_sha256, description, created_at_unix, \
         expires_at_unix) VALUES ($1, $2, $3, $4, $5, $6)",
        &[
            id.clone().into(),
            caller.principal.as_str().into(),
            digest.into(),
            request.description.clone().into(),
            to_db(now)?.into(),
            to_db(expires_at_unix)?.into(),
        ],
    )
    .await?;
    audit::append(
        &mut tx,
        now,
        AuditRecord {
            event_type: "token.issued",
            actor: actor(&caller),
            principal: Some(caller.principal.to_string()),
            detail: Some(format!(
                "token_id={id} expires_at_unix={expires_at_unix} method=identity_provider"
            )),
            ..AuditRecord::default()
        },
    )
    .await?;
    tx.commit().await?;
    Ok(HttpResponse::Created()
        .insert_header((actix_web::http::header::CACHE_CONTROL, "no-store"))
        .json(IssuedToken {
            id,
            token,
            principal: caller.principal,
            expires_at_unix,
        }))
}

async fn list(
    state: State,
    Authenticated(caller): Authenticated,
) -> Result<web::Json<TokenList>, Problem> {
    let rows = state
        .database
        .fetch_all(
            "SELECT id, description, created_at_unix, expires_at_unix, revoked_at_unix \
             FROM api_tokens WHERE principal_id = $1 ORDER BY created_at_unix DESC, id LIMIT 100",
            &[caller.principal.as_str().into()],
        )
        .await?;
    let tokens = rows
        .iter()
        .map(|row| {
            Ok(TokenSummary {
                id: row.text("id")?,
                description: row.opt_text("description")?,
                created_at_unix: from_db(row.int("created_at_unix")?)?,
                expires_at_unix: from_db(row.int("expires_at_unix")?)?,
                revoked_at_unix: row.opt_int("revoked_at_unix")?.map(from_db).transpose()?,
            })
        })
        .collect::<Result<Vec<_>, Problem>>()?;
    Ok(web::Json(TokenList { tokens }))
}

/// Revokes one of the caller's tokens; operators may revoke any token.
async fn revoke(
    state: State,
    Authenticated(caller): Authenticated,
    token_id: web::Path<String>,
) -> Result<HttpResponse, Problem> {
    let token_id = token_id.into_inner();
    if token_id.len() != 32 || !token_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Problem::bad_request(
            "token ids are 32 hexadecimal characters",
        ));
    }
    let now = state.now();
    let mut tx = state.database.begin_write().await?;
    let owner = tx
        .fetch_optional(
            "SELECT principal_id, revoked_at_unix FROM api_tokens WHERE id = $1",
            &[token_id.clone().into()],
        )
        .await?;
    let Some(owner) = owner else {
        return Err(Problem::missing("no such token"));
    };
    let principal = owner.text("principal_id")?;
    if principal != caller.principal.as_str() && !caller.operator {
        return Err(Problem::missing("no such token"));
    }
    if owner.opt_int("revoked_at_unix")?.is_none() {
        tx.execute(
            "UPDATE api_tokens SET revoked_at_unix = $2 WHERE id = $1",
            &[token_id.clone().into(), to_db(now)?.into()],
        )
        .await?;
        audit::append(
            &mut tx,
            now,
            AuditRecord {
                event_type: "token.revoked",
                actor: actor(&caller),
                principal: Some(principal),
                detail: Some(format!("token_id={token_id}")),
                ..AuditRecord::default()
            },
        )
        .await?;
    }
    tx.commit().await?;
    Ok(HttpResponse::NoContent().finish())
}
