//! Operator bootstrap commands that act on the database directly:
//! `sendbox-fleet admin ...`. They need only `FLEET_DATABASE_URL` and are
//! meant for whoever operates the service host. Every change is audited with
//! the actor `cli:admin`.

use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};
use sendbox_governance::{Clock, PrincipalId, ProjectId, SystemClock};

use crate::audit::{self, AuditRecord};
use crate::auth::token_from_bytes;
use crate::config::DatabaseUrl;
use crate::db::{Database, DbError};
use crate::governance;
use crate::problem::Problem;
use crate::state::{from_db, to_db};

const ACTOR: &str = "cli:admin";
const MAX_TOKEN_DAYS: u64 = 90;

#[derive(Debug, Subcommand)]
pub enum AdminCommand {
    /// Manage authenticated principals.
    #[command(subcommand)]
    Principal(PrincipalCommand),
    /// Issue, list, and revoke bearer tokens.
    #[command(subcommand)]
    Token(TokenCommand),
    /// Create projects with their first owner.
    #[command(subcommand)]
    Project(ProjectCommand),
    /// Sign, anchor, and verify the audit chain.
    #[command(subcommand)]
    Audit(AuditCommand),
    /// Apply pending database migrations, for deployments that run the
    /// service with `FLEET_MIGRATE=false` and a least-privilege role.
    Migrate,
}

#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// Create an audit signing key (mode 0600) and print its public identity.
    Keygen {
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Write the current chain head, signed with FLEET_AUDIT_SIGNING_KEY, into
    /// DIR (for example a write-once bucket mount).
    Anchor {
        #[arg(long, value_name = "DIR")]
        output: PathBuf,
    },
    /// Recompute the whole chain and check every given anchor against it.
    Verify {
        /// Public identity printed by `audit keygen` (JSON).
        #[arg(long, value_name = "PATH")]
        identity: Option<PathBuf>,
        #[arg(long = "anchor", value_name = "FILE")]
        anchors: Vec<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
pub enum PrincipalCommand {
    /// Add a person (`user`) or machine identity (`worker`).
    Add(PrincipalAdd),
    /// Disable a principal. Its tokens stop working immediately.
    Disable { id: String },
}

#[derive(Debug, Args)]
pub struct PrincipalAdd {
    /// For example `oidc:alice@example.com` or `worker:ci-runner-1`.
    pub id: String,
    #[arg(long, value_enum)]
    pub kind: Kind,
    /// Fleet operator: may publish profiles and create projects.
    #[arg(long)]
    pub operator: bool,
    #[arg(long)]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Kind {
    User,
    Worker,
}

#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    /// Issue a token and print it once on stdout. Only its digest is stored.
    Issue {
        principal: String,
        #[arg(long, default_value_t = 30)]
        ttl_days: u64,
        #[arg(long)]
        description: Option<String>,
    },
    /// List a principal's tokens without revealing them.
    List { principal: String },
    /// Revoke a token by its id.
    Revoke { token_id: String },
}

#[derive(Debug, Subcommand)]
pub enum ProjectCommand {
    /// Create a project and make `--owner` its first owner.
    Create {
        /// `github:owner/repository` or `path-sha256:<hex>`.
        project: String,
        #[arg(long)]
        owner: String,
        #[arg(long)]
        display_name: Option<String>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Anchor(#[from] crate::anchor::AnchorError),
    #[error("audit verification failed")]
    Unverified,
    #[error(transparent)]
    Database(#[from] DbError),
    #[error("{}", .0.detail)]
    Refused(Problem),
}

impl From<Problem> for AdminError {
    fn from(problem: Problem) -> Self {
        Self::Refused(problem)
    }
}

fn principal(value: &str) -> Result<PrincipalId, AdminError> {
    let principal =
        PrincipalId::new(value).map_err(|error| AdminError::Invalid(error.to_string()))?;
    if principal.kind() == "local-user" {
        return Err(AdminError::Invalid(
            "local-user principals belong to a single host".to_owned(),
        ));
    }
    Ok(principal)
}

fn random<const N: usize>() -> Result<[u8; N], AdminError> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes)
        .map_err(|error| AdminError::Invalid(format!("random generation failed: {error}")))?;
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn display_name(value: Option<String>) -> Result<Option<String>, AdminError> {
    if let Some(name) = &value
        && (name.trim().is_empty()
            || name.chars().count() > 200
            || name.chars().any(char::is_control))
    {
        return Err(AdminError::Invalid(
            "display names must be 1 to 200 characters without control characters".to_owned(),
        ));
    }
    Ok(value)
}

/// Runs one admin command. Results go to stdout; a new token is the only
/// thing printed for `token issue`. Pending migrations are applied first
/// unless `migrate` is false (`FLEET_MIGRATE=false`), in which case only
/// `admin migrate` changes the schema.
pub async fn run(
    url: &DatabaseUrl,
    migrate: bool,
    command: AdminCommand,
) -> Result<(), AdminError> {
    if let AdminCommand::Audit(AuditCommand::Keygen { output }) = &command {
        return keygen(output);
    }
    let database = Database::connect(url).await?;
    if migrate || matches!(command, AdminCommand::Migrate) {
        database.migrate().await?;
    } else {
        database.check_migrated().await?;
    }
    let result = match command {
        AdminCommand::Migrate => {
            println!("migrations applied");
            Ok(())
        }
        AdminCommand::Audit(audit) => run_audit(&database, audit).await,
        command => execute(&database, command, SystemClock.now_unix()).await,
    };
    database.close().await;
    result
}

/// Creates an audit signing key; needs no database.
pub fn keygen(output: &std::path::Path) -> Result<(), AdminError> {
    let key = sendbox_security::provenance::SigningKeyMaterial::generate()
        .map_err(|error| AdminError::Invalid(format!("generate key: {error}")))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output)
        .map_err(|error| AdminError::Invalid(format!("create {}: {error}", output.display())))?;
    file.write_all(key.export().as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .map_err(|error| AdminError::Invalid(format!("write {}: {error}", output.display())))?;
    let identity = crate::anchor::AuditSigner::from_key(key).identity;
    eprintln!(
        "audit signing key written to {}; keep it out of the database host's backups. Public identity:",
        output.display()
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&identity)
            .map_err(|error| AdminError::Invalid(error.to_string()))?
    );
    Ok(())
}

async fn run_audit(database: &Database, command: AuditCommand) -> Result<(), AdminError> {
    match command {
        AuditCommand::Keygen { .. } => Err(AdminError::Invalid("unreachable".to_owned())),
        AuditCommand::Anchor { output } => {
            let key = std::env::var_os(crate::config::AUDIT_SIGNING_KEY_VAR).ok_or_else(|| {
                AdminError::Invalid(format!(
                    "{} is required",
                    crate::config::AUDIT_SIGNING_KEY_VAR
                ))
            })?;
            let signer = crate::anchor::AuditSigner::load(std::path::Path::new(&key))?;
            let authority = std::env::var(crate::config::AUTHORITY_ID_VAR)
                .unwrap_or_else(|_| "sendbox-fleet".to_owned());
            let head = crate::anchor::current_head(database, &authority, SystemClock.now_unix())
                .await
                .map_err(AdminError::Refused)?;
            let signed = signer.sign(head)?;
            match crate::anchor::write_anchor(&output, &signed)? {
                Some(path) => println!(
                    "anchored sequence {} in {}",
                    signed.head.sequence,
                    path.display()
                ),
                None => println!("sequence {} is already anchored", signed.head.sequence),
            }
            Ok(())
        }
        AuditCommand::Verify { identity, anchors } => {
            let chain = crate::audit::verify_chain(database)
                .await
                .map_err(AdminError::Refused)?;
            println!(
                "{}",
                serde_json::to_string(&chain)
                    .map_err(|error| AdminError::Invalid(error.to_string()))?
            );
            let mut valid = chain.valid;
            if !anchors.is_empty() {
                let path = identity.ok_or_else(|| {
                    AdminError::Invalid("--identity is required to check anchors".to_owned())
                })?;
                let bytes = std::fs::read(&path).map_err(|error| {
                    AdminError::Invalid(format!("read {}: {error}", path.display()))
                })?;
                let identity: sendbox_security::provenance::Identity =
                    serde_json::from_slice(&bytes).map_err(|error| {
                        AdminError::Invalid(format!("{}: {error}", path.display()))
                    })?;
                for anchor in anchors {
                    let check = crate::anchor::check_anchor(database, &identity, &anchor).await?;
                    valid &= check.valid;
                    println!(
                        "{}",
                        serde_json::to_string(&check)
                            .map_err(|error| AdminError::Invalid(error.to_string()))?
                    );
                }
            }
            if valid {
                Ok(())
            } else {
                Err(AdminError::Unverified)
            }
        }
    }
}

async fn execute(database: &Database, command: AdminCommand, now: u64) -> Result<(), AdminError> {
    let mut tx = database.begin_write().await?;
    let record = |event_type| AuditRecord {
        event_type,
        actor: Some(ACTOR.to_owned()),
        ..AuditRecord::default()
    };
    match command {
        AdminCommand::Principal(PrincipalCommand::Add(add)) => {
            let id = principal(&add.id)?;
            if tx
                .fetch_optional(
                    "SELECT id FROM principals WHERE id = $1",
                    &[id.as_str().into()],
                )
                .await?
                .is_some()
            {
                return Err(AdminError::Invalid(format!(
                    "principal `{id}` already exists"
                )));
            }
            let kind = match add.kind {
                Kind::User => "user",
                Kind::Worker => "worker",
            };
            if add.operator && matches!(add.kind, Kind::Worker) {
                return Err(AdminError::Invalid(
                    "workers cannot be operators".to_owned(),
                ));
            }
            tx.execute(
                "INSERT INTO principals (id, kind, display_name, created_at_unix, is_operator) \
                 VALUES ($1, $2, $3, $4, $5)",
                &[
                    id.as_str().into(),
                    kind.into(),
                    display_name(add.display_name)?.into(),
                    to_db(now)?.into(),
                    add.operator.into(),
                ],
            )
            .await?;
            audit::append(
                &mut tx,
                now,
                AuditRecord {
                    principal: Some(id.to_string()),
                    detail: Some(format!("kind={kind} operator={}", add.operator)),
                    ..record("principal.added")
                },
            )
            .await?;
            println!(
                "added {kind} `{id}`{}",
                if add.operator { " (operator)" } else { "" }
            );
        }
        AdminCommand::Principal(PrincipalCommand::Disable { id }) => {
            let id = principal(&id)?;
            let changed = tx
                .execute(
                    "UPDATE principals SET disabled_at_unix = $2 WHERE id = $1 \
                     AND disabled_at_unix IS NULL",
                    &[id.as_str().into(), to_db(now)?.into()],
                )
                .await?;
            if changed == 0 {
                return Err(AdminError::Invalid(format!(
                    "principal `{id}` does not exist or is already disabled"
                )));
            }
            audit::append(
                &mut tx,
                now,
                AuditRecord {
                    principal: Some(id.to_string()),
                    ..record("principal.disabled")
                },
            )
            .await?;
            println!("disabled `{id}`");
        }
        AdminCommand::Token(TokenCommand::Issue {
            principal: id,
            ttl_days,
            description,
        }) => {
            let id = principal(&id)?;
            if !(1..=MAX_TOKEN_DAYS).contains(&ttl_days) {
                return Err(AdminError::Invalid(format!(
                    "--ttl-days must be 1 to {MAX_TOKEN_DAYS}"
                )));
            }
            if !governance::principal_active(&mut tx, &id).await? {
                return Err(AdminError::Invalid(format!(
                    "principal `{id}` does not exist or is disabled"
                )));
            }
            let token_id = hex(&random::<16>()?);
            let (token, digest) = token_from_bytes(&random::<32>()?);
            let expires = now.saturating_add(ttl_days * 24 * 60 * 60);
            tx.execute(
                "INSERT INTO api_tokens (id, principal_id, token_sha256, description, \
                 created_at_unix, expires_at_unix) VALUES ($1, $2, $3, $4, $5, $6)",
                &[
                    token_id.clone().into(),
                    id.as_str().into(),
                    digest.into(),
                    display_name(description)?.into(),
                    to_db(now)?.into(),
                    to_db(expires)?.into(),
                ],
            )
            .await?;
            audit::append(
                &mut tx,
                now,
                AuditRecord {
                    principal: Some(id.to_string()),
                    detail: Some(format!("token_id={token_id} expires_at_unix={expires}")),
                    ..record("token.issued")
                },
            )
            .await?;
            tx.commit().await?;
            eprintln!("issued token {token_id} for `{id}`, expiring at {expires} (Unix seconds)");
            println!("{token}");
            return Ok(());
        }
        AdminCommand::Token(TokenCommand::List { principal: id }) => {
            let id = principal(&id)?;
            let rows = tx
                .fetch_all(
                    "SELECT id, description, created_at_unix, expires_at_unix, revoked_at_unix \
                     FROM api_tokens WHERE principal_id = $1 ORDER BY created_at_unix",
                    &[id.as_str().into()],
                )
                .await?;
            for row in rows {
                println!(
                    "{}\tcreated={}\texpires={}\trevoked={}\t{}",
                    row.text("id")?,
                    from_db(row.int("created_at_unix")?)?,
                    from_db(row.int("expires_at_unix")?)?,
                    row.opt_int("revoked_at_unix")?
                        .map_or_else(|| "-".to_owned(), |value| value.to_string()),
                    row.opt_text("description")?.unwrap_or_default()
                );
            }
        }
        AdminCommand::Token(TokenCommand::Revoke { token_id }) => {
            let row = tx
                .fetch_optional(
                    "SELECT principal_id FROM api_tokens WHERE id = $1 AND revoked_at_unix IS NULL",
                    &[token_id.clone().into()],
                )
                .await?
                .ok_or_else(|| {
                    AdminError::Invalid(format!("token `{token_id}` does not exist or is revoked"))
                })?;
            tx.execute(
                "UPDATE api_tokens SET revoked_at_unix = $2 WHERE id = $1",
                &[token_id.clone().into(), to_db(now)?.into()],
            )
            .await?;
            audit::append(
                &mut tx,
                now,
                AuditRecord {
                    principal: Some(row.text("principal_id")?),
                    detail: Some(format!("token_id={token_id}")),
                    ..record("token.revoked")
                },
            )
            .await?;
            println!("revoked token {token_id}");
        }
        AdminCommand::Audit(_) | AdminCommand::Migrate => {
            return Err(AdminError::Invalid(
                "handled before the transaction".to_owned(),
            ));
        }
        AdminCommand::Project(ProjectCommand::Create {
            project,
            owner,
            display_name: name,
        }) => {
            let project =
                ProjectId::new(project).map_err(|error| AdminError::Invalid(error.to_string()))?;
            let owner = principal(&owner)?;
            if governance::project_exists(&mut tx, &project).await? {
                return Err(AdminError::Invalid(format!(
                    "project `{project}` already exists"
                )));
            }
            if !governance::principal_active(&mut tx, &owner).await? {
                return Err(AdminError::Invalid(format!(
                    "principal `{owner}` does not exist or is disabled"
                )));
            }
            tx.execute(
                "INSERT INTO projects (id, display_name, created_at_unix) VALUES ($1, $2, $3)",
                &[
                    project.as_str().into(),
                    display_name(name)?.into(),
                    to_db(now)?.into(),
                ],
            )
            .await?;
            tx.execute(
                "INSERT INTO role_bindings (project_id, principal_id, role, granted_by, \
                 granted_at_unix) VALUES ($1, $2, 'owner', $2, $3)",
                &[
                    project.as_str().into(),
                    owner.as_str().into(),
                    to_db(now)?.into(),
                ],
            )
            .await?;
            for (event_type, principal, detail) in [
                ("project.created", None, None),
                (
                    "role.assigned",
                    Some(owner.to_string()),
                    Some("role=owner".to_owned()),
                ),
            ] {
                audit::append(
                    &mut tx,
                    now,
                    AuditRecord {
                        principal,
                        project: Some(project.to_string()),
                        detail,
                        ..record(event_type)
                    },
                )
                .await?;
            }
            println!("created `{project}` owned by `{owner}`");
        }
    }
    tx.commit().await?;
    Ok(())
}
