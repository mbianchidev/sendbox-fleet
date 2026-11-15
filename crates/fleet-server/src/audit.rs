//! Central, append-only audit log.
//!
//! Every state change and every authorization decision appends one event in
//! the same transaction as the change it records. Events form a hash chain:
//! `event_hash` is the SHA-256 of the RFC 8785 canonical JSON of the event
//! without `event_hash`, which includes `previous_hash`. Events carry
//! identifiers, decisions, a redacted request target, and short non-secret
//! details; never credentials, tokens, headers, query strings, or bodies.

use sendbox_governance::{DenyReason, Sha256Digest};
use serde::{Deserialize, Serialize};

use crate::db::{Arg, Database, Row, Tx};
use crate::problem::Problem;
use crate::state::{from_db, to_db};

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_TARGET_BYTES: usize = 512;
const MAX_DETAIL_BYTES: usize = 1100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Succeeded,
    Failed,
    /// The external effect could not be confirmed.
    Unknown,
}

/// What a caller records. The sequence, times, and hashes are assigned when
/// the event is appended.
#[derive(Debug, Clone, Default)]
pub struct AuditRecord {
    pub event_type: &'static str,
    pub actor: Option<String>,
    pub principal: Option<String>,
    pub project: Option<String>,
    pub session: Option<String>,
    pub grant: Option<String>,
    pub exception: Option<String>,
    pub profile: Option<(String, u64)>,
    pub decision: Option<AuditDecision>,
    pub deny_reason: Option<DenyReason>,
    pub outcome: Option<AuditOutcome>,
    pub target: Option<String>,
    pub detail: Option<String>,
}

/// A stored event exactly as it is hashed and returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    pub sequence: u64,
    pub occurred_at_unix: u64,
    pub recorded_at_unix: u64,
    pub event_type: String,
    pub actor: Option<String>,
    pub principal: Option<String>,
    pub project: Option<String>,
    pub session: Option<String>,
    pub grant: Option<String>,
    pub exception: Option<String>,
    pub profile_id: Option<String>,
    pub profile_revision: Option<u64>,
    pub decision: Option<AuditDecision>,
    pub deny_reason: Option<DenyReason>,
    pub outcome: Option<AuditOutcome>,
    /// Method, service, and path only; never a query string or body.
    pub target: Option<String>,
    pub detail: Option<String>,
    pub previous_hash: Sha256Digest,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub event_hash: Option<Sha256Digest>,
}

impl AuditEvent {
    /// The chain hash of this event, computed over every field except
    /// `event_hash`.
    pub fn compute_hash(&self) -> Result<Sha256Digest, Problem> {
        let unhashed = Self {
            event_hash: None,
            ..self.clone()
        };
        sendbox_governance::canonical_digest(&unhashed).map_err(|error| {
            tracing::error!(%error, "audit event encoding failed");
            Problem::internal()
        })
    }
}

/// Bounds free text to printable ASCII so it satisfies the schema.
#[must_use]
pub fn printable(value: &str, limit: usize) -> String {
    let mut text = value
        .chars()
        .map(|character| {
            if character == ' ' || character.is_ascii_graphic() {
                character
            } else {
                '?'
            }
        })
        .collect::<String>();
    text.truncate(limit);
    text.trim().to_owned()
}

/// Appends one event inside `tx`. The caller's write lock serializes appends.
pub async fn append(tx: &mut Tx, now_unix: u64, record: AuditRecord) -> Result<u64, Problem> {
    let last = tx
        .fetch_optional(
            "SELECT sequence, event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1",
            &[],
        )
        .await?;
    let (sequence, previous_hash) = match last {
        Some(row) => (from_db(row.int("sequence")?)? + 1, row.text("event_hash")?),
        None => (1, GENESIS_HASH.to_owned()),
    };
    let previous_hash = Sha256Digest::parse_hex(&previous_hash).map_err(|error| {
        tracing::error!(%error, "stored audit hash is invalid");
        Problem::internal()
    })?;
    let (profile_id, profile_revision) = record
        .profile
        .map_or((None, None), |(id, revision)| (Some(id), Some(revision)));
    let mut event = AuditEvent {
        sequence,
        occurred_at_unix: now_unix,
        recorded_at_unix: now_unix,
        event_type: record.event_type.to_owned(),
        actor: record.actor,
        principal: record.principal,
        project: record.project,
        session: record.session,
        grant: record.grant,
        exception: record.exception,
        profile_id,
        profile_revision,
        decision: record.decision,
        deny_reason: record.deny_reason,
        outcome: record.outcome,
        target: record
            .target
            .map(|target| printable(&target.replace('?', ""), MAX_TARGET_BYTES))
            .filter(|target| !target.is_empty()),
        detail: record
            .detail
            .map(|detail| printable(&detail, MAX_DETAIL_BYTES))
            .filter(|detail| !detail.is_empty()),
        previous_hash,
        event_hash: None,
    };
    let hash = event.compute_hash()?;
    event.event_hash = Some(hash);
    tx.execute(
        "INSERT INTO audit_events (sequence, occurred_at_unix, recorded_at_unix, event_type, \
         actor_id, principal_id, project_id, session_id, grant_id, exception_id, profile_id, \
         profile_revision, decision, deny_reason, outcome, target_redacted, detail, \
         previous_hash, event_hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, \
         $13, $14, $15, $16, $17, $18, $19)",
        &[
            to_db(event.sequence)?.into(),
            to_db(event.occurred_at_unix)?.into(),
            to_db(event.recorded_at_unix)?.into(),
            event.event_type.clone().into(),
            event.actor.clone().into(),
            event.principal.clone().into(),
            event.project.clone().into(),
            event.session.clone().into(),
            event.grant.clone().into(),
            event.exception.clone().into(),
            event.profile_id.clone().into(),
            event.profile_revision.map(to_db).transpose()?.into(),
            event.decision.map(|decision| code(&decision)).into(),
            event
                .deny_reason
                .map(|reason| reason.code().to_owned())
                .into(),
            event.outcome.map(|outcome| code(&outcome)).into(),
            event.target.clone().into(),
            event.detail.clone().into(),
            event.previous_hash.to_string().into(),
            hash.to_string().into(),
        ],
    )
    .await?;
    crate::metrics::METRICS.audit_appended(sequence);
    Ok(sequence)
}

fn code<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn parse<T: for<'de> Deserialize<'de>>(value: Option<String>) -> Result<Option<T>, Problem> {
    value
        .map(|value| {
            serde_json::from_value(serde_json::Value::String(value)).map_err(|error| {
                tracing::error!(%error, "stored audit code is invalid");
                Problem::internal()
            })
        })
        .transpose()
}

const SELECT_EVENTS: &str = "SELECT sequence, occurred_at_unix, recorded_at_unix, event_type, \
     actor_id, principal_id, project_id, session_id, grant_id, exception_id, profile_id, \
     profile_revision, decision, deny_reason, outcome, target_redacted, detail, previous_hash, \
     event_hash FROM audit_events";

fn event_from_row(row: &Row) -> Result<AuditEvent, Problem> {
    let digest = |value: String| {
        Sha256Digest::parse_hex(&value).map_err(|error| {
            tracing::error!(%error, "stored audit hash is invalid");
            Problem::internal()
        })
    };
    Ok(AuditEvent {
        sequence: from_db(row.int("sequence")?)?,
        occurred_at_unix: from_db(row.int("occurred_at_unix")?)?,
        recorded_at_unix: from_db(row.int("recorded_at_unix")?)?,
        event_type: row.text("event_type")?,
        actor: row.opt_text("actor_id")?,
        principal: row.opt_text("principal_id")?,
        project: row.opt_text("project_id")?,
        session: row.opt_text("session_id")?,
        grant: row.opt_text("grant_id")?,
        exception: row.opt_text("exception_id")?,
        profile_id: row.opt_text("profile_id")?,
        profile_revision: row.opt_int("profile_revision")?.map(from_db).transpose()?,
        decision: parse(row.opt_text("decision")?)?,
        deny_reason: parse(row.opt_text("deny_reason")?)?,
        outcome: parse(row.opt_text("outcome")?)?,
        target: row.opt_text("target_redacted")?,
        detail: row.opt_text("detail")?,
        previous_hash: digest(row.text("previous_hash")?)?,
        event_hash: Some(digest(row.text("event_hash")?)?),
    })
}

/// Filters for one page of events, oldest first.
#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    pub project: Option<String>,
    pub session: Option<String>,
    pub principal: Option<String>,
    pub exception: Option<String>,
    pub after_sequence: u64,
    pub limit: u32,
}

pub async fn query(database: &Database, filter: &EventFilter) -> Result<Vec<AuditEvent>, Problem> {
    let mut sql = format!("{SELECT_EVENTS} WHERE sequence > $1");
    let mut args = vec![Arg::from(to_db(filter.after_sequence)?)];
    for (column, value) in [
        ("project_id", &filter.project),
        ("session_id", &filter.session),
        ("principal_id", &filter.principal),
        ("exception_id", &filter.exception),
    ] {
        if let Some(value) = value {
            args.push(Arg::from(value.clone()));
            sql.push_str(&format!(" AND {column} = ${}", args.len()));
        }
    }
    args.push(Arg::from(i64::from(filter.limit)));
    sql.push_str(&format!(" ORDER BY sequence LIMIT ${}", args.len()));
    database
        .fetch_all(&sql, &args)
        .await?
        .iter()
        .map(event_from_row)
        .collect()
}

/// Result of recomputing the whole chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainVerification {
    pub events: u64,
    pub head_hash: Sha256Digest,
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub first_invalid_sequence: Option<u64>,
}

/// Recomputes every event hash and link, in pages.
pub async fn verify_chain(database: &Database) -> Result<ChainVerification, Problem> {
    const PAGE: i64 = 1000;
    let mut previous = Sha256Digest::parse_hex(GENESIS_HASH).map_err(|_| Problem::internal())?;
    let mut expected_sequence = 1;
    let mut after = 0_i64;
    loop {
        let rows = database
            .fetch_all(
                &format!("{SELECT_EVENTS} WHERE sequence > $1 ORDER BY sequence LIMIT $2"),
                &[Arg::from(after), Arg::from(PAGE)],
            )
            .await?;
        if rows.is_empty() {
            break;
        }
        for row in &rows {
            let event = event_from_row(row)?;
            let valid = event.sequence == expected_sequence
                && event.previous_hash == previous
                && event.event_hash == Some(event.compute_hash()?);
            if !valid {
                return Ok(ChainVerification {
                    events: expected_sequence - 1,
                    head_hash: previous,
                    valid: false,
                    first_invalid_sequence: Some(event.sequence),
                });
            }
            previous = event.event_hash.unwrap_or(previous);
            expected_sequence += 1;
            after = to_db(event.sequence)?;
        }
    }
    Ok(ChainVerification {
        events: expected_sequence - 1,
        head_hash: previous,
        valid: true,
        first_invalid_sequence: None,
    })
}
