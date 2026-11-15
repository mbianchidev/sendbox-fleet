//! Anchoring the audit chain outside the database.
//!
//! The service signs its chain head (sequence and event hash) with an
//! Ed25519 key that is kept out of the database. Signed heads are written
//! periodically to `FLEET_AUDIT_ANCHOR_DIR` (meant to be storage the database
//! administrator cannot rewrite, such as a write-once bucket mount) and served
//! to operators at `GET /v1/audit/head`. `sendbox-fleet admin audit verify
//! --anchor FILE` later proves the database still contains the anchored
//! events: a rewritten or truncated chain no longer reproduces the anchored
//! hash.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sendbox_governance::Sha256Digest;
use sendbox_security::provenance::{
    DetachedSignature, Identity, SignedSubject, SigningKeyMaterial, SubjectKind, TrustPolicy,
    TrustStore,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::audit::GENESIS_HASH;
use crate::db::{Arg, Database};
use crate::problem::Problem;
use crate::state::from_db;

pub const HEAD_FORMAT: &str = "sendbox-fleet-audit-head";
const HEAD_VERSION: u32 = 1;
const SUBJECT_NAME: &str = "audit-head";
const MAX_KEY_BYTES: u64 = 4 * 1024;

#[derive(Debug, Error)]
pub enum AnchorError {
    #[error("{0}")]
    Invalid(String),
    #[error("{context} {path}: {source}")]
    Io {
        context: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
}

/// The chain head at one point in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditHead {
    pub format: String,
    pub version: u32,
    pub authority_id: String,
    /// Number of events; `0` with the genesis hash for an empty log.
    pub sequence: u64,
    pub event_hash: Sha256Digest,
    pub signed_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuditHead {
    pub head: AuditHead,
    pub signature: DetachedSignature,
}

/// The service's audit signing key.
pub struct AuditSigner {
    key: SigningKeyMaterial,
    pub identity: Identity,
}

impl std::fmt::Debug for AuditSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuditSigner")
            .field("fingerprint", &self.identity.fingerprint)
            .finish_non_exhaustive()
    }
}

impl AuditSigner {
    /// Loads a key file written by `sendbox-fleet admin audit keygen` (or
    /// `sendbox governance keygen`). The file must not be readable by group
    /// or others.
    pub fn load(path: &Path) -> Result<Self, AnchorError> {
        let io = |source| AnchorError::Io {
            context: "read audit signing key",
            path: path.to_path_buf(),
            source,
        };
        let metadata = std::fs::metadata(path).map_err(io)?;
        if !metadata.is_file() || metadata.len() > MAX_KEY_BYTES {
            return Err(AnchorError::Invalid(format!(
                "{} is not a small regular file",
                path.display()
            )));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(AnchorError::Invalid(format!(
                "{} must not be accessible by group or others (chmod 600)",
                path.display()
            )));
        }
        let text = zeroize::Zeroizing::new(std::fs::read_to_string(path).map_err(io)?);
        let key = SigningKeyMaterial::import(text.trim())
            .map_err(|error| AnchorError::Invalid(format!("audit signing key: {error}")))?;
        Ok(Self::from_key(key))
    }

    #[must_use]
    pub fn from_key(key: SigningKeyMaterial) -> Self {
        let identity = key.identity("SendBox fleet audit", None, 0, None);
        Self { key, identity }
    }

    pub fn sign(&self, head: AuditHead) -> Result<SignedAuditHead, AnchorError> {
        let bytes = serde_json_canonicalizer::to_vec(&head)
            .map_err(|error| AnchorError::Invalid(error.to_string()))?;
        let signature = DetachedSignature::sign(
            SignedSubject::from_bytes(SubjectKind::Artifact, Some(SUBJECT_NAME.to_owned()), &bytes),
            &self.key,
            head.signed_at_unix,
            None,
            BTreeMap::from([("sequence".to_owned(), head.sequence.to_string())]),
        )
        .map_err(|error| AnchorError::Invalid(format!("sign audit head: {error}")))?;
        Ok(SignedAuditHead { head, signature })
    }
}

/// Reads the current chain head.
pub async fn current_head(
    database: &Database,
    authority_id: &str,
    now_unix: u64,
) -> Result<AuditHead, Problem> {
    let row = database
        .fetch_optional(
            "SELECT sequence, event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1",
            &[],
        )
        .await?;
    let (sequence, hash) = match row {
        Some(row) => (from_db(row.int("sequence")?)?, row.text("event_hash")?),
        None => (0, GENESIS_HASH.to_owned()),
    };
    Ok(AuditHead {
        format: HEAD_FORMAT.to_owned(),
        version: HEAD_VERSION,
        authority_id: authority_id.to_owned(),
        sequence,
        event_hash: Sha256Digest::parse_hex(&hash).map_err(|_| Problem::internal())?,
        signed_at_unix: now_unix,
    })
}

/// Writes `audit-head-<sequence>.json` once; an existing anchor for the same
/// sequence is never overwritten.
pub fn write_anchor(
    directory: &Path,
    signed: &SignedAuditHead,
) -> Result<Option<PathBuf>, AnchorError> {
    let path = directory.join(format!("audit-head-{:020}.json", signed.head.sequence));
    let bytes = serde_json::to_vec_pretty(signed)
        .map_err(|error| AnchorError::Invalid(error.to_string()))?;
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(None),
        Err(source) => {
            return Err(AnchorError::Io {
                context: "create audit anchor",
                path,
                source,
            });
        }
    };
    file.write_all(&bytes)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|source| AnchorError::Io {
            context: "write audit anchor",
            path: path.clone(),
            source,
        })?;
    Ok(Some(path))
}

/// Result of checking one anchor against the database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnchorCheck {
    pub file: String,
    pub sequence: u64,
    pub valid: bool,
    pub reason: Option<String>,
}

/// Verifies an anchor's signature against `identity` and that the database
/// still holds the same event hash at the anchored sequence.
pub async fn check_anchor(
    database: &Database,
    identity: &Identity,
    file: &Path,
) -> Result<AnchorCheck, AnchorError> {
    let bytes = std::fs::read(file).map_err(|source| AnchorError::Io {
        context: "read audit anchor",
        path: file.to_path_buf(),
        source,
    })?;
    let fail = |sequence, reason: String| AnchorCheck {
        file: file.display().to_string(),
        sequence,
        valid: false,
        reason: Some(reason),
    };
    let signed: SignedAuditHead = match serde_json::from_slice(&bytes) {
        Ok(signed) => signed,
        Err(error) => return Ok(fail(0, format!("not a signed audit head: {error}"))),
    };
    let head = &signed.head;
    if head.format != HEAD_FORMAT || head.version != HEAD_VERSION {
        return Ok(fail(head.sequence, "unsupported anchor format".to_owned()));
    }
    let mut trust = TrustStore::new(TrustPolicy {
        allow_unsigned: false,
        threshold: 1,
        required_signers: std::collections::BTreeSet::new(),
    });
    trust
        .add_identity(identity.clone())
        .map_err(|error| AnchorError::Invalid(format!("audit identity: {error}")))?;
    let canonical = serde_json_canonicalizer::to_vec(head)
        .map_err(|error| AnchorError::Invalid(error.to_string()))?;
    if let Err(error) = trust.verify(
        &canonical,
        SubjectKind::Artifact,
        std::slice::from_ref(&signed.signature),
        head.signed_at_unix,
    ) {
        return Ok(fail(head.sequence, format!("signature: {error}")));
    }
    if signed.signature.subject.name.as_deref() != Some(SUBJECT_NAME) {
        return Ok(fail(
            head.sequence,
            "signature names another subject".to_owned(),
        ));
    }
    let stored = if head.sequence == 0 {
        Some(GENESIS_HASH.to_owned())
    } else {
        database
            .fetch_optional(
                "SELECT event_hash FROM audit_events WHERE sequence = $1",
                &[Arg::from(i64::try_from(head.sequence).unwrap_or(i64::MAX))],
            )
            .await
            .map_err(|error| AnchorError::Invalid(error.to_string()))?
            .map(|row| row.text("event_hash"))
            .transpose()
            .map_err(|error| AnchorError::Invalid(error.to_string()))?
    };
    Ok(match stored {
        None => fail(
            head.sequence,
            "the database no longer holds this sequence".to_owned(),
        ),
        Some(hash) if hash != head.event_hash.to_string() => fail(
            head.sequence,
            "the database holds a different event at this sequence".to_owned(),
        ),
        Some(_) => AnchorCheck {
            file: file.display().to_string(),
            sequence: head.sequence,
            valid: true,
            reason: None,
        },
    })
}

/// Writes a signed head to `directory` whenever the chain advanced.
pub fn spawn_anchoring(
    database: Database,
    signer: Arc<AuditSigner>,
    authority_id: String,
    directory: PathBuf,
    interval: Duration,
    clock: Arc<dyn sendbox_governance::Clock>,
) -> tokio::task::JoinHandle<()> {
    actix_web::rt::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        let mut last = None;
        loop {
            ticker.tick().await;
            let head = match current_head(&database, &authority_id, clock.now_unix()).await {
                Ok(head) => head,
                Err(_) => {
                    tracing::warn!("cannot read the audit chain head for anchoring");
                    continue;
                }
            };
            if last == Some(head.sequence) {
                continue;
            }
            match signer
                .sign(head)
                .map(|signed| (signed.head.sequence, write_anchor(&directory, &signed)))
            {
                Ok((sequence, Ok(written))) => {
                    if let Some(path) = written {
                        tracing::info!(sequence, path = %path.display(), "audit chain head anchored");
                    }
                    last = Some(sequence);
                }
                Ok((_, Err(error))) | Err(error) => {
                    tracing::error!(%error, "audit chain head anchoring failed");
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(sequence: u64) -> AuditHead {
        AuditHead {
            format: HEAD_FORMAT.to_owned(),
            version: HEAD_VERSION,
            authority_id: "fleet.example.com".to_owned(),
            sequence,
            event_hash: Sha256Digest::of(b"event"),
            signed_at_unix: 1_800_000_000,
        }
    }

    #[test]
    fn anchors_are_written_once_and_keys_must_be_private() {
        let directory = tempfile::tempdir().unwrap();
        let signer = AuditSigner::from_key(SigningKeyMaterial::generate().unwrap());
        let signed = signer.sign(head(7)).unwrap();
        let path = write_anchor(directory.path(), &signed).unwrap().unwrap();
        assert!(path.ends_with("audit-head-00000000000000000007.json"));
        assert!(write_anchor(directory.path(), &signed).unwrap().is_none());

        let key = directory.path().join("audit.key");
        std::fs::write(
            &key,
            SigningKeyMaterial::generate().unwrap().export().as_bytes(),
        )
        .unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(AuditSigner::load(&key).is_err());
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(AuditSigner::load(&key).is_ok());
    }
}
