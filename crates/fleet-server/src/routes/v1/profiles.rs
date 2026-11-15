//! Governance profiles: read the current revision or publish a signed one.

use std::collections::BTreeSet;

use actix_web::web;
use sendbox_governance::{GovernanceProfile, ProfileId, ProfileRef};
use serde::{Deserialize, Serialize};

use super::{Capability, invalid};
use crate::auth::Authenticated;
use crate::problem::Problem;
use crate::routes::{json_config, resource};

/// Generous enough for a maximum-size profile document after JSON escaping.
const PUBLICATION_LIMIT_BYTES: usize = 1024 * 1024;
const MAX_SIGNATURES: usize = 16;
const MAX_KEY_ID_BYTES: usize = 128;
const MAX_SIGNATURE_BYTES: usize = 2048;

/// A profile revision as published by an operator: the exact signed YAML
/// document plus detached signatures over its bytes. The signature envelope is
/// a placeholder until the shared contract defines the operator signing
/// format; signatures are stored but not verified by this scaffold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfilePublication {
    pub document: String,
    pub signatures: Vec<ProfileSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSignature {
    pub key_id: String,
    /// Standard base64 signature over the exact document bytes.
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRecord {
    pub reference: ProfileRef,
    pub minimum_revision: u64,
    pub not_before_unix: u64,
    pub expires_at_unix: u64,
    pub document: String,
    pub signatures: Vec<ProfileSignature>,
}

impl ProfilePublication {
    /// Parses the document with the shared contract and checks the envelope.
    pub fn validate(&self, path_id: &ProfileId) -> Result<GovernanceProfile, Problem> {
        let profile = GovernanceProfile::parse(self.document.as_bytes()).map_err(invalid)?;
        if &profile.id != path_id {
            return Err(Problem::bad_request(format!(
                "profile document id `{}` does not match the request path id `{path_id}`",
                profile.id
            )));
        }
        if self.signatures.is_empty() || self.signatures.len() > MAX_SIGNATURES {
            return Err(Problem::bad_request(format!(
                "a publication needs 1 to {MAX_SIGNATURES} signatures"
            )));
        }
        let mut key_ids = BTreeSet::new();
        for signature in &self.signatures {
            let key_id = &signature.key_id;
            if key_id.is_empty()
                || key_id.len() > MAX_KEY_ID_BYTES
                || !key_id.bytes().all(|byte| byte.is_ascii_graphic())
            {
                return Err(Problem::bad_request(format!(
                    "signature key_id must be 1 to {MAX_KEY_ID_BYTES} printable ASCII bytes"
                )));
            }
            if !key_ids.insert(key_id) {
                return Err(Problem::bad_request(format!(
                    "signature key_id `{key_id}` appears more than once"
                )));
            }
            if !valid_base64(&signature.signature) {
                return Err(Problem::bad_request(format!(
                    "signature for `{key_id}` must be 1 to {MAX_SIGNATURE_BYTES} bytes of padded standard base64"
                )));
            }
        }
        Ok(profile)
    }
}

fn valid_base64(value: &str) -> bool {
    let body = value.trim_end_matches('=');
    !value.is_empty()
        && value.len() <= MAX_SIGNATURE_BYTES
        && value.len().is_multiple_of(4)
        && value.len() - body.len() <= 2
        && body
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
}

pub fn configure(config: &mut web::ServiceConfig) {
    config.service(
        resource("/profiles/{profile_id}")
            .app_data(json_config(PUBLICATION_LIMIT_BYTES))
            .route(web::get().to(read))
            .route(web::put().to(publish)),
    );
}

async fn read(
    _caller: Authenticated,
    _profile: web::Path<ProfileId>,
) -> Result<web::Json<ProfileRecord>, Problem> {
    Err(Capability::ProfileRead.problem())
}

async fn publish(
    _caller: Authenticated,
    profile: web::Path<ProfileId>,
    publication: web::Json<ProfilePublication>,
) -> Result<web::Json<ProfileRecord>, Problem> {
    publication.validate(&profile)?;
    Err(Capability::ProfilePublication.problem())
}
