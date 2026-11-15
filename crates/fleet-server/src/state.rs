//! Shared application state: storage, time, identity of this authority, and
//! the trust that verifies published profiles.

use std::sync::Arc;

use sendbox_governance::{Clock, GovernanceError};
use sendbox_security::provenance::TrustStore;

use crate::config::TokenLimits;
use crate::db::Database;
use crate::problem::Problem;

pub type RandomSource = dyn Fn() -> Result<[u8; 16], GovernanceError> + Send + Sync;

pub struct AppState {
    pub database: Database,
    pub clock: Arc<dyn Clock>,
    pub random: Arc<RandomSource>,
    /// Must equal `GovernanceBinding.authority.id` in every admitted session.
    pub authority_id: String,
    /// Operator signers that profile publications must satisfy. Publication
    /// is refused while this is unset.
    pub profile_trust: Option<TrustStore>,
    pub tokens: TokenLimits,
    /// Signs audit chain heads; `None` disables `GET /v1/audit/head`.
    pub audit_signer: Option<Arc<crate::anchor::AuditSigner>>,
    pub limits: Arc<crate::ratelimit::Limits>,
}

impl AppState {
    #[must_use]
    pub fn now(&self) -> u64 {
        self.clock.now_unix()
    }

    /// A fresh random identifier as 32 lowercase hex characters.
    pub fn new_id(&self) -> Result<[u8; 16], Problem> {
        (self.random)().map_err(|error| {
            tracing::error!(%error, "random identifier generation failed");
            Problem::internal()
        })
    }
}

/// Random bytes from the operating system.
pub fn os_random() -> Result<[u8; 16], GovernanceError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|error| GovernanceError::AuthorityUnavailable(error.to_string()))?;
    Ok(bytes)
}

/// Signed 64-bit storage for unsigned contract times and counters.
pub fn to_db(value: u64) -> Result<i64, Problem> {
    i64::try_from(value).map_err(|_| Problem::bad_request("a number is out of range"))
}

/// Reads a stored non-negative number back into the contract's `u64`.
pub fn from_db(value: i64) -> Result<u64, Problem> {
    u64::try_from(value).map_err(|_| {
        tracing::error!(value, "stored number is negative");
        Problem::internal()
    })
}
