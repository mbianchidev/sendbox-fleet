//! OpenID Connect bearer tokens from configured identity providers.
//!
//! People and machine identities (for example GitHub Actions) present a
//! signed JWT. The service accepts it only when:
//!
//! - its `iss` exactly matches a configured issuer and its `aud` contains one
//!   of that issuer's audiences;
//! - its signature verifies with a key from the issuer's JWKS (fetched over
//!   HTTPS, cached, and refreshed when an unknown key id appears), using an
//!   algorithm the issuer allows (`RS256`, `ES256`, `EdDSA`);
//! - `exp` is in the future and `nbf`/`iat` are not, within a small leeway;
//! - required claims match exactly, and `email_verified` is true when the
//!   principal comes from `email`.
//!
//! The principal is `<principal_prefix>:<principal_claim value>` and must fit
//! the shared identifier grammar. Signatures are checked with `ring`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{self, UnparsedPublicKey};
use sendbox_governance::{Clock, PrincipalId};
use serde::Deserialize;
use serde_json::{Map, Value};
use thiserror::Error;

use crate::auth::CallerKind;
use crate::config::{ConfigError, OIDC_CONFIG_VAR};

const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_ISSUERS: usize = 16;
const MAX_DOCUMENT_BYTES: usize = 64 * 1024;
const MAX_JWKS_BYTES: usize = 256 * 1024;
const MAX_KEYS: usize = 64;
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const MAX_LEEWAY_SECONDS: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
pub enum Algorithm {
    RS256,
    ES256,
    EdDSA,
}

impl Algorithm {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "RS256" => Some(Self::RS256),
            "ES256" => Some(Self::ES256),
            "EdDSA" => Some(Self::EdDSA),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuerKind {
    User,
    Worker,
}

impl From<IssuerKind> for CallerKind {
    fn from(kind: IssuerKind) -> Self {
        match kind {
            IssuerKind::User => Self::User,
            IssuerKind::Worker => Self::Worker,
        }
    }
}

/// One trusted identity provider.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerConfig {
    /// Exact `iss` claim, for example `https://token.actions.githubusercontent.com`.
    pub issuer: String,
    /// Accepted `aud` values; at least one must be present in the token.
    pub audiences: Vec<String>,
    pub kind: IssuerKind,
    /// Claim that names the principal, such as `email`, `sub`, or `repository_id`.
    pub principal_claim: String,
    /// Prefix of the principal id, such as `oidc` or `github-actions`.
    pub principal_prefix: String,
    /// Defaults to true when `principal_claim` is `email`.
    #[serde(default)]
    pub require_email_verified: Option<bool>,
    /// Create unknown principals (with no roles) on first use.
    #[serde(default)]
    pub auto_provision: bool,
    /// Skips discovery when set.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default = "default_algorithms")]
    pub algorithms: Vec<Algorithm>,
    /// Claims that must equal these strings, for example
    /// `repository_owner: example` for GitHub Actions.
    #[serde(default)]
    pub required_claims: BTreeMap<String, String>,
    #[serde(default = "default_cache_seconds")]
    pub jwks_cache_seconds: u64,
    #[serde(default = "default_leeway_seconds")]
    pub leeway_seconds: u64,
}

fn default_algorithms() -> Vec<Algorithm> {
    vec![Algorithm::RS256, Algorithm::ES256, Algorithm::EdDSA]
}

const fn default_cache_seconds() -> u64 {
    600
}

const fn default_leeway_seconds() -> u64 {
    60
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    pub issuers: Vec<IssuerConfig>,
}

/// `https://`, or `http://` to a loopback host for local testing.
pub(crate) fn trusted_url(value: &str) -> Option<reqwest::Url> {
    let url = reqwest::Url::parse(value).ok()?;
    let loopback = match url.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    };
    let scheme_ok = url.scheme() == "https" || (url.scheme() == "http" && loopback);
    (scheme_ok && url.username().is_empty() && url.password().is_none() && url.fragment().is_none())
        .then_some(url)
}

impl OidcConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        use std::io::Read as _;
        let invalid = |reason: String| ConfigError::Invalid {
            name: OIDC_CONFIG_VAR,
            reason,
        };
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .and_then(|file| file.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes))
            .map_err(|error| invalid(format!("cannot read {}: {error}", path.display())))?;
        if bytes.len() as u64 > MAX_CONFIG_BYTES {
            return Err(invalid(format!("{} is too large", path.display())));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| invalid("must be UTF-8".to_owned()))?;
        let config: Self =
            serde_yaml_ng::from_str(text).map_err(|error| invalid(error.to_string()))?;
        config.validate().map_err(invalid)?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        if self.issuers.is_empty() || self.issuers.len() > MAX_ISSUERS {
            return Err(format!("list 1 to {MAX_ISSUERS} issuers"));
        }
        let mut issuers = BTreeSet::new();
        let mut prefixes = BTreeSet::new();
        for issuer in &self.issuers {
            let name = &issuer.issuer;
            if trusted_url(name).is_none() {
                return Err(format!(
                    "issuer `{name}` must be an https URL (http only for loopback)"
                ));
            }
            if !issuers.insert(name.as_str()) {
                return Err(format!("issuer `{name}` is listed twice"));
            }
            if issuer.audiences.is_empty()
                || issuer
                    .audiences
                    .iter()
                    .any(|audience| audience.is_empty() || audience.len() > 256)
            {
                return Err(format!("issuer `{name}` needs 1 or more bounded audiences"));
            }
            let prefix = &issuer.principal_prefix;
            let valid_prefix = !prefix.is_empty()
                && prefix.len() <= 32
                && prefix
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
                && prefix != "local-user";
            if !valid_prefix || !prefixes.insert(prefix.as_str()) {
                return Err(format!(
                    "issuer `{name}` needs a unique principal_prefix of 1-32 lowercase letters or `-`, not `local-user`"
                ));
            }
            if issuer.principal_claim.is_empty() || issuer.principal_claim.len() > 64 {
                return Err(format!("issuer `{name}` needs a principal_claim"));
            }
            if issuer.algorithms.is_empty() {
                return Err(format!("issuer `{name}` must allow at least one algorithm"));
            }
            if let Some(uri) = &issuer.jwks_uri
                && trusted_url(uri).is_none()
            {
                return Err(format!("issuer `{name}` jwks_uri must be an https URL"));
            }
            if !(60..=86_400).contains(&issuer.jwks_cache_seconds) {
                return Err(format!(
                    "issuer `{name}` jwks_cache_seconds must be 60..=86400"
                ));
            }
            if issuer.leeway_seconds > MAX_LEEWAY_SECONDS {
                return Err(format!(
                    "issuer `{name}` leeway_seconds must be at most {MAX_LEEWAY_SECONDS}"
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OidcError {
    /// The token is not acceptable; the caller should see `401`. The reason
    /// is a fixed code for the server log, never shown to the caller.
    #[error("identity token was not accepted: {0}")]
    Rejected(&'static str),
    /// The issuer's keys could not be fetched; the caller should see `503`.
    #[error("identity provider keys are unavailable")]
    Unavailable,
}

/// A validated identity-provider caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcIdentity {
    pub principal: PrincipalId,
    pub kind: CallerKind,
    pub issuer: String,
    pub auto_provision: bool,
}

#[derive(Debug, Clone)]
struct PublicKey {
    kid: Option<String>,
    algorithm: Algorithm,
    /// Encoded for `ring`: RSA (n, e), an uncompressed P-256 point, or raw
    /// Ed25519 bytes.
    material: KeyMaterial,
}

#[derive(Debug, Clone)]
enum KeyMaterial {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    Raw(Vec<u8>),
}

struct CachedKeys {
    keys: Vec<PublicKey>,
    fetched: Instant,
}

struct IssuerState {
    config: IssuerConfig,
    cache: tokio::sync::Mutex<Option<CachedKeys>>,
    last_refresh: Mutex<Option<Instant>>,
}

/// Validates bearer JWTs against the configured issuers.
pub struct OidcVerifier {
    issuers: Vec<IssuerState>,
    http: reqwest::Client,
    clock: Arc<dyn Clock>,
    min_refresh: Duration,
}

fn b64(value: &str) -> Result<Vec<u8>, OidcError> {
    if value.contains('=') {
        return Err(OidcError::Rejected("malformed"));
    }
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| OidcError::Rejected("malformed"))
}

fn object(bytes: &[u8]) -> Result<Map<String, Value>, OidcError> {
    match serde_json::from_slice(bytes) {
        Ok(Value::Object(map)) => Ok(map),
        _ => Err(OidcError::Rejected("malformed")),
    }
}

/// Parses one JWK, or `None` when it is unsupported or not a signing key.
fn parse_jwk(jwk: &Map<String, Value>) -> Option<PublicKey> {
    let text = |name: &str| jwk.get(name).and_then(Value::as_str);
    if text("use").is_some_and(|value| value != "sig") {
        return None;
    }
    let declared = text("alg").map(Algorithm::parse);
    let decode = |name: &str| text(name).and_then(|value| URL_SAFE_NO_PAD.decode(value).ok());
    let (algorithm, material) = match (text("kty")?, text("crv")) {
        ("RSA", _) => {
            let n = decode("n")?;
            if n.len() < 256 {
                return None;
            }
            (Algorithm::RS256, KeyMaterial::Rsa { n, e: decode("e")? })
        }
        ("EC", Some("P-256")) => {
            let (x, y) = (decode("x")?, decode("y")?);
            if x.len() != 32 || y.len() != 32 {
                return None;
            }
            let mut point = vec![0x04];
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            (Algorithm::ES256, KeyMaterial::Raw(point))
        }
        ("OKP", Some("Ed25519")) => {
            let x = decode("x")?;
            if x.len() != 32 {
                return None;
            }
            (Algorithm::EdDSA, KeyMaterial::Raw(x))
        }
        _ => return None,
    };
    if declared.is_some_and(|declared| declared != Some(algorithm)) {
        return None;
    }
    Some(PublicKey {
        kid: text("kid").map(str::to_owned),
        algorithm,
        material,
    })
}

/// Verifies a JWS signature with one public key.
fn verify_signature(key: &PublicKey, message: &[u8], signature_bytes: &[u8]) -> bool {
    match (&key.material, key.algorithm) {
        (KeyMaterial::Rsa { n, e }, Algorithm::RS256) => signature::RsaPublicKeyComponents { n, e }
            .verify(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                message,
                signature_bytes,
            )
            .is_ok(),
        (KeyMaterial::Raw(point), Algorithm::ES256) => {
            UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                .verify(message, signature_bytes)
                .is_ok()
        }
        (KeyMaterial::Raw(public), Algorithm::EdDSA) => {
            UnparsedPublicKey::new(&signature::ED25519, public)
                .verify(message, signature_bytes)
                .is_ok()
        }
        _ => false,
    }
}

impl OidcVerifier {
    pub fn new(config: OidcConfig, clock: Arc<dyn Clock>) -> Result<Self, ConfigError> {
        // reqwest is built without a bundled crypto provider; use ring, as the
        // rest of the service does. Installing twice is harmless.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(FETCH_TIMEOUT)
            .build()
            .map_err(|error| ConfigError::Invalid {
                name: OIDC_CONFIG_VAR,
                reason: format!("cannot build the HTTPS client: {error}"),
            })?;
        Ok(Self {
            issuers: config
                .issuers
                .into_iter()
                .map(|config| IssuerState {
                    config,
                    cache: tokio::sync::Mutex::new(None),
                    last_refresh: Mutex::new(None),
                })
                .collect(),
            http,
            clock,
            min_refresh: MIN_REFRESH_INTERVAL,
        })
    }

    /// Sets the minimum time between JWKS refreshes forced by unknown key
    /// ids (default 30 seconds).
    #[must_use]
    pub fn with_min_refresh_interval(mut self, interval: Duration) -> Self {
        self.min_refresh = interval;
        self
    }

    async fn fetch(&self, url: &str, limit: usize) -> Result<Map<String, Value>, OidcError> {
        let url = trusted_url(url).ok_or(OidcError::Unavailable)?;
        let response = self
            .http
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|error| {
                tracing::warn!(error = %error.without_url(), "identity provider request failed");
                OidcError::Unavailable
            })?;
        if !response.status().is_success() {
            tracing::warn!(status = %response.status(), "identity provider returned an error");
            return Err(OidcError::Unavailable);
        }
        if response
            .content_length()
            .is_some_and(|length| length > limit as u64)
        {
            return Err(OidcError::Unavailable);
        }
        let bytes = response.bytes().await.map_err(|_| OidcError::Unavailable)?;
        if bytes.len() > limit {
            return Err(OidcError::Unavailable);
        }
        object(&bytes).map_err(|_| OidcError::Unavailable)
    }

    async fn load_keys(&self, issuer: &IssuerConfig) -> Result<Vec<PublicKey>, OidcError> {
        let jwks_uri = match &issuer.jwks_uri {
            Some(uri) => uri.clone(),
            None => {
                let discovery = format!(
                    "{}/.well-known/openid-configuration",
                    issuer.issuer.trim_end_matches('/')
                );
                let document = self.fetch(&discovery, MAX_DOCUMENT_BYTES).await?;
                if document.get("issuer").and_then(Value::as_str) != Some(issuer.issuer.as_str()) {
                    tracing::warn!(issuer = %issuer.issuer, "discovery document names another issuer");
                    return Err(OidcError::Unavailable);
                }
                document
                    .get("jwks_uri")
                    .and_then(Value::as_str)
                    .ok_or(OidcError::Unavailable)?
                    .to_owned()
            }
        };
        let jwks = self.fetch(&jwks_uri, MAX_JWKS_BYTES).await?;
        let keys = jwks
            .get("keys")
            .and_then(Value::as_array)
            .ok_or(OidcError::Unavailable)?
            .iter()
            .take(MAX_KEYS)
            .filter_map(Value::as_object)
            .filter_map(parse_jwk)
            .filter(|key| issuer.algorithms.contains(&key.algorithm))
            .collect::<Vec<_>>();
        if keys.is_empty() {
            tracing::warn!(issuer = %issuer.issuer, "identity provider published no usable keys");
            return Err(OidcError::Unavailable);
        }
        Ok(keys)
    }

    /// Cached keys, refreshed after `jwks_cache_seconds` or (at most every
    /// 30 seconds) when `force` reports an unknown key id.
    async fn keys(&self, state: &IssuerState, force: bool) -> Result<Vec<PublicKey>, OidcError> {
        let mut cache = state.cache.lock().await;
        let ttl = Duration::from_secs(state.config.jwks_cache_seconds);
        let fresh = cache
            .as_ref()
            .is_some_and(|cached| cached.fetched.elapsed() < ttl);
        let may_refresh = {
            let mut last = state
                .last_refresh
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let allowed = last.is_none_or(|at| at.elapsed() >= self.min_refresh);
            if (!fresh || force) && allowed {
                *last = Some(Instant::now());
            }
            allowed
        };
        if (!fresh || force) && may_refresh {
            match self.load_keys(&state.config).await {
                Ok(keys) => {
                    *cache = Some(CachedKeys {
                        keys,
                        fetched: Instant::now(),
                    });
                }
                Err(error) if cache.is_none() || !fresh => return Err(error),
                Err(_) => {}
            }
        }
        cache
            .as_ref()
            .map(|cached| cached.keys.clone())
            .ok_or(OidcError::Unavailable)
    }

    /// Whether `token` looks like a compact JWS this verifier should handle.
    #[must_use]
    pub fn handles(token: &str) -> bool {
        token.split('.').count() == 3
    }

    pub async fn verify(&self, token: &str) -> Result<OidcIdentity, OidcError> {
        let mut parts = token.split('.');
        let (Some(header), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(OidcError::Rejected("malformed"));
        };
        let header_json = object(&b64(header)?)?;
        let claims = object(&b64(payload)?)?;
        let signature_bytes = b64(signature)?;
        if header_json.contains_key("crit") {
            return Err(OidcError::Rejected("critical_header"));
        }
        let algorithm = header_json
            .get("alg")
            .and_then(Value::as_str)
            .and_then(Algorithm::parse)
            .ok_or(OidcError::Rejected("unsupported_algorithm"))?;
        let kid = header_json.get("kid").and_then(Value::as_str);
        let issuer = claims
            .get("iss")
            .and_then(Value::as_str)
            .ok_or(OidcError::Rejected("missing_issuer"))?;
        let state = self
            .issuers
            .iter()
            .find(|state| state.config.issuer == issuer)
            .ok_or(OidcError::Rejected("unknown_issuer"))?;
        let config = &state.config;
        if !config.algorithms.contains(&algorithm) {
            return Err(OidcError::Rejected("algorithm_not_allowed"));
        }
        let message = &token.as_bytes()[..header.len() + 1 + payload.len()];
        let candidates = |keys: &[PublicKey]| {
            keys.iter()
                .filter(|key| {
                    key.algorithm == algorithm
                        && kid.is_none_or(|kid| key.kid.as_deref() == Some(kid))
                })
                .cloned()
                .collect::<Vec<_>>()
        };
        let mut matching = candidates(&self.keys(state, false).await?);
        if matching.is_empty() && kid.is_some() {
            matching = candidates(&self.keys(state, true).await?);
        }
        if matching.is_empty() {
            return Err(OidcError::Rejected("unknown_key"));
        }
        if kid.is_none() && matching.len() != 1 {
            return Err(OidcError::Rejected("ambiguous_key"));
        }
        if !matching
            .iter()
            .any(|key| verify_signature(key, message, &signature_bytes))
        {
            return Err(OidcError::Rejected("bad_signature"));
        }
        self.check_claims(config, &claims)?;
        let value = claims
            .get(&config.principal_claim)
            .and_then(|value| match value {
                Value::String(text) => Some(text.clone()),
                Value::Number(number) => Some(number.to_string()),
                _ => None,
            })
            .ok_or(OidcError::Rejected("missing_principal_claim"))?;
        let principal = PrincipalId::new(format!("{}:{value}", config.principal_prefix))
            .map_err(|_| OidcError::Rejected("invalid_principal"))?;
        Ok(OidcIdentity {
            principal,
            kind: config.kind.into(),
            issuer: config.issuer.clone(),
            auto_provision: config.auto_provision,
        })
    }

    fn check_claims(
        &self,
        config: &IssuerConfig,
        claims: &Map<String, Value>,
    ) -> Result<(), OidcError> {
        let now = self.clock.now_unix();
        let leeway = config.leeway_seconds;
        let time = |name: &str| claims.get(name).and_then(Value::as_u64);
        let expires = time("exp").ok_or(OidcError::Rejected("missing_expiry"))?;
        if now >= expires.saturating_add(leeway) {
            return Err(OidcError::Rejected("expired"));
        }
        if time("nbf").is_some_and(|not_before| now.saturating_add(leeway) < not_before)
            || time("iat").is_some_and(|issued| now.saturating_add(leeway) < issued)
            || claims.get("nbf").is_some_and(|value| !value.is_u64())
            || claims.get("iat").is_some_and(|value| !value.is_u64())
        {
            return Err(OidcError::Rejected("not_yet_valid"));
        }
        let audience_ok = match claims.get("aud") {
            Some(Value::String(audience)) => config.audiences.contains(audience),
            Some(Value::Array(audiences)) => audiences
                .iter()
                .filter_map(Value::as_str)
                .any(|audience| config.audiences.iter().any(|allowed| allowed == audience)),
            _ => false,
        };
        if !audience_ok {
            return Err(OidcError::Rejected("audience_mismatch"));
        }
        if !config
            .required_claims
            .iter()
            .all(|(name, expected)| claims.get(name).and_then(Value::as_str) == Some(expected))
        {
            return Err(OidcError::Rejected("required_claim_mismatch"));
        }
        let email_verified = config
            .require_email_verified
            .unwrap_or(config.principal_claim == "email");
        if email_verified && claims.get("email_verified") != Some(&Value::Bool(true)) {
            return Err(OidcError::Rejected("email_not_verified"));
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// RFC 7515 Appendix A.2: RS256 key and signature.
    #[test]
    fn rs256_signatures_verify_against_the_rfc_7515_example() {
        let jwk = serde_json::json!({
            "kty": "RSA",
            "n": "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
            "e": "AQAB"
        });
        let key = parse_jwk(jwk.as_object().unwrap()).expect("rsa key");
        let header = "eyJhbGciOiJSUzI1NiJ9";
        let payload = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
        let signature = "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";
        let message = format!("{header}.{payload}");
        let bytes = URL_SAFE_NO_PAD.decode(signature).unwrap();
        assert!(verify_signature(&key, message.as_bytes(), &bytes));
        assert!(!verify_signature(&key, b"tampered", &bytes));
    }

    #[test]
    fn jwks_reject_mismatched_or_weak_keys() {
        let ed = |x: &str, alg: &str| serde_json::json!({ "kty": "OKP", "crv": "Ed25519", "x": x, "alg": alg });
        let x = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        assert!(parse_jwk(ed(&x, "EdDSA").as_object().unwrap()).is_some());
        assert!(parse_jwk(ed(&x, "RS256").as_object().unwrap()).is_none());
        let short = URL_SAFE_NO_PAD.encode([7_u8; 31]);
        assert!(parse_jwk(ed(&short, "EdDSA").as_object().unwrap()).is_none());
        let weak_rsa = serde_json::json!({
            "kty": "RSA", "n": URL_SAFE_NO_PAD.encode([1_u8; 128]), "e": "AQAB"
        });
        assert!(parse_jwk(weak_rsa.as_object().unwrap()).is_none());
        let encryption = serde_json::json!({
            "kty": "OKP", "crv": "Ed25519", "x": x, "use": "enc"
        });
        assert!(parse_jwk(encryption.as_object().unwrap()).is_none());
    }

    #[test]
    fn issuer_configuration_is_validated() {
        let issuer = |name: &str, prefix: &str| IssuerConfig {
            issuer: name.to_owned(),
            audiences: vec!["sendbox-fleet".to_owned()],
            kind: IssuerKind::User,
            principal_claim: "email".to_owned(),
            principal_prefix: prefix.to_owned(),
            require_email_verified: None,
            auto_provision: false,
            jwks_uri: None,
            algorithms: default_algorithms(),
            required_claims: BTreeMap::new(),
            jwks_cache_seconds: 600,
            leeway_seconds: 60,
        };
        let valid = OidcConfig {
            issuers: vec![
                issuer("https://login.example.com", "oidc"),
                issuer("http://127.0.0.1:9000", "ci"),
            ],
        };
        assert!(valid.validate().is_ok());
        for broken in [
            vec![issuer("http://login.example.com", "oidc")],
            vec![issuer("https://login.example.com", "local-user")],
            vec![
                issuer("https://a.example.com", "oidc"),
                issuer("https://b.example.com", "oidc"),
            ],
            vec![],
        ] {
            assert!(OidcConfig { issuers: broken }.validate().is_err());
        }
    }
}
