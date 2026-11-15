//! HTTP behaviour of the shared governance service: authentication before
//! validation, project roles, signed profiles, session admission, grants,
//! authorization, exceptions, the audit chain, identity-provider sign-in,
//! token exchange, signed audit heads, and rate limits. All data and keys are
//! synthetic.
//!
//! Runs against in-memory SQLite by default. Set `FLEET_TEST_DATABASE_URL` to
//! a PostgreSQL database whose name ends in `_test` to run the same requests
//! against PostgreSQL; its `public` schema is dropped and recreated by every
//! test, so run with `--test-threads=1`.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use actix_web::body::MessageBody;
use actix_web::dev::{Service, ServiceResponse};
use actix_web::http::{Method, StatusCode, header};
use actix_web::{App, HttpResponse, HttpServer, test, web};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use fleet_server::anchor::{self, AuditSigner};
use fleet_server::auth::{self, FleetAuthenticator, token_from_bytes};
use fleet_server::config::{DatabaseUrl, TokenLimits};
use fleet_server::db::{Arg, Database};
use fleet_server::oidc::{OidcConfig, OidcVerifier};
use fleet_server::ratelimit::{Limits, RateLimiter};
use fleet_server::server;
use fleet_server::state::AppState;
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair as _,
};
use sendbox_governance::{
    AuthorityRef, CONTRACT_VERSION, Clock, ExceptionId, GovernanceBinding, PrincipalId, ProfileRef,
    ProjectId, ServiceId, SessionRef, Sha256Digest,
};
use sendbox_security::provenance::{
    DetachedSignature, SignedSubject, SigningKeyMaterial, SubjectKind, TrustPolicy, TrustStore,
};
use serde_json::{Value, json};

const NOW: u64 = 1_800_000_000;
const AUTHORITY: &str = "fleet.example.com";
const PROJECT: &str = "github:example/service";
const PROJECT_PATH: &str = "github:example%2Fservice";

const OPERATOR: &str = "oidc:olivia@example.com";
const OWNER: &str = "oidc:owen@example.com";
const ADMIN: &str = "oidc:ada@example.com";
const MEMBER: &str = "oidc:alice@example.com";
const BOB: &str = "oidc:bob@example.com";
const VIEWER: &str = "oidc:vera@example.com";
const WORKER: &str = "worker:ci-1";
const OUTSIDER: &str = "oidc:mallory@example.com";

struct TestClock(AtomicU64);

impl Clock for TestClock {
    fn now_unix(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn profile_yaml(revision: u64) -> String {
    format!(
        r#"format: sendbox.governance-profile
version: 1
id: acme
revision: {revision}
not_before_unix: {}
expires_at_unix: {}
ceiling:
  runtimes: [apple, kata]
  commands:
    default_action: deny
    allowlist: ["git *"]
  network:
    default_action: deny
    allowed_domains: ["*.github.com"]
denials:
  commands: ["git push --force *"]
  domains: [gist.github.com, pastebin.com]
credential_services:
  - id: anthropic
    provider: anthropic
    secret: SENDBOX_ANTHROPIC_API_KEY
grants:
  lease_seconds: 60
  max_ttl_seconds: 3600
  revocation_grace_seconds: 5
  max_concurrent_streams: 4
exceptions:
  max_ttl_seconds: 86400
  commands: ["git push --force *"]
  domains: [gist.github.com]
"#,
        NOW - 100,
        NOW + 30 * 86_400
    )
}

fn publication(document: &str, key: &SigningKeyMaterial) -> Value {
    let signature = DetachedSignature::sign(
        SignedSubject::from_bytes(SubjectKind::Configuration, None, document.as_bytes()),
        key,
        NOW - 10,
        None,
        BTreeMap::new(),
    )
    .unwrap();
    json!({
        "document": document,
        "signatures": {
            "format": "sendbox.governance-signatures",
            "version": 1,
            "signatures": [signature],
        }
    })
}

struct Fleet<S> {
    service: S,
    database: Database,
    clock: Arc<TestClock>,
    key: SigningKeyMaterial,
    tokens: HashMap<&'static str, String>,
    audit_signer: Option<Arc<AuditSigner>>,
}

/// Optional features; everything is off by default.
#[derive(Default)]
struct Setup {
    oidc: Option<OidcConfig>,
    audit_signer: Option<Arc<AuditSigner>>,
    /// Per-principal requests and per-peer failures per minute.
    limits: (u32, u32),
}

async fn fleet() -> Fleet<
    impl Service<
        actix_http::Request,
        Response = ServiceResponse<impl MessageBody>,
        Error = actix_web::Error,
    >,
> {
    fleet_with(Setup::default()).await
}

async fn fleet_with(
    setup: Setup,
) -> Fleet<
    impl Service<
        actix_http::Request,
        Response = ServiceResponse<impl MessageBody>,
        Error = actix_web::Error,
    >,
> {
    let url =
        std::env::var("FLEET_TEST_DATABASE_URL").unwrap_or_else(|_| "sqlite::memory:".to_owned());
    let database = Database::connect(&DatabaseUrl::parse(&url).unwrap())
        .await
        .unwrap();
    if let Database::Postgres(pool) = &database {
        let name: String = sqlx::query_scalar("SELECT current_database()")
            .fetch_one(pool)
            .await
            .unwrap();
        assert!(
            name.ends_with("_test"),
            "refusing to reset database `{name}`: FLEET_TEST_DATABASE_URL must name a database ending in `_test`"
        );
        sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
            .execute(pool)
            .await
            .unwrap();
    }
    database.migrate().await.unwrap();
    let clock = Arc::new(TestClock(AtomicU64::new(NOW)));
    let key = SigningKeyMaterial::generate().unwrap();
    let mut trust = TrustStore::new(TrustPolicy {
        allow_unsigned: false,
        threshold: 1,
        required_signers: Default::default(),
    });
    trust
        .add_identity(key.identity("Example operator", None, 0, None))
        .unwrap();

    let mut tokens = HashMap::new();
    let mut tx = database.begin_write().await.unwrap();
    for (index, (principal, kind, operator)) in [
        (OPERATOR, "user", true),
        (OWNER, "user", false),
        (ADMIN, "user", false),
        (MEMBER, "user", false),
        (BOB, "user", false),
        (VIEWER, "user", false),
        (WORKER, "worker", false),
        (OUTSIDER, "user", false),
    ]
    .into_iter()
    .enumerate()
    {
        tx.execute(
            "INSERT INTO principals (id, kind, created_at_unix, is_operator) VALUES ($1, $2, $3, $4)",
            &[principal.into(), kind.into(), Arg::from(0_i64), operator.into()],
        )
        .await
        .unwrap();
        let byte = u8::try_from(index).unwrap() + 1;
        let (token, digest) = token_from_bytes(&[byte; 32]);
        tx.execute(
            "INSERT INTO api_tokens (id, principal_id, token_sha256, created_at_unix, \
             expires_at_unix) VALUES ($1, $2, $3, $4, $5)",
            &[
                format!("{byte:02x}").repeat(16).into(),
                principal.into(),
                digest.into(),
                Arg::from(i64::try_from(NOW - 10).unwrap()),
                Arg::from(i64::try_from(NOW + 7 * 86_400).unwrap()),
            ],
        )
        .await
        .unwrap();
        tokens.insert(principal, token);
    }
    tx.commit().await.unwrap();

    let state = web::Data::new(AppState {
        database: database.clone(),
        clock: clock.clone(),
        random: Arc::new(fleet_server::state::os_random),
        authority_id: AUTHORITY.to_owned(),
        profile_trust: Some(trust),
        tokens: TokenLimits::default(),
        audit_signer: setup.audit_signer.clone(),
        limits: Arc::new(Limits {
            requests: RateLimiter::new(setup.limits.0),
            auth_failures: RateLimiter::new(setup.limits.1),
        }),
    });
    let oidc = setup.oidc.map(|config| {
        OidcVerifier::new(config, clock.clone())
            .unwrap()
            .with_min_refresh_interval(Duration::ZERO)
    });
    let authenticator = auth::shared(Arc::new(FleetAuthenticator::new(
        database.clone(),
        clock.clone(),
        oidc,
    )));
    let service = test::init_service(server::app(state, authenticator)).await;
    Fleet {
        service,
        database,
        clock,
        key,
        tokens,
        audit_signer: setup.audit_signer,
    }
}

impl<S, B> Fleet<S>
where
    S: Service<actix_http::Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: MessageBody,
{
    async fn send(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> (StatusCode, Value) {
        let (status, _, value) = self.respond(None, method, path, token, body).await;
        (status, value)
    }

    /// Sends a request from `peer` and returns the headers as well.
    async fn respond(
        &self,
        peer: Option<&str>,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> (StatusCode, header::HeaderMap, Value) {
        let mut request = test::TestRequest::default().method(method).uri(path);
        if let Some(peer) = peer {
            request = request.peer_addr(peer.parse().unwrap());
        }
        if let Some(token) = token {
            request = request.insert_header((header::AUTHORIZATION, format!("Bearer {token}")));
        }
        let request = match body {
            Some(body) => request.set_json(body).to_request(),
            None => request.to_request(),
        };
        let response = test::call_service(&self.service, request).await;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = test::read_body(response).await;
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        if status.is_client_error() || status.is_server_error() {
            assert_eq!(value["status"], status.as_u16(), "{value}");
            assert!(
                value["detail"]
                    .as_str()
                    .is_some_and(|detail| !detail.is_empty())
            );
        }
        (status, headers, value)
    }

    async fn call(
        &self,
        as_: &str,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let token = self.tokens.get(as_).map(String::as_str);
        self.send(method, path, token, body.as_ref()).await
    }

    fn advance(&self, seconds: u64) {
        self.clock.0.fetch_add(seconds, Ordering::SeqCst);
    }

    fn now(&self) -> u64 {
        self.clock.now_unix()
    }

    async fn publish(&self, revision: u64) -> ProfileRef {
        let (status, body) = self
            .call(
                OPERATOR,
                Method::PUT,
                "/v1/profiles/acme",
                Some(publication(&profile_yaml(revision), &self.key)),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        serde_json::from_value(body["reference"].clone()).unwrap()
    }

    /// A project with an owner, an admin, two members, a viewer, and a worker.
    async fn project(&self) -> ProfileRef {
        let profile = self.publish(3).await;
        let (status, body) = self
            .call(
                OPERATOR,
                Method::POST,
                "/v1/projects",
                Some(json!({ "project": PROJECT, "owner": OWNER })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        for (principal, role) in [
            (ADMIN, "admin"),
            (MEMBER, "member"),
            (BOB, "member"),
            (VIEWER, "viewer"),
            (WORKER, "member"),
        ] {
            let (status, body) = self
                .call(
                    OWNER,
                    Method::POST,
                    &format!("/v1/projects/{PROJECT_PATH}/roles"),
                    Some(json!({ "principal": principal, "role": role })),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
        }
        profile
    }

    async fn request_exception(
        &self,
        as_: &str,
        profile: &ProfileRef,
        kind: &str,
        value: &str,
    ) -> (StatusCode, Value) {
        self.call(
            as_,
            Method::POST,
            "/v1/exceptions",
            Some(json!({
                "project": PROJECT,
                "profile": profile,
                "scope": { "kind": kind, "value": value },
                "reason": "Synthetic release window",
                "expires_at_unix": self.now() + 3_600,
            })),
        )
        .await
    }

    async fn approved_exception(&self, profile: &ProfileRef) -> ExceptionId {
        let (status, body) = self
            .request_exception(MEMBER, profile, "domain", "gist.github.com")
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let id: ExceptionId = serde_json::from_value(body["id"].clone()).unwrap();
        let (status, body) = self
            .call(
                ADMIN,
                Method::POST,
                &format!("/v1/exceptions/{id}:approve"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        id
    }

    async fn admit(
        &self,
        as_: &str,
        binding: &GovernanceBinding,
        session: &SessionRef,
    ) -> (StatusCode, Value) {
        self.call(
            as_,
            Method::POST,
            "/v1/sessions:admit",
            Some(json!({ "session": session, "binding": binding })),
        )
        .await
    }

    async fn events(&self, query: &str) -> Vec<Value> {
        let (status, body) = self
            .call(
                OPERATOR,
                Method::GET,
                &format!("/v1/audit/events?{query}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["events"].as_array().unwrap().clone()
    }
}

fn binding(
    principal: &str,
    profile: &ProfileRef,
    exceptions: Vec<ExceptionId>,
) -> GovernanceBinding {
    GovernanceBinding {
        contract_version: CONTRACT_VERSION,
        authority: AuthorityRef {
            id: AUTHORITY.to_owned(),
            trust_sha256: Sha256Digest::of(b"operator trust"),
        },
        profile: profile.clone(),
        principal: PrincipalId::new(principal).unwrap(),
        project: ProjectId::new(PROJECT).unwrap(),
        effective_policy_sha256: Sha256Digest::of(b"effective policy"),
        brokered_services: vec![ServiceId::new("anthropic").unwrap()],
        exceptions,
    }
}

fn session(byte: char) -> SessionRef {
    SessionRef::new(byte.to_string().repeat(32)).unwrap()
}

fn grant_request(binding: &GovernanceBinding, session: &SessionRef) -> Value {
    json!({
        "principal": binding.principal,
        "project": binding.project,
        "session": session,
        "binding": binding,
        "service": "anthropic",
        "methods": ["POST"],
        "path_prefixes": ["/v1/messages"],
        "max_ttl_seconds": 3_600,
    })
}

fn context(grant: &Value, path: &str) -> Value {
    json!({
        "grant_id": grant["grant_id"],
        "principal": grant["principal"],
        "project": grant["project"],
        "session": grant["session"],
        "binding_sha256": grant["binding_sha256"],
        "service": "anthropic",
        "method": "POST",
        "path": path,
    })
}

fn decision(body: &Value) -> &str {
    match body["decision"].as_str() {
        Some("allow") => "allow",
        _ => body["reason"].as_str().unwrap_or("?"),
    }
}

#[actix_web::test]
async fn health_and_readiness_report_status() {
    let fleet = fleet().await;
    for (path, status) in [("/healthz", "ok"), ("/readyz", "ready")] {
        let (code, body) = fleet.send(Method::GET, path, None, None).await;
        assert_eq!(code, StatusCode::OK, "{path}");
        assert_eq!(body, json!({ "status": status }));
    }
    fleet.database.close().await;
    let (code, _) = fleet.send(Method::GET, "/readyz", None, None).await;
    assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
    let (code, _) = fleet.send(Method::GET, "/healthz", None, None).await;
    assert_eq!(code, StatusCode::OK);
}

#[actix_web::test]
async fn every_v1_route_requires_a_valid_bearer_token() {
    let fleet = fleet().await;
    let routes = [
        (Method::GET, "/v1/whoami"),
        (Method::POST, "/v1/sessions:admit"),
        (
            Method::POST,
            "/v1/sessions/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:end",
        ),
        (Method::POST, "/v1/grants"),
        (
            Method::POST,
            "/v1/grants/fedcba9876543210fedcba9876543210:renew",
        ),
        (
            Method::POST,
            "/v1/grants/fedcba9876543210fedcba9876543210:revoke",
        ),
        (Method::POST, "/v1/authorize"),
        (Method::GET, "/v1/profiles/acme"),
        (Method::PUT, "/v1/profiles/acme"),
        (Method::PUT, "/v1/profiles/acme/minimum-revision"),
        (Method::POST, "/v1/projects"),
        (Method::GET, "/v1/projects/github:example%2Fservice/roles"),
        (Method::POST, "/v1/projects/github:example%2Fservice/roles"),
        (
            Method::DELETE,
            "/v1/projects/github:example%2Fservice/roles/oidc:bob@example.com",
        ),
        (Method::POST, "/v1/exceptions"),
        (
            Method::GET,
            "/v1/exceptions?project=github:example%2Fservice",
        ),
        (
            Method::POST,
            "/v1/exceptions/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:approve",
        ),
        (Method::GET, "/v1/audit/events"),
        (Method::GET, "/v1/audit/verify"),
    ];
    for (method, path) in routes {
        for token in [None, Some("wrong-token"), Some("sbf_unknown")] {
            let (status, _) = fleet
                .send(method.clone(), path, token, Some(&json!({})))
                .await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{method} {path} {token:?}"
            );
        }
    }
    for (name, value) in [
        ("x-forwarded-user", MEMBER),
        ("x-sendbox-principal", OPERATOR),
        ("authorization", "Basic YWxpY2U6c2VjcmV0"),
    ] {
        let request = test::TestRequest::get()
            .uri("/v1/whoami")
            .insert_header((name, value))
            .to_request();
        let response = test::call_service(&fleet.service, request).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{name}");
    }
}

#[actix_web::test]
async fn tokens_authenticate_until_expired_revoked_or_disabled() {
    let fleet = fleet().await;
    let (status, body) = fleet.call(OPERATOR, Method::GET, "/v1/whoami", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({ "principal": OPERATOR, "kind": "user", "operator": true })
    );
    let (_, body) = fleet.call(WORKER, Method::GET, "/v1/whoami", None).await;
    assert_eq!(body["kind"], "worker");

    let mut tx = fleet.database.begin_write().await.unwrap();
    tx.execute(
        "UPDATE api_tokens SET revoked_at_unix = $2 WHERE principal_id = $1",
        &[MEMBER.into(), Arg::from(i64::try_from(NOW).unwrap())],
    )
    .await
    .unwrap();
    tx.execute(
        "UPDATE principals SET disabled_at_unix = 1 WHERE id = $1",
        &[BOB.into()],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    for principal in [MEMBER, BOB] {
        let (status, _) = fleet.call(principal, Method::GET, "/v1/whoami", None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{principal}");
    }
    fleet.advance(7 * 86_400);
    let (status, _) = fleet.call(OPERATOR, Method::GET, "/v1/whoami", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "expired");
}

#[actix_web::test]
async fn only_operators_publish_verified_profiles_and_minimums_only_rise() {
    let fleet = fleet().await;
    let document = profile_yaml(3);
    let (status, _) = fleet
        .call(
            OWNER,
            Method::PUT,
            "/v1/profiles/acme",
            Some(publication(&document, &fleet.key)),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let other = SigningKeyMaterial::generate().unwrap();
    let (status, _) = fleet
        .call(
            OPERATOR,
            Method::PUT,
            "/v1/profiles/acme",
            Some(publication(&document, &other)),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unknown signer");
    let mut tampered = publication(&document, &fleet.key);
    tampered["document"] = json!(document.replace("pastebin.com", "example.org"));
    let (status, _) = fleet
        .call(OPERATOR, Method::PUT, "/v1/profiles/acme", Some(tampered))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "tampered bytes");
    let (status, _) = fleet
        .call(
            OPERATOR,
            Method::PUT,
            "/v1/profiles/other",
            Some(publication(&document, &fleet.key)),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "path and document ids differ"
    );

    let third = fleet.publish(3).await;
    assert_eq!(third.sha256, Sha256Digest::of(document.as_bytes()));
    let (status, _) = fleet
        .call(
            OPERATOR,
            Method::PUT,
            "/v1/profiles/acme",
            Some(publication(&document, &fleet.key)),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "revisions only increase");
    let fourth = fleet.publish(4).await;
    let (status, body) = fleet
        .call(MEMBER, Method::GET, "/v1/profiles/acme", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["reference"], json!(fourth));
    assert_eq!(body["document"], profile_yaml(4));
    let (_, body) = fleet
        .call(MEMBER, Method::GET, "/v1/profiles/acme?revision=3", None)
        .await;
    assert_eq!(body["reference"], json!(third));

    let minimum = |revision: u64| json!({ "revision": revision, "reason": "Rotate after review" });
    let (status, _) = fleet
        .call(
            OWNER,
            Method::PUT,
            "/v1/profiles/acme/minimum-revision",
            Some(minimum(4)),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = fleet
        .call(
            OPERATOR,
            Method::PUT,
            "/v1/profiles/acme/minimum-revision",
            Some(minimum(4)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["minimum_revision"], 4);
    let (status, _) = fleet
        .call(
            OPERATOR,
            Method::PUT,
            "/v1/profiles/acme/minimum-revision",
            Some(minimum(3)),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "minimums never decrease");
}

#[actix_web::test]
async fn project_roles_are_enforced_and_every_change_is_attributed() {
    let fleet = fleet().await;
    let create = json!({ "project": PROJECT, "owner": OWNER });
    let (status, _) = fleet
        .call(OWNER, Method::POST, "/v1/projects", Some(create.clone()))
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "only operators create projects"
    );
    fleet.project().await;
    let (status, _) = fleet
        .call(OPERATOR, Method::POST, "/v1/projects", Some(create))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let roles = format!("/v1/projects/{PROJECT_PATH}/roles");
    let assign =
        |principal: &str, role: &str| Some(json!({ "principal": principal, "role": role }));
    for (caller, status) in [
        (ADMIN, StatusCode::FORBIDDEN),
        (MEMBER, StatusCode::FORBIDDEN),
        (WORKER, StatusCode::FORBIDDEN),
        (OUTSIDER, StatusCode::FORBIDDEN),
    ] {
        let (code, _) = fleet
            .call(caller, Method::POST, &roles, assign(OUTSIDER, "owner"))
            .await;
        assert_eq!(code, status, "{caller}");
    }
    let (status, _) = fleet
        .call(
            OWNER,
            Method::POST,
            &roles,
            assign("local-user:501", "member"),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = fleet
        .call(OWNER, Method::POST, &roles, assign(OWNER, "admin"))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "last owner");
    let (status, _) = fleet
        .call(OWNER, Method::DELETE, &format!("{roles}/{OWNER}"), None)
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "last owner");
    let (status, body) = fleet
        .call(OWNER, Method::POST, &roles, assign(ADMIN, "owner"))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = fleet
        .call(ADMIN, Method::DELETE, &format!("{roles}/{BOB}"), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        !body["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["principal"] == BOB)
    );

    let (status, body) = fleet.call(VIEWER, Method::GET, &roles, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["bindings"].as_array().unwrap().len(), 5);
    let (status, _) = fleet.call(OUTSIDER, Method::GET, &roles, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = fleet
        .call(
            OPERATOR,
            Method::GET,
            "/v1/projects/github:example%2Fmissing/roles",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let events = fleet.events(&format!("project={PROJECT_PATH}")).await;
    let summary = events
        .iter()
        .map(|event| {
            (
                event["event_type"].as_str().unwrap().to_owned(),
                event["actor"].as_str().unwrap_or_default().to_owned(),
                event["principal"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect::<Vec<_>>();
    assert!(summary.contains(&("project.created".into(), OPERATOR.into(), String::new())));
    assert!(summary.contains(&("role.assigned".into(), OWNER.into(), WORKER.into())));
    assert!(summary.contains(&("role.change_refused".into(), MEMBER.into(), OUTSIDER.into())));
    assert!(summary.contains(&("role.removed".into(), ADMIN.into(), BOB.into())));
}

#[actix_web::test]
async fn exceptions_need_a_different_authorized_approver_within_the_profile() {
    let fleet = fleet().await;
    let profile = fleet.project().await;

    for (caller, status) in [
        (VIEWER, StatusCode::FORBIDDEN),
        (OUTSIDER, StatusCode::FORBIDDEN),
        (WORKER, StatusCode::FORBIDDEN),
    ] {
        let (code, _) = fleet
            .request_exception(caller, &profile, "domain", "gist.github.com")
            .await;
        assert_eq!(code, status, "{caller}");
    }
    let (status, _) = fleet
        .request_exception(MEMBER, &profile, "domain", "pastebin.com")
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "not liftable in the profile");
    let (status, _) = fleet
        .request_exception(MEMBER, &profile, "domain", "*.github.com")
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "not a denial");
    let (status, _) = fleet
        .call(
            MEMBER,
            Method::POST,
            "/v1/exceptions",
            Some(json!({
                "project": PROJECT,
                "profile": profile,
                "scope": { "kind": "domain", "value": "gist.github.com" },
                "reason": "Too long",
                "expires_at_unix": fleet.now() + 86_401,
            })),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "beyond the profile's max_ttl_seconds"
    );

    let (status, body) = fleet
        .request_exception(MEMBER, &profile, "command", "git push --force *")
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["status"], "pending");
    assert_eq!(body["requested_by"], MEMBER);
    let id = body["id"].as_str().unwrap().to_owned();
    let approve = format!("/v1/exceptions/{id}:approve");
    for caller in [MEMBER, VIEWER, BOB, WORKER, OPERATOR] {
        let (status, _) = fleet.call(caller, Method::POST, &approve, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{caller} cannot approve");
    }
    let (status, body) = fleet.call(ADMIN, Method::POST, &approve, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "approved");
    assert_eq!(body["decided_by"], ADMIN);
    let (status, _) = fleet
        .call(
            OWNER,
            Method::POST,
            &format!("/v1/exceptions/{id}:reject"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "already decided");

    let active = format!("/v1/exceptions?project={PROJECT_PATH}&state=active");
    let (_, body) = fleet.call(VIEWER, Method::GET, &active, None).await;
    assert_eq!(body["exceptions"].as_array().unwrap().len(), 1);
    let (status, _) = fleet.call(OUTSIDER, Method::GET, &active, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    fleet.advance(3_600);
    let (_, body) = fleet.call(VIEWER, Method::GET, &active, None).await;
    assert!(body["exceptions"].as_array().unwrap().is_empty(), "expired");

    let events = fleet.events(&format!("exception={id}")).await;
    let types = events
        .iter()
        .map(|event| {
            (
                event["event_type"].as_str().unwrap(),
                event["actor"].as_str().unwrap(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(types[0], ("exception.requested", MEMBER));
    assert!(types.contains(&("exception.approval_refused", MEMBER)));
    assert!(types.contains(&("exception.approval_refused", VIEWER)));
    assert!(types.contains(&("exception.approved", ADMIN)));
    assert!(events.iter().all(|event| {
        event["detail"]
            .as_str()
            .unwrap()
            .contains("command:git push --force *")
    }));
}

#[actix_web::test]
async fn stale_approvals_cannot_authorize_changed_work() {
    let fleet = fleet().await;
    let third = fleet.project().await;
    let (status, body) = fleet
        .request_exception(MEMBER, &third, "domain", "gist.github.com")
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let pending = body["id"].as_str().unwrap().to_owned();
    let approved = fleet.approved_exception(&third).await;
    let admitted = binding(MEMBER, &third, vec![approved.clone()]);
    let (status, body) = fleet.admit(MEMBER, &admitted, &session('a')).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let fourth = fleet.publish(4).await;
    let (status, body) = fleet
        .call(
            ADMIN,
            Method::POST,
            &format!("/v1/exceptions/{pending}:approve"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let (status, _) = fleet.admit(MEMBER, &admitted, &session('b')).await;
    assert_eq!(status, StatusCode::CONFLICT, "revision 3 is stale");
    let (status, body) = fleet
        .admit(
            MEMBER,
            &binding(MEMBER, &fourth, vec![approved]),
            &session('c'),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body["detail"].as_str().unwrap().contains("exception"));
    let (status, body) = fleet
        .admit(MEMBER, &binding(MEMBER, &fourth, vec![]), &session('d'))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[actix_web::test]
async fn admission_requires_the_caller_a_member_role_and_this_authority() {
    let fleet = fleet().await;
    let profile = fleet.project().await;
    let exception = fleet.approved_exception(&profile).await;

    for caller in [VIEWER, OUTSIDER] {
        let (status, _) = fleet
            .admit(caller, &binding(caller, &profile, vec![]), &session('a'))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{caller}");
    }
    let (status, _) = fleet
        .admit(BOB, &binding(MEMBER, &profile, vec![]), &session('a'))
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a caller cannot claim another principal"
    );
    let (status, _) = fleet
        .admit(WORKER, &binding(MEMBER, &profile, vec![]), &session('a'))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "nor can a worker");
    let mut foreign = binding(MEMBER, &profile, vec![]);
    foreign.authority.id = "local".to_owned();
    let (status, _) = fleet.admit(MEMBER, &foreign, &session('a')).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let mut unknown_service = binding(MEMBER, &profile, vec![]);
    unknown_service.brokered_services = vec![ServiceId::new("openai").unwrap()];
    let (status, _) = fleet.admit(MEMBER, &unknown_service, &session('a')).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = fleet
        .admit(
            BOB,
            &binding(BOB, &profile, vec![ExceptionId::from_bytes([9; 16])]),
            &session('a'),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "unknown exception");

    let excepted = binding(MEMBER, &profile, vec![exception.clone()]);
    let (status, body) = fleet.admit(MEMBER, &excepted, &session('a')).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["binding_sha256"], json!(excepted.digest().unwrap()));
    let (status, _) = fleet.admit(MEMBER, &excepted, &session('a')).await;
    assert_eq!(status, StatusCode::CONFLICT, "duplicate session");
    let (status, body) = fleet
        .admit(
            WORKER,
            &binding(WORKER, &profile, vec![exception.clone()]),
            &session('b'),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "project-wide exceptions cover the worker: {body}"
    );

    let events = fleet.events(&format!("project={PROJECT_PATH}")).await;
    let refused = events
        .iter()
        .filter(|event| event["event_type"] == "session.refused")
        .count();
    assert_eq!(refused, 7);
    assert!(
        events
            .iter()
            .any(|event| event["event_type"] == "exception.applied"
                && event["exception"] == json!(exception)
                && event["session"] == json!(session('a')))
    );
}

#[actix_web::test]
async fn grants_follow_the_session_profile_and_exception_lifecycle() {
    let fleet = fleet().await;
    let profile = fleet.project().await;
    let exception = fleet.approved_exception(&profile).await;
    let excepted = binding(MEMBER, &profile, vec![exception.clone()]);
    let id = session('a');
    assert_eq!(fleet.admit(MEMBER, &excepted, &id).await.0, StatusCode::OK);

    let (status, _) = fleet
        .call(
            BOB,
            Method::POST,
            "/v1/grants",
            Some(grant_request(&excepted, &id)),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "another member cannot use the session"
    );
    let mut wide = grant_request(&excepted, &id);
    wide["path_prefixes"] = json!(["/v1/files"]);
    let (status, _) = fleet
        .call(MEMBER, Method::POST, "/v1/grants", Some(wide))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "path outside the profile");
    let (status, grant) = fleet
        .call(
            MEMBER,
            Method::POST,
            "/v1/grants",
            Some(grant_request(&excepted, &id)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{grant}");
    assert_eq!(grant["max_expires_at_unix"], fleet.now() + 3_600);
    assert_eq!(grant["lease_expires_at_unix"], fleet.now() + 60);

    let authorize = |grant: &Value, path: &str| Some(context(grant, path));
    let (status, body) = fleet
        .call(
            MEMBER,
            Method::POST,
            "/v1/authorize",
            authorize(&grant, "/v1/messages"),
        )
        .await;
    assert_eq!((status, decision(&body)), (StatusCode::OK, "allow"));
    let (_, body) = fleet
        .call(
            MEMBER,
            Method::POST,
            "/v1/authorize",
            authorize(&grant, "/v1/files"),
        )
        .await;
    assert_eq!(decision(&body), "path_not_granted");
    let (_, body) = fleet
        .call(
            MEMBER,
            Method::POST,
            "/v1/authorize",
            authorize(&grant, "/v1/messages/../files"),
        )
        .await;
    assert_eq!(decision(&body), "invalid_path");
    let (_, body) = fleet
        .call(
            BOB,
            Method::POST,
            "/v1/authorize",
            authorize(&grant, "/v1/messages"),
        )
        .await;
    assert_eq!(decision(&body), "principal_mismatch");
    let mut changed = context(&grant, "/v1/messages");
    changed["binding_sha256"] = json!(Sha256Digest::of(b"changed"));
    let (_, body) = fleet
        .call(MEMBER, Method::POST, "/v1/authorize", Some(changed))
        .await;
    assert_eq!(decision(&body), "binding_mismatch");

    fleet.advance(30);
    let renew = format!("/v1/grants/{}:renew", grant["grant_id"].as_str().unwrap());
    let (status, renewed) = fleet.call(MEMBER, Method::POST, &renew, None).await;
    assert_eq!(status, StatusCode::OK, "{renewed}");
    assert_eq!(renewed["generation"], 2);
    assert_eq!(renewed["lease_expires_at_unix"], fleet.now() + 60);

    let (status, _) = fleet
        .call(
            MEMBER,
            Method::POST,
            &format!("/v1/exceptions/{exception}:revoke"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "the requester may revoke");
    let (_, body) = fleet
        .call(
            MEMBER,
            Method::POST,
            "/v1/authorize",
            authorize(&grant, "/v1/messages"),
        )
        .await;
    assert_eq!(decision(&body), "stale_policy");
    let (status, _) = fleet.call(MEMBER, Method::POST, &renew, None).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = fleet
        .call(
            MEMBER,
            Method::POST,
            "/v1/grants",
            Some(grant_request(&excepted, &id)),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let plain = binding(MEMBER, &profile, vec![]);
    let second = session('b');
    assert_eq!(fleet.admit(MEMBER, &plain, &second).await.0, StatusCode::OK);
    let (_, grant) = fleet
        .call(
            MEMBER,
            Method::POST,
            "/v1/grants",
            Some(grant_request(&plain, &second)),
        )
        .await;
    let revoke = format!("/v1/grants/{}:revoke", grant["grant_id"].as_str().unwrap());
    let (status, _) = fleet
        .call(
            MEMBER,
            Method::POST,
            &revoke,
            Some(json!({ "reason": "operator_revoked" })),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "members cannot revoke as operators"
    );
    let (status, _) = fleet
        .call(
            MEMBER,
            Method::POST,
            &format!("/v1/sessions/{second}:end"),
            Some(json!({ "outcome": "cancelled" })),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, body) = fleet
        .call(
            MEMBER,
            Method::POST,
            "/v1/authorize",
            authorize(&grant, "/v1/messages"),
        )
        .await;
    assert_eq!(decision(&body), "revoked");
    let (status, _) = fleet
        .call(
            MEMBER,
            Method::POST,
            "/v1/grants",
            Some(grant_request(&plain, &second)),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "ended sessions get no grants");

    let events = fleet.events(&format!("session={second}")).await;
    let revoked = events
        .iter()
        .find(|event| event["event_type"] == "grant.revoked")
        .unwrap();
    assert_eq!(revoked["detail"], "reason=session_cancelled");
    let authorized = events
        .iter()
        .filter(|event| event["event_type"] == "request.authorized")
        .collect::<Vec<_>>();
    assert_eq!(authorized.last().unwrap()["deny_reason"], "revoked");
    assert_eq!(
        authorized.last().unwrap()["target"],
        "POST anthropic/v1/messages"
    );
}

#[actix_web::test]
async fn audit_is_role_scoped_attributable_and_verifiable() {
    let fleet = fleet().await;
    let profile = fleet.project().await;
    fleet.approved_exception(&profile).await;
    let query = format!("/v1/audit/events?project={PROJECT_PATH}&limit=3");
    let (status, page) = fleet.call(VIEWER, Method::GET, &query, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["events"].as_array().unwrap().len(), 3);
    let cursor = page["next_after_sequence"].as_u64().unwrap();
    let (_, next) = fleet
        .call(
            VIEWER,
            Method::GET,
            &format!("{query}&after_sequence={cursor}"),
            None,
        )
        .await;
    assert!(next["events"][0]["sequence"].as_u64().unwrap() > cursor);
    for (caller, path) in [
        (OUTSIDER, query.as_str()),
        (VIEWER, "/v1/audit/events"),
        (OWNER, "/v1/audit/verify"),
    ] {
        let (status, _) = fleet.call(caller, Method::GET, path, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{caller} {path}");
    }

    let (status, verification) = fleet
        .call(OPERATOR, Method::GET, "/v1/audit/verify", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(verification["valid"], true);
    let all = fleet.events("limit=500").await;
    assert_eq!(verification["events"], all.len());
    assert_eq!(verification["head_hash"], all.last().unwrap()["event_hash"]);
    let serialized = serde_json::to_string(&all).unwrap();
    for token in fleet.tokens.values() {
        assert!(!serialized.contains(token.as_str()));
    }
    assert!(
        !serialized.contains("Synthetic release window"),
        "reasons stay in the exception record"
    );
}

#[actix_web::test]
async fn invalid_contract_bodies_and_transport_errors_are_problems() {
    let fleet = fleet().await;
    let profile = fleet.project().await;
    let mut wrong_version = serde_json::to_value(binding(MEMBER, &profile, vec![])).unwrap();
    wrong_version["contract_version"] = json!(1);
    let unsorted = {
        let mut binding = binding(MEMBER, &profile, vec![]);
        binding.exceptions = vec![
            ExceptionId::from_bytes([2; 16]),
            ExceptionId::from_bytes([1; 16]),
        ];
        serde_json::to_value(binding).unwrap()
    };
    for (method, path, body) in [
        (
            Method::POST,
            "/v1/sessions:admit",
            json!({ "session": "nope", "binding": unsorted }),
        ),
        (
            Method::POST,
            "/v1/sessions:admit",
            json!({ "session": session('a'), "binding": wrong_version }),
        ),
        (
            Method::POST,
            "/v1/sessions:admit",
            json!({ "session": session('a'), "binding": unsorted }),
        ),
        (
            Method::POST,
            "/v1/exceptions",
            json!({ "project": PROJECT, "profile": profile, "scope": { "kind": "mcp_tool", "value": "x" }, "reason": "r", "expires_at_unix": NOW + 60 }),
        ),
        (
            Method::POST,
            "/v1/exceptions",
            json!({ "project": PROJECT, "profile": profile, "scope": { "kind": "domain", "value": "gist.github.com" }, "reason": "\u{0007}", "expires_at_unix": NOW + 60 }),
        ),
        (
            Method::POST,
            "/v1/projects",
            json!({ "project": "github:Example/x", "owner": OWNER }),
        ),
    ] {
        let (status, body) = fleet.call(OPERATOR, method.clone(), path, Some(body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{method} {path}: {body}");
    }
    let (status, _) = fleet
        .call(OPERATOR, Method::GET, "/v1/audit/events?limit=0", None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = fleet
        .call(OPERATOR, Method::DELETE, "/v1/grants", None)
        .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    let (status, _) = fleet.call(OPERATOR, Method::GET, "/v1/unknown", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let oversized = json!({ "document": "x".repeat(2 * 1024 * 1024), "signatures": [] });
    let (status, _) = fleet
        .call(OPERATOR, Method::PUT, "/v1/profiles/acme", Some(oversized))
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    let request = test::TestRequest::post()
        .uri("/v1/authorize")
        .insert_header((
            header::AUTHORIZATION,
            format!("Bearer {}", fleet.tokens[MEMBER]),
        ))
        .insert_header((header::CONTENT_TYPE, "text/plain"))
        .set_payload("{}")
        .to_request();
    let response = test::call_service(&fleet.service, request).await;
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

/// A synthetic identity-provider signing key.
enum IdpKey {
    Ed25519 {
        kid: &'static str,
        pair: Ed25519KeyPair,
    },
    Es256 {
        kid: &'static str,
        pair: EcdsaKeyPair,
    },
}

impl IdpKey {
    fn ed25519(kid: &'static str) -> Self {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Self::Ed25519 {
            kid,
            pair: Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap(),
        }
    }

    fn es256(kid: &'static str) -> Self {
        let random = SystemRandom::new();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &random).unwrap();
        Self::Es256 {
            kid,
            pair: EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                pkcs8.as_ref(),
                &random,
            )
            .unwrap(),
        }
    }

    fn jwk(&self) -> Value {
        match self {
            Self::Ed25519 { kid, pair } => json!({
                "kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA", "kid": kid,
                "x": URL_SAFE_NO_PAD.encode(pair.public_key().as_ref()),
            }),
            Self::Es256 { kid, pair } => {
                let point = pair.public_key().as_ref();
                json!({
                    "kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": kid,
                    "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
                    "y": URL_SAFE_NO_PAD.encode(&point[33..65]),
                })
            }
        }
    }

    fn sign(&self, claims: &Value) -> String {
        let (algorithm, kid) = match self {
            Self::Ed25519 { kid, .. } => ("EdDSA", kid),
            Self::Es256 { kid, .. } => ("ES256", kid),
        };
        let encode = |value: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap());
        let message = format!(
            "{}.{}",
            encode(&json!({ "alg": algorithm, "kid": kid, "typ": "JWT" })),
            encode(claims)
        );
        let signature = match self {
            Self::Ed25519 { pair, .. } => pair.sign(message.as_bytes()).as_ref().to_vec(),
            Self::Es256 { pair, .. } => pair
                .sign(&SystemRandom::new(), message.as_bytes())
                .unwrap()
                .as_ref()
                .to_vec(),
        };
        format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature))
    }
}

/// Key sets served by the local identity provider; `None` answers `500`.
struct IdpState {
    base: String,
    users: Mutex<Option<Value>>,
    ci: Mutex<Option<Value>>,
}

async fn discovery(state: web::Data<IdpState>) -> HttpResponse {
    HttpResponse::Ok().json(json!({
        "issuer": format!("{}/users", state.base),
        "jwks_uri": format!("{}/users/jwks", state.base),
    }))
}

fn key_set(keys: &Mutex<Option<Value>>) -> HttpResponse {
    match keys.lock().unwrap().clone() {
        Some(keys) => HttpResponse::Ok().json(keys),
        None => HttpResponse::InternalServerError().finish(),
    }
}

async fn users_jwks(state: web::Data<IdpState>) -> HttpResponse {
    key_set(&state.users)
}

async fn ci_jwks(state: web::Data<IdpState>) -> HttpResponse {
    key_set(&state.ci)
}

/// A loopback identity provider: `/users` uses discovery, `/ci` a fixed
/// JWKS URI.
async fn identity_provider(users: &[&IdpKey], ci: &[&IdpKey]) -> web::Data<IdpState> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let keys =
        |keys: &[&IdpKey]| json!({ "keys": keys.iter().map(|key| key.jwk()).collect::<Vec<_>>() });
    let state = web::Data::new(IdpState {
        base: format!("http://{}", listener.local_addr().unwrap()),
        users: Mutex::new(Some(keys(users))),
        ci: Mutex::new(Some(keys(ci))),
    });
    let shared = state.clone();
    let server = HttpServer::new(move || {
        App::new()
            .app_data(shared.clone())
            .route(
                "/users/.well-known/openid-configuration",
                web::get().to(discovery),
            )
            .route("/users/jwks", web::get().to(users_jwks))
            .route("/ci/jwks", web::get().to(ci_jwks))
    })
    .workers(1)
    .listen(listener)
    .unwrap()
    .run();
    actix_web::rt::spawn(server);
    state
}

fn oidc_config(base: &str) -> OidcConfig {
    serde_json::from_value(json!({ "issuers": [
        {
            "issuer": format!("{base}/users"),
            "audiences": ["sendbox-fleet"],
            "kind": "user",
            "principal_claim": "email",
            "principal_prefix": "oidc",
        },
        {
            "issuer": format!("{base}/ci"),
            "audiences": ["sendbox-fleet"],
            "kind": "worker",
            "principal_claim": "repository_id",
            "principal_prefix": "ci",
            "auto_provision": true,
            "jwks_uri": format!("{base}/ci/jwks"),
            "algorithms": ["ES256"],
            "required_claims": { "repository_owner": "example" },
        },
    ]}))
    .unwrap()
}

fn person(base: &str, email: &str, now: u64) -> Value {
    json!({
        "iss": format!("{base}/users"),
        "aud": "sendbox-fleet",
        "sub": "synthetic-subject",
        "email": email,
        "email_verified": true,
        "iat": now,
        "exp": now + 300,
    })
}

fn pipeline(base: &str, repository_id: u64, now: u64) -> Value {
    json!({
        "iss": format!("{base}/ci"),
        "aud": ["other", "sendbox-fleet"],
        "repository_id": repository_id,
        "repository_owner": "example",
        "iat": now,
        "nbf": now,
        "exp": now + 300,
    })
}

impl<S, B> Fleet<S>
where
    S: Service<actix_http::Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: MessageBody,
{
    async fn sign_in(&self, token: &str) -> StatusCode {
        self.send(Method::GET, "/v1/tokens", Some(token), None)
            .await
            .0
    }

    async fn exchange(&self, token: &str, body: Value) -> (StatusCode, header::HeaderMap, Value) {
        self.respond(None, Method::POST, "/v1/tokens", Some(token), Some(&body))
            .await
    }
}

#[actix_web::test]
async fn identity_provider_tokens_need_a_trusted_signature_and_exact_claims() {
    let user_key = IdpKey::ed25519("user-1");
    let ci_key = IdpKey::es256("ci-1");
    let idp = identity_provider(&[&user_key], &[&ci_key]).await;
    let base = idp.base.as_str();
    let fleet = fleet_with(Setup {
        oidc: Some(oidc_config(base)),
        ..Setup::default()
    })
    .await;
    let now = fleet.now();
    let alice = person(base, "alice@example.com", now);
    assert_eq!(fleet.sign_in(&user_key.sign(&alice)).await, StatusCode::OK);

    let mut tampered = user_key.sign(&alice);
    let forged = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&person(base, "olivia@example.com", now)).unwrap());
    let parts = tampered.split('.').map(str::to_owned).collect::<Vec<_>>();
    tampered = format!("{}.{forged}.{}", parts[0], parts[2]);
    let unsigned = |algorithm: &str, signature: &str| {
        let encode = |value: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap());
        format!(
            "{}.{}.{signature}",
            encode(&json!({ "alg": algorithm, "kid": "user-1" })),
            encode(&alice)
        )
    };
    let impostor = IdpKey::ed25519("user-1");
    let unpublished = IdpKey::ed25519("user-9");
    let with = |change: &dyn Fn(&mut Value)| {
        let mut claims = alice.clone();
        change(&mut claims);
        user_key.sign(&claims)
    };
    for (case, token) in [
        ("tampered payload", tampered),
        ("alg none", unsigned("none", "")),
        ("HMAC", unsigned("HS256", "c2lnbmF0dXJl")),
        ("same kid, other key", impostor.sign(&alice)),
        ("unpublished key", unpublished.sign(&alice)),
        (
            "expired",
            with(&|claims| {
                claims["iat"] = json!(now - 600);
                claims["exp"] = json!(now - 61);
            }),
        ),
        (
            "not yet valid",
            with(&|claims| claims["nbf"] = json!(now + 120)),
        ),
        (
            "issued in the future",
            with(&|claims| claims["iat"] = json!(now + 120)),
        ),
        (
            "wrong audience",
            with(&|claims| claims["aud"] = json!("other")),
        ),
        (
            "unknown issuer",
            with(&|claims| claims["iss"] = json!(format!("{base}/elsewhere"))),
        ),
        (
            "unverified email",
            with(&|claims| claims["email_verified"] = json!(false)),
        ),
        (
            "no email_verified",
            with(&|claims| {
                claims.as_object_mut().unwrap().remove("email_verified");
            }),
        ),
        (
            "no expiry",
            with(&|claims| {
                claims.as_object_mut().unwrap().remove("exp");
            }),
        ),
        (
            "unregistered",
            user_key.sign(&person(base, "nobody@example.com", now)),
        ),
        (
            "not a principal id",
            user_key.sign(&person(base, "a b@example.com", now)),
        ),
        ("ci key on the user issuer", ci_key.sign(&alice)),
        (
            "wrong owner claim",
            ci_key.sign(&{
                let mut claims = pipeline(base, 4242, now);
                claims["repository_owner"] = json!("someone-else");
                claims
            }),
        ),
        (
            "algorithm not allowed",
            IdpKey::ed25519("ci-1").sign(&pipeline(base, 4242, now)),
        ),
    ] {
        assert_eq!(
            fleet.sign_in(&token).await,
            StatusCode::UNAUTHORIZED,
            "{case}"
        );
    }

    let mut tx = fleet.database.begin_write().await.unwrap();
    tx.execute(
        "UPDATE principals SET disabled_at_unix = $2 WHERE id = $1",
        &[BOB.into(), Arg::from(i64::try_from(now).unwrap())],
    )
    .await
    .unwrap();
    tx.execute(
        "INSERT INTO principals (id, kind, created_at_unix) VALUES ('ci:777', 'user', 0)",
        &[],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let bob = user_key.sign(&person(base, "bob@example.com", now));
    assert_eq!(
        fleet.sign_in(&bob).await,
        StatusCode::UNAUTHORIZED,
        "disabled"
    );
    let mismatched = ci_key.sign(&pipeline(base, 777, now));
    assert_eq!(
        fleet.sign_in(&mismatched).await,
        StatusCode::UNAUTHORIZED,
        "a worker issuer cannot sign in as a user"
    );

    let ci = ci_key.sign(&pipeline(base, 4242, now));
    assert_eq!(fleet.sign_in(&ci).await, StatusCode::OK, "auto-provisioned");
    assert_eq!(fleet.sign_in(&ci).await, StatusCode::OK);
    let provisioned = fleet
        .events("principal=ci:4242")
        .await
        .into_iter()
        .filter(|event| event["event_type"] == "principal.provisioned")
        .collect::<Vec<_>>();
    assert_eq!(provisioned.len(), 1);
    assert_eq!(
        provisioned[0]["detail"],
        format!("kind=worker issuer={base}/ci")
    );
    let row = fleet
        .database
        .fetch_optional(
            "SELECT kind, is_operator AS operator FROM principals WHERE id = 'ci:4242'",
            &[],
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.text("kind").unwrap(), "worker");
    assert!(
        !row.flag("operator").unwrap(),
        "provisioned principals hold no roles"
    );
    let (status, _) = fleet
        .send(
            Method::POST,
            "/v1/projects",
            Some(&ci),
            Some(&json!({ "project": "github:example/other", "owner": "ci:4242" })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn identity_provider_keys_rotate_and_outages_fail_closed() {
    let first = IdpKey::ed25519("user-1");
    let second = IdpKey::es256("user-2");
    let ci_key = IdpKey::es256("ci-1");
    let idp = identity_provider(&[&first], &[&ci_key]).await;
    let base = idp.base.clone();
    let fleet = fleet_with(Setup {
        oidc: Some(oidc_config(&base)),
        ..Setup::default()
    })
    .await;
    let alice = person(&base, "alice@example.com", fleet.now());
    assert_eq!(fleet.sign_in(&first.sign(&alice)).await, StatusCode::OK);

    *idp.users.lock().unwrap() = Some(json!({ "keys": [second.jwk()] }));
    assert_eq!(
        fleet.sign_in(&second.sign(&alice)).await,
        StatusCode::OK,
        "an unknown key id refreshes the key set"
    );
    assert_eq!(
        fleet.sign_in(&first.sign(&alice)).await,
        StatusCode::UNAUTHORIZED,
        "retired keys stop working once the key set is refreshed"
    );

    *idp.users.lock().unwrap() = None;
    assert_eq!(
        fleet.sign_in(&second.sign(&alice)).await,
        StatusCode::OK,
        "cached keys survive a provider outage"
    );
    assert_eq!(
        fleet.sign_in(&IdpKey::ed25519("user-3").sign(&alice)).await,
        StatusCode::UNAUTHORIZED
    );
    *idp.ci.lock().unwrap() = None;
    let (status, body) = fleet
        .send(
            Method::GET,
            "/v1/tokens",
            Some(&ci_key.sign(&pipeline(&base, 4242, fleet.now()))),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    let (status, _) = fleet
        .send(Method::GET, "/v1/tokens", Some(&first.sign(&alice)), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let plain = fleet_with(Setup::default()).await;
    assert_eq!(
        plain.sign_in(&second.sign(&alice)).await,
        StatusCode::UNAUTHORIZED,
        "identity-provider tokens need FLEET_OIDC_CONFIG"
    );
}

#[actix_web::test]
async fn sign_in_exchanges_for_short_lived_service_tokens() {
    let key = IdpKey::ed25519("user-1");
    let idp = identity_provider(&[&key], &[]).await;
    let fleet = fleet_with(Setup {
        oidc: Some(oidc_config(&idp.base)),
        ..Setup::default()
    })
    .await;
    let now = fleet.now();
    let alice = key.sign(&person(&idp.base, "alice@example.com", now));

    let (status, headers, issued) = fleet
        .exchange(
            &alice,
            json!({ "ttl_seconds": 3_600, "description": "Synthetic laptop" }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{issued}");
    assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(issued["principal"], MEMBER);
    assert_eq!(issued["expires_at_unix"], now + 3_600);
    let token = issued["token"].as_str().unwrap().to_owned();
    let id = issued["id"].as_str().unwrap().to_owned();
    assert!(token.starts_with("sbf_"));
    assert_eq!(id.len(), 32);

    let (_, _, default) = fleet.exchange(&alice, json!({})).await;
    assert_eq!(
        default["expires_at_unix"],
        now + TokenLimits::default().default_seconds
    );
    let max = TokenLimits::default().max_seconds;
    for body in [
        json!({ "ttl_seconds": 59 }),
        json!({ "ttl_seconds": max + 1 }),
        json!({ "description": "\u{0007}" }),
        json!({ "description": " " }),
    ] {
        assert_eq!(
            fleet.exchange(&alice, body.clone()).await.0,
            StatusCode::BAD_REQUEST,
            "{body}"
        );
    }
    for service_token in [token.as_str(), fleet.tokens[MEMBER].as_str()] {
        assert_eq!(
            fleet.exchange(service_token, json!({})).await.0,
            StatusCode::FORBIDDEN,
            "a service token cannot mint another"
        );
    }

    let (status, list) = fleet
        .send(Method::GET, "/v1/tokens", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let tokens = list["tokens"].as_array().unwrap();
    assert_eq!(tokens.len(), 3, "the seeded token and two exchanged tokens");
    let summary = tokens.iter().find(|summary| summary["id"] == id).unwrap();
    assert_eq!(summary["description"], "Synthetic laptop");
    assert!(!list.to_string().contains("sbf_"));

    let revoke = format!("/v1/tokens/{id}");
    assert_eq!(
        fleet.call(BOB, Method::DELETE, &revoke, None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fleet
            .call(BOB, Method::DELETE, "/v1/tokens/not-hex", None)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let (status, _) = fleet
        .send(Method::DELETE, &revoke, Some(&alice), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = fleet
        .send(Method::DELETE, &revoke, Some(&alice), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "revocation is idempotent");
    assert_eq!(fleet.sign_in(&token).await, StatusCode::UNAUTHORIZED);
    let other = default["token"].as_str().unwrap();
    assert_eq!(fleet.sign_in(other).await, StatusCode::OK);
    let (status, _) = fleet
        .call(
            OPERATOR,
            Method::DELETE,
            &format!("/v1/tokens/{}", default["id"].as_str().unwrap()),
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "operators may revoke any token"
    );
    assert_eq!(fleet.sign_in(other).await, StatusCode::UNAUTHORIZED);

    let (_, _, short) = fleet.exchange(&alice, json!({ "ttl_seconds": 60 })).await;
    fleet.advance(61);
    assert_eq!(
        fleet.sign_in(short["token"].as_str().unwrap()).await,
        StatusCode::UNAUTHORIZED,
        "exchanged tokens expire"
    );

    let mut issued_tokens = Vec::new();
    let conflict = loop {
        let (status, _, body) = fleet.exchange(&alice, json!({ "ttl_seconds": 600 })).await;
        if status != StatusCode::CREATED {
            break status;
        }
        issued_tokens.push(body["token"].as_str().unwrap().to_owned());
        assert!(issued_tokens.len() <= 20);
    };
    assert_eq!(conflict, StatusCode::CONFLICT);
    assert_eq!(
        issued_tokens.len(),
        19,
        "20 live tokens including the seeded one"
    );

    let events = fleet
        .events("principal=oidc:alice@example.com&limit=500")
        .await;
    let count = |kind: &str| {
        events
            .iter()
            .filter(|event| event["event_type"] == kind)
            .count()
    };
    assert_eq!(count("token.issued"), 22);
    assert_eq!(count("token.revoked"), 2);
    let serialized = serde_json::to_string(&events).unwrap();
    for secret in issued_tokens.iter().chain([&token]) {
        assert!(!serialized.contains(secret.as_str()));
    }
}

#[actix_web::test]
async fn outcome_reports_are_attributed_evidence_that_never_change_decisions() {
    let fleet = fleet().await;
    let profile = fleet.project().await;
    let plain = binding(MEMBER, &profile, vec![]);
    let id = session('c');
    assert_eq!(fleet.admit(MEMBER, &plain, &id).await.0, StatusCode::OK);
    let (_, grant) = fleet
        .call(
            MEMBER,
            Method::POST,
            "/v1/grants",
            Some(grant_request(&plain, &id)),
        )
        .await;
    let path = format!("/v1/grants/{}:outcome", grant["grant_id"].as_str().unwrap());
    let report = json!({
        "service": "anthropic",
        "method": "POST",
        "path": "/v1/messages",
        "outcome": "failed",
        "reason": "upstream_error",
        "status": 502,
        "request_bytes": 10,
        "response_bytes": 20,
        "duration_ms": 30,
    });
    let changed = |field: &str, value: Value| {
        let mut report = report.clone();
        report[field] = value;
        Some(report)
    };
    assert_eq!(
        fleet
            .call(BOB, Method::POST, &path, Some(report.clone()))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    for (field, value, expected) in [
        ("service", json!("openai"), StatusCode::BAD_REQUEST),
        ("reason", json!("Not A Code"), StatusCode::BAD_REQUEST),
        ("method", json!("post"), StatusCode::BAD_REQUEST),
        ("status", json!(42), StatusCode::BAD_REQUEST),
        ("headers", json!({}), StatusCode::BAD_REQUEST),
    ] {
        let (status, body) = fleet
            .call(MEMBER, Method::POST, &path, changed(field, value))
            .await;
        assert_eq!(status, expected, "{field}: {body}");
    }
    let missing = format!("/v1/grants/{}:outcome", "f".repeat(32));
    assert_eq!(
        fleet
            .call(MEMBER, Method::POST, &missing, Some(report.clone()))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fleet
            .call(MEMBER, Method::POST, &path, Some(report))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    let (_, body) = fleet
        .call(
            MEMBER,
            Method::POST,
            "/v1/authorize",
            Some(context(&grant, "/v1/messages")),
        )
        .await;
    assert_eq!(decision(&body), "allow", "outcomes are evidence only");

    let events = fleet.events(&format!("session={id}")).await;
    let outcome = events
        .iter()
        .find(|event| event["event_type"] == "request.outcome")
        .unwrap();
    assert_eq!(outcome["outcome"], "failed");
    assert_eq!(outcome["actor"], MEMBER);
    assert_eq!(outcome["target"], "POST anthropic/v1/messages");
    assert_eq!(
        outcome["detail"],
        "reason=upstream_error status=502 request_bytes=10 response_bytes=20 duration_ms=30"
    );
}

#[actix_web::test]
async fn signed_audit_heads_anchor_the_chain_and_reveal_rewrites() {
    {
        let unsigned = fleet().await;
        let (status, _) = unsigned
            .call(OPERATOR, Method::GET, "/v1/audit/head", None)
            .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }
    let signer = Arc::new(AuditSigner::from_key(
        SigningKeyMaterial::generate().unwrap(),
    ));
    let fleet = fleet_with(Setup {
        audit_signer: Some(signer.clone()),
        ..Setup::default()
    })
    .await;
    assert!(fleet.audit_signer.is_some());
    fleet.project().await;
    assert_eq!(
        fleet
            .call(OWNER, Method::GET, "/v1/audit/head", None)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let (status, head) = fleet
        .call(OPERATOR, Method::GET, "/v1/audit/head", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{head}");
    let last = fleet.events("limit=500").await.last().unwrap().clone();
    assert_eq!(head["head"]["sequence"], last["sequence"]);
    assert_eq!(head["head"]["event_hash"], last["event_hash"]);
    assert_eq!(head["head"]["authority_id"], AUTHORITY);

    let directory = tempfile::tempdir().unwrap();
    let signed: anchor::SignedAuditHead = serde_json::from_value(head.clone()).unwrap();
    let path = anchor::write_anchor(directory.path(), &signed)
        .unwrap()
        .unwrap();
    assert!(
        anchor::write_anchor(directory.path(), &signed)
            .unwrap()
            .is_none(),
        "anchors are never overwritten"
    );
    let check = |file: std::path::PathBuf| {
        let database = fleet.database.clone();
        let identity = signer.identity.clone();
        async move {
            anchor::check_anchor(&database, &identity, &file)
                .await
                .unwrap()
        }
    };
    assert!(check(path.clone()).await.valid);

    fleet.approved_exception(&fleet.publish(4).await).await;
    assert!(
        check(path.clone()).await.valid,
        "a growing chain keeps old anchors valid"
    );

    let other = AuditSigner::from_key(SigningKeyMaterial::generate().unwrap());
    let foreign = directory.path().join("foreign.json");
    std::fs::write(
        &foreign,
        serde_json::to_vec(&other.sign(signed.head.clone()).unwrap()).unwrap(),
    )
    .unwrap();
    assert!(!check(foreign).await.valid, "another key's anchor");
    let mut edited = head.clone();
    edited["head"]["signed_at_unix"] = json!(NOW + 1);
    let edited_path = directory.path().join("edited.json");
    std::fs::write(&edited_path, serde_json::to_vec(&edited).unwrap()).unwrap();
    assert!(!check(edited_path).await.valid, "an edited anchor");

    let mut tx = fleet.database.begin_write().await.unwrap();
    let drop_trigger = match fleet.database {
        Database::Postgres(_) => "DROP TRIGGER audit_events_reject_update_delete ON audit_events",
        Database::Sqlite(_) => "DROP TRIGGER audit_events_reject_update",
    };
    tx.execute(drop_trigger, &[]).await.unwrap();
    tx.execute(
        "UPDATE audit_events SET event_hash = $2 WHERE sequence = $1",
        &[
            Arg::from(i64::try_from(signed.head.sequence).unwrap()),
            "0".repeat(64).into(),
        ],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let rewritten = check(path).await;
    assert!(!rewritten.valid);
    assert_eq!(
        rewritten.reason.as_deref(),
        Some("the database holds a different event at this sequence")
    );
    let (_, verification) = fleet
        .call(OPERATOR, Method::GET, "/v1/audit/verify", None)
        .await;
    assert_eq!(verification["valid"], false);
}

#[actix_web::test]
async fn rate_limits_refuse_with_retry_after() {
    let fleet = fleet_with(Setup {
        limits: (3, 2),
        ..Setup::default()
    })
    .await;
    let attacker = Some("192.0.2.1:40000");
    for token in [Some("sbf_not-a-token"), None] {
        let (status, _, _) = fleet
            .respond(attacker, Method::GET, "/v1/tokens", token, None)
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, headers, _) = fleet
        .respond(
            attacker,
            Method::GET,
            "/v1/tokens",
            Some(&fleet.tokens[MEMBER]),
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "even valid tokens wait"
    );
    assert_eq!(headers.get(header::RETRY_AFTER).unwrap(), "30");
    let (status, _, _) = fleet
        .respond(attacker, Method::GET, "/healthz", None, None)
        .await;
    assert_eq!(status, StatusCode::OK, "probes are not limited");

    let office = Some("192.0.2.2:40000");
    for _ in 0..3 {
        let (status, _, _) = fleet
            .respond(
                office,
                Method::GET,
                "/v1/tokens",
                Some(&fleet.tokens[VIEWER]),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, headers, _) = fleet
        .respond(
            office,
            Method::GET,
            "/v1/tokens",
            Some(&fleet.tokens[VIEWER]),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(headers.get(header::RETRY_AFTER).unwrap(), "20");
    let (status, _, _) = fleet
        .respond(
            office,
            Method::GET,
            "/v1/tokens",
            Some(&fleet.tokens[BOB]),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "limits are per principal");
}

#[actix_web::test]
async fn metrics_are_served_only_on_their_own_listener() {
    let fleet = fleet().await;
    assert_eq!(
        fleet.call(MEMBER, Method::GET, "/v1/tokens", None).await.0,
        StatusCode::OK
    );
    let response = test::call_service(
        &fleet.service,
        test::TestRequest::get().uri("/metrics").to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let metrics = test::init_service(App::new().configure(fleet_server::metrics::configure)).await;
    let response = test::call_service(
        &metrics,
        test::TestRequest::get().uri("/metrics").to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/plain; version=0.0.4")
    );
    let text = String::from_utf8(test::read_body(response).await.to_vec()).unwrap();
    let successes = text
        .lines()
        .find_map(|line| line.strip_prefix("fleet_http_requests_total{class=\"2xx\"} "))
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert!(successes >= 1);
    for name in [
        "fleet_auth_failures_total",
        "fleet_rate_limited_total",
        "fleet_audit_events_total",
        "fleet_audit_sequence",
        "fleet_http_request_duration_seconds_sum",
    ] {
        assert!(text.contains(&format!("\n{name} ")), "{name}");
    }
    assert!(!text.contains("@example.com") && !text.contains("sbf_"));
}
