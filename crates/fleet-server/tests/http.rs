//! HTTP behaviour of the shared governance service: authentication before
//! validation, project roles, signed profiles, session admission, grants,
//! authorization, exceptions, and the audit chain. All data is synthetic.
//!
//! Runs against in-memory SQLite by default. Set `FLEET_TEST_DATABASE_URL` to
//! a PostgreSQL database whose name ends in `_test` to run the same requests
//! against PostgreSQL; its `public` schema is dropped and recreated by every
//! test, so run with `--test-threads=1`.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use actix_web::body::MessageBody;
use actix_web::dev::{Service, ServiceResponse};
use actix_web::http::{Method, StatusCode, header};
use actix_web::{test, web};
use fleet_server::auth::{self, DatabaseAuthenticator, token_from_bytes};
use fleet_server::config::DatabaseUrl;
use fleet_server::db::{Arg, Database};
use fleet_server::server;
use fleet_server::state::AppState;
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
}

async fn fleet() -> Fleet<
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
    });
    let authenticator = auth::shared(Arc::new(DatabaseAuthenticator::new(
        database.clone(),
        clock.clone(),
    )));
    let service = test::init_service(server::app(state, authenticator)).await;
    Fleet {
        service,
        database,
        clock,
        key,
        tokens,
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
        let mut request = test::TestRequest::default().method(method).uri(path);
        if let Some(token) = token {
            request = request.insert_header((header::AUTHORIZATION, format!("Bearer {token}")));
        }
        let request = match body {
            Some(body) => request.set_json(body).to_request(),
            None => request.to_request(),
        };
        let response = test::call_service(&self.service, request).await;
        let status = response.status();
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
        (status, value)
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
