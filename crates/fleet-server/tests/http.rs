//! HTTP behaviour of the scaffold: probes, authentication before validation,
//! contract validation, and explicit 501 responses. All data is synthetic.

use std::sync::Arc;

use actix_web::body::MessageBody;
use actix_web::dev::{Service, ServiceResponse};
use actix_web::http::{Method, StatusCode, header};
use actix_web::{test, web};
use fleet_server::auth::{self, AuthError, AuthFuture, Authenticator, Caller, CallerKind};
use fleet_server::config::DatabaseUrl;
use fleet_server::db::Database;
use fleet_server::server;
use sendbox_governance::PrincipalId;
use serde_json::{Value, json};

const TEST_TOKEN: &str = "synthetic-test-token";
const SESSION: &str = "0123456789abcdef0123456789abcdef";
const GRANT: &str = "fedcba9876543210fedcba9876543210";
const PROFILE_YAML: &str = "\
format: sendbox.governance-profile
version: 1
id: example-default
revision: 3
not_before_unix: 1790000000
expires_at_unix: 1800000000
ceiling:
  runtimes: [apple, kata]
  commands:
    default_action: deny
  network:
    default_action: deny
";

/// Accepts exactly one synthetic token, standing in for a real identity provider.
struct MockAuthenticator;

impl Authenticator for MockAuthenticator {
    fn authenticate<'a>(&'a self, bearer_token: &'a str) -> AuthFuture<'a> {
        Box::pin(async move {
            if bearer_token == TEST_TOKEN {
                Ok(Caller {
                    principal: PrincipalId::new("oidc:alice@example.com").unwrap(),
                    kind: CallerKind::User,
                })
            } else {
                Err(AuthError::InvalidToken)
            }
        })
    }
}

async fn database() -> Database {
    let database = Database::connect(&DatabaseUrl::parse("sqlite::memory:").unwrap())
        .await
        .unwrap();
    database.migrate().await.unwrap();
    database
}

async fn service(
    database: Database,
    authenticator: Arc<dyn Authenticator>,
) -> impl Service<
    actix_http::Request,
    Response = ServiceResponse<impl MessageBody>,
    Error = actix_web::Error,
> {
    test::init_service(server::app(
        web::Data::new(database),
        auth::shared(authenticator),
    ))
    .await
}

fn digest(byte: char) -> String {
    byte.to_string().repeat(64)
}

fn binding() -> Value {
    json!({
        "contract_version": 1,
        "authority": { "id": "sendbox-fleet", "trust_sha256": digest('a') },
        "profile": { "id": "example-default", "revision": 3, "sha256": digest('b') },
        "principal": "oidc:alice@example.com",
        "project": "github:example/service",
        "effective_policy_sha256": digest('c'),
        "brokered_services": ["anthropic"]
    })
}

fn grant_request() -> Value {
    json!({
        "principal": "oidc:alice@example.com",
        "project": "github:example/service",
        "session": SESSION,
        "binding": binding(),
        "service": "anthropic",
        "methods": ["POST"],
        "path_prefixes": ["/v1/messages"],
        "max_ttl_seconds": 3600
    })
}

fn exception_request() -> Value {
    json!({
        "project": "github:example/service",
        "profile": { "id": "example-default", "revision": 3, "sha256": digest('b') },
        "scope": { "kind": "network_domain", "value": "registry.example.com" },
        "reason": "Package mirror outage during release",
        "expires_at_unix": 1795000000
    })
}

fn publication() -> Value {
    json!({
        "document": PROFILE_YAML,
        "signatures": [{ "key_id": "operator-2026", "signature": "c2lnbmF0dXJl" }]
    })
}

struct Route {
    method: Method,
    path: &'static str,
    body: Option<Value>,
    capability: &'static str,
}

fn route(
    method: Method,
    path: &'static str,
    body: Option<Value>,
    capability: &'static str,
) -> Route {
    Route {
        method,
        path,
        body,
        capability,
    }
}

/// Every `/v1` operation with a valid synthetic request.
fn v1_routes() -> Vec<Route> {
    vec![
        route(
            Method::POST,
            "/v1/sessions:admit",
            Some(json!({ "session": SESSION, "binding": binding() })),
            "session_admission",
        ),
        route(
            Method::POST,
            "/v1/grants",
            Some(grant_request()),
            "grant_issuance",
        ),
        route(
            Method::POST,
            "/v1/grants/fedcba9876543210fedcba9876543210:renew",
            None,
            "grant_renewal",
        ),
        route(
            Method::POST,
            "/v1/grants/fedcba9876543210fedcba9876543210:revoke",
            Some(json!({ "reason": "operator_revoked" })),
            "grant_revocation",
        ),
        route(
            Method::POST,
            "/v1/authorize",
            Some(json!({
                "grant_id": GRANT,
                "principal": "oidc:alice@example.com",
                "project": "github:example/service",
                "session": SESSION,
                "binding_sha256": digest('d'),
                "service": "anthropic",
                "method": "POST",
                "path": "/v1/messages"
            })),
            "request_authorization",
        ),
        route(
            Method::GET,
            "/v1/profiles/example-default",
            None,
            "profile_read",
        ),
        route(
            Method::PUT,
            "/v1/profiles/example-default",
            Some(publication()),
            "profile_publication",
        ),
        route(
            Method::GET,
            "/v1/projects/github:example%2Fservice/roles",
            None,
            "role_listing",
        ),
        route(
            Method::POST,
            "/v1/projects/github:example%2Fservice/roles",
            Some(json!({ "principal": "oidc:bob@example.com", "role": "member" })),
            "role_assignment",
        ),
        route(
            Method::POST,
            "/v1/exceptions",
            Some(exception_request()),
            "exception_request",
        ),
        route(
            Method::GET,
            "/v1/audit/events?project=github:example%2Fservice&limit=50",
            None,
            "audit_query",
        ),
    ]
}

fn request(
    method: Method,
    path: &str,
    body: Option<&Value>,
    token: Option<&str>,
) -> actix_http::Request {
    let mut request = test::TestRequest::default().method(method).uri(path);
    if let Some(token) = token {
        request = request.insert_header((header::AUTHORIZATION, format!("Bearer {token}")));
    }
    match body {
        Some(body) => request.set_json(body).to_request(),
        None => request.to_request(),
    }
}

async fn problem(response: ServiceResponse<impl MessageBody>) -> (StatusCode, Value) {
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    assert_eq!(content_type.as_deref(), Some("application/problem+json"));
    let body: Value = test::read_body_json(response).await;
    assert_eq!(body["status"], status.as_u16());
    assert_eq!(body["type"], "about:blank");
    assert!(
        body["detail"]
            .as_str()
            .is_some_and(|detail| !detail.is_empty())
    );
    (status, body)
}

#[actix_web::test]
async fn health_and_readiness_report_status() {
    let database = database().await;
    let app = service(database.clone(), Arc::new(MockAuthenticator)).await;

    for (path, status) in [("/healthz", "ok"), ("/readyz", "ready")] {
        let response = test::call_service(&app, request(Method::GET, path, None, None)).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        let body: Value = test::read_body_json(response).await;
        assert_eq!(body, json!({ "status": status }));
    }

    database.close().await;
    let response = test::call_service(&app, request(Method::GET, "/readyz", None, None)).await;
    let (status, _) = problem(response).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let response = test::call_service(&app, request(Method::GET, "/healthz", None, None)).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[actix_web::test]
async fn every_v1_route_requires_a_bearer_token() {
    let app = service(database().await, Arc::new(MockAuthenticator)).await;
    for route in v1_routes() {
        let response = test::call_service(
            &app,
            request(route.method.clone(), route.path, route.body.as_ref(), None),
        )
        .await;
        let challenge = response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let (status, _) = problem(response).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{} {}",
            route.method,
            route.path
        );
        assert!(challenge.is_some_and(|value| value.starts_with("Bearer ")));

        let response = test::call_service(
            &app,
            request(
                route.method.clone(),
                route.path,
                route.body.as_ref(),
                Some("wrong-token"),
            ),
        )
        .await;
        let (status, _) = problem(response).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{} {}",
            route.method,
            route.path
        );
    }
}

#[actix_web::test]
async fn authenticated_valid_requests_are_not_implemented() {
    let app = service(database().await, Arc::new(MockAuthenticator)).await;
    for route in v1_routes() {
        let response = test::call_service(
            &app,
            request(
                route.method.clone(),
                route.path,
                route.body.as_ref(),
                Some(TEST_TOKEN),
            ),
        )
        .await;
        let (status, body) = problem(response).await;
        assert_eq!(
            status,
            StatusCode::NOT_IMPLEMENTED,
            "{} {}: {body}",
            route.method,
            route.path
        );
        assert_eq!(body["title"], "Not Implemented");
        assert_eq!(body["capability"], route.capability);
        assert!(
            body["detail"]
                .as_str()
                .unwrap()
                .contains("https://github.com/mbianchidev/sendbox/issues/87")
        );
    }
}

#[actix_web::test]
async fn the_unconfigured_provider_rejects_every_token() {
    let app = service(database().await, Arc::new(auth::UnconfiguredAuthenticator)).await;
    for route in v1_routes() {
        let response = test::call_service(
            &app,
            request(
                route.method.clone(),
                route.path,
                route.body.as_ref(),
                Some(TEST_TOKEN),
            ),
        )
        .await;
        let (status, body) = problem(response).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["detail"], "authentication provider not configured");
    }
}

#[actix_web::test]
async fn identity_headers_are_not_authentication() {
    let app = service(database().await, Arc::new(MockAuthenticator)).await;
    for (name, value) in [
        ("x-forwarded-user", "oidc:alice@example.com"),
        ("x-remote-user", "alice"),
        ("x-sendbox-principal", "oidc:alice@example.com"),
        ("authorization", "Basic YWxpY2U6c2VjcmV0"),
    ] {
        let request = test::TestRequest::post()
            .uri("/v1/authorize")
            .insert_header((name, value))
            .to_request();
        let (status, _) = problem(test::call_service(&app, request).await).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{name}");
    }
}

/// Returns `value` with the field at `pointer` replaced or added.
fn with(mut value: Value, pointer: &str, replacement: Value) -> Value {
    let (parent, key) = pointer.rsplit_once('/').unwrap();
    value.pointer_mut(parent).unwrap()[key] = replacement;
    value
}

#[actix_web::test]
async fn invalid_contract_bodies_are_rejected_after_authentication() {
    let app = service(database().await, Arc::new(MockAuthenticator)).await;
    let admit = json!({ "session": SESSION, "binding": binding() });
    let cases: Vec<(Method, &str, Option<Value>)> = vec![
        (
            Method::POST,
            "/v1/sessions:admit",
            Some(with(admit.clone(), "/session", json!("not-a-session"))),
        ),
        (
            Method::POST,
            "/v1/sessions:admit",
            Some(with(admit.clone(), "/binding/contract_version", json!(2))),
        ),
        (
            Method::POST,
            "/v1/sessions:admit",
            Some(with(admit, "/binding/principal", json!("Alice"))),
        ),
        (
            Method::POST,
            "/v1/grants",
            Some(with(
                grant_request(),
                "/binding/brokered_services",
                json!(["openai", "anthropic"]),
            )),
        ),
        (
            Method::POST,
            "/v1/grants",
            Some(with(grant_request(), "/methods", json!(["CONNECT"]))),
        ),
        (
            Method::POST,
            "/v1/grants",
            Some(with(
                grant_request(),
                "/path_prefixes",
                json!(["/v1/../admin"]),
            )),
        ),
        (
            Method::POST,
            "/v1/grants",
            Some(with(grant_request(), "/max_ttl_seconds", json!(0))),
        ),
        (Method::POST, "/v1/grants/NOT-A-GRANT:renew", None),
        (
            Method::POST,
            "/v1/grants/fedcba9876543210fedcba9876543210:revoke",
            Some(json!({ "reason": "because" })),
        ),
        (
            Method::POST,
            "/v1/authorize",
            Some(json!({ "grant_id": GRANT })),
        ),
        (Method::GET, "/v1/profiles/Example", None),
        (
            Method::PUT,
            "/v1/profiles/other-profile",
            Some(publication()),
        ),
        (
            Method::PUT,
            "/v1/profiles/example-default",
            Some(with(publication(), "/document", json!("id: ["))),
        ),
        (
            Method::PUT,
            "/v1/profiles/example-default",
            Some(with(
                publication(),
                "/signatures/0/signature",
                json!("not base64!"),
            )),
        ),
        (
            Method::GET,
            "/v1/projects/gitlab:example%2Fservice/roles",
            None,
        ),
        (
            Method::POST,
            "/v1/projects/github:example%2Fservice/roles",
            Some(json!({ "principal": "oidc:bob@example.com", "role": "superuser" })),
        ),
        (
            Method::POST,
            "/v1/projects/github:example%2Fservice/roles",
            Some(json!({ "principal": "local-user:501:bob", "role": "member" })),
        ),
        (
            Method::POST,
            "/v1/exceptions",
            Some(with(exception_request(), "/reason", json!("  "))),
        ),
        (
            Method::POST,
            "/v1/exceptions",
            Some(with(
                exception_request(),
                "/scope/value",
                json!("two words"),
            )),
        ),
        (
            Method::POST,
            "/v1/exceptions",
            Some(with(
                exception_request(),
                "/approved_by",
                json!("oidc:bob@example.com"),
            )),
        ),
        (Method::GET, "/v1/audit/events?limit=0", None),
        (Method::GET, "/v1/audit/events?session=abc", None),
        (
            Method::GET,
            "/v1/audit/events?actor=oidc:alice@example.com",
            None,
        ),
    ];
    for (method, path, body) in cases {
        let response = test::call_service(
            &app,
            request(method.clone(), path, body.as_ref(), Some(TEST_TOKEN)),
        )
        .await;
        let (status, problem_body) = problem(response).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{method} {path} {body:?}: {problem_body}"
        );

        let response =
            test::call_service(&app, request(method.clone(), path, body.as_ref(), None)).await;
        let (status, _) = problem(response).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{method} {path} without a token"
        );
    }
}

#[actix_web::test]
async fn transport_errors_are_problems() {
    let app = service(database().await, Arc::new(MockAuthenticator)).await;
    let authorized = |request: test::TestRequest| {
        request
            .insert_header((header::AUTHORIZATION, format!("Bearer {TEST_TOKEN}")))
            .to_request()
    };

    let response = test::call_service(
        &app,
        authorized(
            test::TestRequest::post()
                .uri("/v1/authorize")
                .insert_header((header::CONTENT_TYPE, "text/plain"))
                .set_payload("{}"),
        ),
    )
    .await;
    assert_eq!(
        problem(response).await.0,
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );

    let oversized = json!({ "document": "x".repeat(2 * 1024 * 1024), "signatures": [] });
    let response = test::call_service(
        &app,
        authorized(
            test::TestRequest::put()
                .uri("/v1/profiles/example-default")
                .set_json(oversized),
        ),
    )
    .await;
    assert_eq!(problem(response).await.0, StatusCode::PAYLOAD_TOO_LARGE);

    let response = test::call_service(
        &app,
        authorized(test::TestRequest::delete().uri("/v1/grants")),
    )
    .await;
    assert_eq!(problem(response).await.0, StatusCode::METHOD_NOT_ALLOWED);

    let response = test::call_service(
        &app,
        authorized(test::TestRequest::get().uri("/v1/unknown")),
    )
    .await;
    assert_eq!(problem(response).await.0, StatusCode::NOT_FOUND);

    let response =
        test::call_service(&app, test::TestRequest::get().uri("/unknown").to_request()).await;
    assert_eq!(problem(response).await.0, StatusCode::NOT_FOUND);
}
