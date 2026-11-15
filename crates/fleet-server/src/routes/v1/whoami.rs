//! `GET /v1/whoami`: the identity this service authenticated.

use actix_web::web;
use sendbox_governance::api::CallerIdentity;

use crate::auth::Authenticated;
use crate::routes::resource;

pub fn configure(config: &mut web::ServiceConfig) {
    config.service(resource("/whoami").route(web::get().to(whoami)));
}

async fn whoami(Authenticated(caller): Authenticated) -> web::Json<CallerIdentity> {
    web::Json(CallerIdentity {
        principal: caller.principal,
        kind: caller.kind,
        operator: caller.operator,
    })
}
