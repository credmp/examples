// actix-web-middleware-keycloak-auth
//
// Copyright: 2020, David Sferruzza
// License: MIT

use actix_web::{middleware, web, App, HttpResponse, HttpServer, Responder};
use actix_web_middleware_keycloak_auth::{
    AlwaysReturnPolicy, DecodingKey, KeycloakAuth, KeycloakClaims, Role, StandardKeycloakClaims,
    UnstructuredKeycloakClaims,
};
use serde::Deserialize;

const KEYCLOAK_PK: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2X7tCFOjk8cwlX2t1awj
WWNoJxeB7d7XagFSabTmLiLDPwsOfWxPRSfS8pKeOHVuhEQeWMh/4R4VaPnHmo7Z
O4mvnyClbCHZnmRPsZg/fe7Ue4bUt+tZeQvUD2WUukRU3dJxoexQ/dGewitf0hqT
a6VZcXfrenS6yj1wjXTUdKXLPfh+SyRLxgcWD8NKm570L+DgcHimT3quXJofqRq1
Pi0T0eXXi714Y9WtZAB7Wa6X+1FzEwBPFdCIBUeilyzItFHsG5vplW+JEixWb1/+
Uh4s7DQYL89HeXgB/ZU4LogpmNezrzZQBL3Gi5aux6iMtWznE6MiNaYl1Mo5VRqj
GwIDAQAB
-----END PUBLIC KEY-----";

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "info,actix_web_middleware_keycloak_auth=trace");
    env_logger::init();

    HttpServer::new(|| {
        let keycloak_auth = KeycloakAuth::default_with_pk(
            DecodingKey::from_rsa_pem(KEYCLOAK_PK.as_bytes()).unwrap(),
        );

        App::new()
            .wrap(middleware::Logger::default())
            .service(
                web::scope("/private")
                    .wrap(keycloak_auth)
                    .route("", web::get().to(private)),
            )
            .service(web::resource("/").to(hello_world))
    })
    .bind("127.0.0.1:9080")?
    .workers(1)
    .run()
    .await
}

async fn hello_world() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

// Let's define a struct with only the claims we need (even if they are not standard)
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ClaimsWithEmail {
    // Custom claims
    email_verified: bool,
    preferred_username: String,
    name: String,
    given_name: String,
    family_name: String,
    email: String,
}

// We use this lib's extractor to deserialize the provided JWT into our struct (only if the JWT is valid)
async fn private(claims: KeycloakClaims<ClaimsWithEmail>) -> impl Responder {
    HttpResponse::Ok().body(format!("Hello {}", &claims.name))
}
