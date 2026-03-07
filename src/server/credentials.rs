//! `/csc/v2/credentials/list` and `/csc/v2/credentials/info` endpoints.

use actix_web::{web, HttpRequest, HttpResponse};

use crate::common::csc_types::{
    CertInfo, CredentialsInfoRequest, CredentialsInfoResponse, CredentialsListRequest,
    CredentialsListResponse, CscErrorResponse, KeyInfo,
};
use crate::server::app::AppState;
use crate::server::auth::{validate_bearer_token, USERS};

/// `POST /csc/v2/credentials/list`
pub async fn credentials_list_handler(
    req: HttpRequest,
    _body: web::Json<CredentialsListRequest>,
    _state: web::Data<AppState>,
) -> HttpResponse {
    // Validate token
    let claims = match validate_bearer_token(&req) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    // Find the user's credential(s)
    let credential_ids: Vec<String> = USERS
        .iter()
        .filter(|u| u.username == claims.sub)
        .map(|u| u.credential_id.to_string())
        .collect();

    log::info!(
        "User '{}' listed credentials: {:?}",
        claims.sub,
        credential_ids
    );

    HttpResponse::Ok().json(CredentialsListResponse { credential_ids })
}

/// `POST /csc/v2/credentials/info`
pub async fn credentials_info_handler(
    req: HttpRequest,
    body: web::Json<CredentialsInfoRequest>,
    state: web::Data<AppState>,
) -> HttpResponse {
    // Validate token
    let claims = match validate_bearer_token(&req) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    // Check that the user has access to this credential
    let has_access = USERS
        .iter()
        .any(|u| u.username == claims.sub && u.credential_id == body.credential_id);

    if !has_access {
        return HttpResponse::NotFound().json(CscErrorResponse {
            error: "invalid_request".to_string(),
            error_description: format!(
                "Credential '{}' not found for user '{}'",
                body.credential_id, claims.sub
            ),
        });
    }

    let pki = &state.pki;

    // Extract certificate metadata
    let user_cert = &pki.user_cert_parsed;

    let subject_dn = user_cert
        .subject_name()
        .user_friendly_str()
        .unwrap_or_else(|_| "Unknown".to_string());
    let issuer_dn = user_cert
        .issuer_name()
        .user_friendly_str()
        .unwrap_or_else(|_| "Unknown".to_string());

    // Get serial number
    let serial_number = format!("{:?}", user_cert.serial_number_asn1());

    // Get validity dates
    let validity = user_cert.validity_not_before();
    let valid_from = format!("{:?}", validity);
    let validity_after = user_cert.validity_not_after();
    let valid_to = format!("{:?}", validity_after);

    // Build certificate chain (Base64 DER)
    let certificates = if body.certificates == "chain" {
        pki.cert_chain_base64()
    } else {
        // "single" — just the user cert
        vec![pki.cert_chain_base64().into_iter().next().unwrap_or_default()]
    };

    let response = CredentialsInfoResponse {
        key: KeyInfo {
            status: "enabled".to_string(),
            algo: vec!["1.2.840.113549.1.1.11".to_string()], // RSA-SHA256
            len: 3072, // Nowina certs use 3072-bit RSA keys
        },
        cert: CertInfo {
            status: "valid".to_string(),
            certificates,
            issuer_dn,
            serial_number,
            subject_dn,
            valid_from,
            valid_to,
        },
        auth_mode: "implicit".to_string(),
    };

    log::info!(
        "User '{}' retrieved info for credential '{}'",
        claims.sub,
        body.credential_id
    );

    HttpResponse::Ok().json(response)
}

/// Configure credentials routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route(
        "/csc/v2/credentials/list",
        web::post().to(credentials_list_handler),
    )
    .route(
        "/csc/v2/credentials/info",
        web::post().to(credentials_info_handler),
    );
}

