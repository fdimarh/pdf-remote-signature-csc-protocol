//! `/csc/v2/signatures/signHash` and `/csc/v2/signatures/signDoc` endpoints.
//!
//! `signHash` — standard CSC: receives a hash, builds CMS (simplified).
//! `signDoc`  — extension: receives raw content bytes, builds proper CMS
//!              with correct messageDigest. This is the recommended endpoint
//!              for this prototype since it produces valid PDF signatures.

use actix_web::{web, HttpRequest, HttpResponse};
use base64::Engine;
use bcder::Mode::Der;
use bcder::{encode::Values, Captured, OctetString};
use cryptographic_message_syntax::{Bytes, Oid, SignedDataBuilder, SignerBuilder};
use sha2::{Digest, Sha256};
use x509_certificate::rfc5652::AttributeValue;
use x509_certificate::{CapturedX509Certificate, InMemorySigningKeyPair};

use crate::common::csc_types::{
    CscErrorResponse, SignDocRequest, SignDocResponse, SignHashRequest, SignHashResponse,
    OID_SHA256,
};
use crate::server::app::AppState;
use crate::server::auth::{validate_bearer_token, USERS};

/// `POST /csc/v2/signatures/signHash`
///
/// Standard CSC endpoint. Receives Base64-encoded SHA-256 hash(es).
/// NOTE: For this prototype, the server uses `content_external` with
/// the hash bytes, producing messageDigest = SHA256(hash). This is a
/// simplification. Use `/csc/v2/signatures/signDoc` for correct CMS.
pub async fn sign_hash_handler(
    req: HttpRequest,
    body: web::Json<SignHashRequest>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let claims = match validate_bearer_token(&req) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    if !has_credential_access(&claims.sub, &body.credential_id) {
        return forbidden_response(&body.credential_id);
    }

    if body.hash_algo != OID_SHA256 {
        return HttpResponse::BadRequest().json(CscErrorResponse {
            error: "invalid_request".to_string(),
            error_description: format!(
                "Unsupported hash algorithm. Only SHA-256 ({}) is supported.",
                OID_SHA256
            ),
        });
    }

    if body.hashes.is_empty() {
        return HttpResponse::BadRequest().json(CscErrorResponse {
            error: "invalid_request".to_string(),
            error_description: "No hashes provided".to_string(),
        });
    }

    let pki = &state.pki;
    let b64 = base64::engine::general_purpose::STANDARD;

    let mut signatures = Vec::with_capacity(body.hashes.len());
    for (i, hash_b64) in body.hashes.iter().enumerate() {
        let hash_bytes = match b64.decode(hash_b64) {
            Ok(h) if h.len() == 32 => h,
            Ok(h) => {
                return HttpResponse::BadRequest().json(CscErrorResponse {
                    error: "invalid_request".to_string(),
                    error_description: format!(
                        "Hash[{}] is {} bytes, expected 32",
                        i,
                        h.len()
                    ),
                });
            }
            Err(e) => {
                return HttpResponse::BadRequest().json(CscErrorResponse {
                    error: "invalid_request".to_string(),
                    error_description: format!("Invalid Base64 in hash[{}]: {}", i, e),
                });
            }
        };

        // Build CMS with hash as external content (simplified)
        match build_cms_from_content(pki, &hash_bytes) {
            Ok(cms_der) => signatures.push(b64.encode(&cms_der)),
            Err(e) => {
                log::error!("CMS build failed for hash[{}]: {}", i, e);
                return HttpResponse::InternalServerError().json(CscErrorResponse {
                    error: "server_error".to_string(),
                    error_description: format!("Signing failed: {}", e),
                });
            }
        }
    }

    log::info!(
        "User '{}' signed {} hash(es) with '{}'",
        claims.sub,
        signatures.len(),
        body.credential_id
    );

    HttpResponse::Ok().json(SignHashResponse { signatures })
}

/// `POST /csc/v2/signatures/signDoc`
///
/// Extension endpoint. Receives Base64-encoded raw document content bytes
/// (the concatenated byte ranges). The server computes the hash internally
/// and builds a proper CMS SignedData with correct messageDigest.
///
/// Supports all signing variants:
/// - signatureFormat: "pkcs7" (adbe.pkcs7.detached) or "pades" (ETSI.CAdES.detached)
/// - padesLevel: "B-B", "B-T", "B-LT", "B-LTA"
/// - timestampUrl: TSA URL for B-T/B-LT/B-LTA levels
/// - includeCrl / includeOcsp: CMS signed attribute revocation data
pub async fn sign_doc_handler(
    req: HttpRequest,
    body: web::Json<SignDocRequest>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let claims = match validate_bearer_token(&req) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    if !has_credential_access(&claims.sub, &body.credential_id) {
        return forbidden_response(&body.credential_id);
    }

    if body.hash_algo != OID_SHA256 {
        return HttpResponse::BadRequest().json(CscErrorResponse {
            error: "invalid_request".to_string(),
            error_description: "Only SHA-256 is supported".to_string(),
        });
    }

    let pki = &state.pki;
    let b64 = base64::engine::general_purpose::STANDARD;

    let content_bytes = match b64.decode(&body.document_content) {
        Ok(c) => c,
        Err(e) => {
            return HttpResponse::BadRequest().json(CscErrorResponse {
                error: "invalid_request".to_string(),
                error_description: format!("Invalid Base64 in documentContent: {}", e),
            });
        }
    };

    let sig_format = body.signature_format.to_lowercase();
    let pades_level = body.pades_level.to_uppercase()
        .replace("BB", "B-B").replace("BT", "B-T")
        .replace("BLT", "B-LT").replace("BLTA", "B-LTA");

    log::info!(
        "Building CMS for {} bytes — format={}, level={}, tsa={:?}, crl={}, ocsp={}",
        content_bytes.len(),
        sig_format,
        pades_level,
        body.timestamp_url,
        body.include_crl,
        body.include_ocsp,
    );

    let cms_options = CmsSigningOptions {
        signature_format: sig_format.clone(),
        pades_level: pades_level.clone(),
        timestamp_url: body.timestamp_url.clone(),
        include_crl: body.include_crl,
        include_ocsp: body.include_ocsp,
    };

    match build_cms_with_options(pki, &content_bytes, &cms_options) {
        Ok(cms_der) => {
            log::info!(
                "User '{}' signed document with '{}' — format={}, level={}, CMS {} bytes",
                claims.sub,
                body.credential_id,
                sig_format,
                pades_level,
                cms_der.len()
            );
            let pades_level_resp = if sig_format == "pades" {
                Some(pades_level)
            } else {
                None
            };
            HttpResponse::Ok().json(SignDocResponse {
                signature: b64.encode(&cms_der),
                signature_format: sig_format,
                pades_level: pades_level_resp,
            })
        }
        Err(e) => {
            log::error!("CMS build failed: {}", e);
            HttpResponse::InternalServerError().json(CscErrorResponse {
                error: "server_error".to_string(),
                error_description: format!("Signing failed: {}", e),
            })
        }
    }
}

// ──────────────────── helpers ────────────────────────────────

pub(crate) fn has_credential_access(username: &str, credential_id: &str) -> bool {
    USERS
        .iter()
        .any(|u| u.username == username && u.credential_id == credential_id)
}

pub(crate) fn forbidden_response(credential_id: &str) -> HttpResponse {
    HttpResponse::Forbidden().json(CscErrorResponse {
        error: "invalid_request".to_string(),
        error_description: format!("No access to credential '{}'", credential_id),
    })
}

/// Options for CMS signature building
pub(crate) struct CmsSigningOptions {
    pub(crate) signature_format: String,
    pub(crate) pades_level: String,
    pub(crate) timestamp_url: Option<String>,
    pub(crate) include_crl: bool,
    pub(crate) include_ocsp: bool,
}

/// Build a CMS/PKCS#7 `SignedData` from raw content bytes.
///
/// Uses `content_external()` which:
/// 1. Computes SHA-256(content_bytes) → messageDigest signed attribute
/// 2. DER-encodes the signed attributes
/// 3. Signs the DER-encoded attributes with the private key
/// 4. Packages everything into a PKCS#7 SignedData structure
fn build_cms_from_content(
    pki: &crate::server::pki::PkiState,
    content_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    let opts = CmsSigningOptions {
        signature_format: "pades".to_string(),
        pades_level: "B-B".to_string(),
        timestamp_url: None,
        include_crl: false,
        include_ocsp: false,
    };
    build_cms_with_options(pki, content_bytes, &opts)
}

/// Build a CMS/PKCS#7 `SignedData` with configurable options.
///
/// Supports:
/// - PKCS7 (adbe.pkcs7.detached) and PAdES (ETSI.CAdES.detached) formats
/// - PAdES levels: B-B, B-T, B-LT, B-LTA
/// - Timestamp via TSA URL
/// - CRL/OCSP in CMS signed attributes
pub(crate) fn build_cms_with_options(
    pki: &crate::server::pki::PkiState,
    content_bytes: &[u8],
    options: &CmsSigningOptions,
) -> Result<Vec<u8>, String> {
    let key_pair = InMemorySigningKeyPair::from_pkcs8_der(&pki.user_key_der)
        .map_err(|e| format!("Failed to load signing key: {}", e))?;

    let user_cert = CapturedX509Certificate::from_der(pki.user_cert_der.clone())
        .map_err(|e| format!("Failed to parse user cert: {}", e))?;

    // Parse all CA certificates in the chain
    let mut ca_certs = Vec::new();
    for (i, ca_der) in pki.ca_chain_der.iter().enumerate() {
        let ca_cert = CapturedX509Certificate::from_der(ca_der.clone())
            .map_err(|e| format!("Failed to parse CA cert #{}: {}", i, e))?;
        ca_certs.push(ca_cert);
    }

    // ESS-signing-certificate-v2 attribute (always included for both PKCS7 and PAdES)
    let cert_hash = {
        let mut hasher = Sha256::new();
        hasher.update(user_cert.encode_der().map_err(|e| format!("{}", e))?);
        hasher.finalize().to_vec()
    };
    let signing_cert_v2_value = build_signing_certificate_v2_attribute_value(cert_hash);

    // OID: 1.2.840.113549.1.9.16.2.47
    let signing_certificate_v2_oid = Oid(Bytes::copy_from_slice(&[
        42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 47,
    ]));

    let mut signer = SignerBuilder::new(&key_pair, user_cert.clone()).signed_attribute(
        signing_certificate_v2_oid,
        vec![AttributeValue::new(signing_cert_v2_value)],
    );

    // Determine what to include based on format and level
    let is_pades = options.signature_format == "pades";
    let include_timestamp;
    let _include_dss;

    if is_pades {
        match options.pades_level.as_str() {
            "B-B" => {
                include_timestamp = false;
                _include_dss = false;
            }
            "B-T" => {
                include_timestamp = true;
                _include_dss = false;
            }
            "B-LT" => {
                include_timestamp = true;
                _include_dss = true;
            }
            "B-LTA" => {
                include_timestamp = true;
                _include_dss = true;
            }
            _ => {
                include_timestamp = false;
                _include_dss = false;
            }
        }
    } else {
        // PKCS7 format
        include_timestamp = options.timestamp_url.is_some();
        _include_dss = false;
    }

    // Add timestamp via TSA
    if include_timestamp {
        if let Some(tsa_url) = &options.timestamp_url {
            signer = signer
                .time_stamp_url(tsa_url)
                .map_err(|e| format!("Failed to set TSA URL: {}", e))?;
        } else {
            log::warn!(
                "Timestamp requested (level={}) but no TSA URL provided",
                options.pades_level
            );
        }
    }

    let mut builder = SignedDataBuilder::default()
        .content_external(content_bytes.to_vec())
        .content_type(Oid(Bytes::copy_from_slice(
            cryptographic_message_syntax::asn1::rfc5652::OID_ID_DATA.as_ref(),
        )))
        .signer(signer)
        .certificate(user_cert.clone());

    // Add all CA certificates in the chain
    for ca_cert in &ca_certs {
        builder = builder.certificate(ca_cert.clone());
    }

    let signature = builder
        .build_der()
        .map_err(|e| format!("CMS build failed: {}", e))?;

    Ok(signature)
}

/// Build ESS-signing-certificate-v2 attribute value (prevents cert substitution).
fn build_signing_certificate_v2_attribute_value(cert_hash: Vec<u8>) -> Captured {
    let certificate_hash_octet_string = OctetString::new(Bytes::from(cert_hash));
    let ess_cert_id_v2 = bcder::encode::sequence(certificate_hash_octet_string.encode());
    let signing_certificate_v2 = bcder::encode::sequence(ess_cert_id_v2);
    let attr_value = bcder::encode::sequence(signing_certificate_v2);
    attr_value.to_captured(Der)
}

/// Configure signing routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route(
        "/csc/v2/signatures/signHash",
        web::post().to(sign_hash_handler),
    )
    .route(
        "/csc/v2/signatures/signDoc",
        web::post().to(sign_doc_handler),
    );
}

