//! `/api/v1/validate` endpoint — validate PDF digital signatures.
//!
//! Uses the `pdf_signing::signature_validator::SignatureValidator` to perform
//! comprehensive validation including:
//! - CMS/PKCS#7 signature integrity
//! - Certificate chain validation
//! - ByteRange structural checks (USF attack defense)
//! - Signature wrapping detection (SWA attack defense)
//! - MDP certification permission enforcement
//! - Modification detection after signing
//! - LTV / DSS dictionary analysis
//! - Timestamp presence detection

use actix_multipart::Multipart;
use actix_web::{web, HttpResponse};
use base64::Engine;
use pdf_signing::signature_validator::SignatureValidator;

use crate::common::csc_types::{
    CscErrorResponse, SignatureValidationResult, ValidateCertInfo, ValidateRequest,
    ValidateResponse,
};
use crate::server::multipart::extract_multipart_fields;

/// `POST /api/v1/validate`
///
/// Accepts a Base64-encoded PDF and returns comprehensive validation results
/// for every digital signature found in the document.
pub async fn validate_handler(body: web::Json<ValidateRequest>) -> HttpResponse {
    let b64 = base64::engine::general_purpose::STANDARD;

    let pdf_bytes = match b64.decode(&body.pdf_content) {
        Ok(b) => b,
        Err(e) => {
            return HttpResponse::BadRequest().json(CscErrorResponse {
                error: "invalid_request".to_string(),
                error_description: format!("Invalid Base64 in pdfContent: {}", e),
            });
        }
    };

    let password = body.password.as_ref().map(|p| p.as_bytes());
    execute_validate(&pdf_bytes, password)
}

/// `POST /api/v1/validate/form`
///
/// Multipart form-data alternative for PDF signature validation.
///
/// Form fields:
/// - `file` (required): PDF file upload
/// - `password`: Optional password for encrypted PDFs
///
/// Example with curl:
/// ```sh
/// curl -X POST http://localhost:8080/api/v1/validate/form \
///   -F "file=@signed.pdf"
/// ```
pub async fn validate_form_handler(payload: Multipart) -> HttpResponse {
    let fields = match extract_multipart_fields(payload).await {
        Ok(f) => f,
        Err(e) => {
            return HttpResponse::BadRequest().json(CscErrorResponse {
                error: "invalid_request".into(),
                error_description: format!("Failed to parse form data: {}", e),
            });
        }
    };

    let pdf_bytes = match fields.get("file") {
        Some(f) if !f.bytes.is_empty() => &f.bytes,
        _ => {
            return HttpResponse::BadRequest().json(CscErrorResponse {
                error: "invalid_request".into(),
                error_description: "Missing required field 'file' (PDF file upload)".into(),
            });
        }
    };

    let password_str = fields
        .get("password")
        .and_then(|f| f.as_text())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let password = password_str.as_ref().map(|p| p.as_bytes());

    execute_validate(pdf_bytes, password)
}

/// Core validation logic shared by JSON and form-data handlers.
fn execute_validate(pdf_bytes: &[u8], password: Option<&[u8]>) -> HttpResponse {

    log::info!(
        "Validating PDF: {} bytes, password={}",
        pdf_bytes.len(),
        password.is_some()
    );

    let results = match SignatureValidator::validate_with_password(&pdf_bytes, password) {
        Ok(r) => r,
        Err(e) => {
            let msg = format!("{}", e);
            // Distinguish "no signatures" from real errors
            if msg.contains("No digital signature") {
                return HttpResponse::Ok().json(ValidateResponse {
                    signature_count: 0,
                    all_valid: false,
                    signatures: vec![],
                });
            }
            log::error!("Validation failed: {}", msg);
            return HttpResponse::BadRequest().json(CscErrorResponse {
                error: "validation_error".to_string(),
                error_description: msg,
            });
        }
    };

    let all_valid = results.iter().all(|r| r.is_valid());
    let signature_count = results.len();

    let signatures: Vec<SignatureValidationResult> = results
        .into_iter()
        .map(|r| {
            let certificates: Vec<ValidateCertInfo> = r
                .certificates
                .iter()
                .map(|c| ValidateCertInfo {
                    subject: c.subject.clone(),
                    issuer: c.issuer.clone(),
                    serial_number: c.serial_number.clone(),
                    not_before: c.not_before.map(|d| d.to_rfc3339()),
                    not_after: c.not_after.map(|d| d.to_rfc3339()),
                    is_expired: c.is_expired,
                    is_self_signed: c.is_self_signed,
                })
                .collect();

            SignatureValidationResult {
                field_name: r.field_info.field_name.clone(),
                signer_name: r.signer_name.clone(),
                contact_info: r.contact_info.clone(),
                reason: r.reason.clone(),
                signing_time: r.signing_time.clone(),
                filter: r.filter.clone(),
                sub_filter: r.sub_filter.clone(),
                is_valid: r.is_valid(),
                digest_match: r.digest_match,
                cms_signature_valid: r.cms_signature_valid,
                certificate_chain_valid: r.certificate_chain_valid,
                certificate_chain_trusted: r.certificate_chain_trusted,
                byte_range: r.byte_range.clone(),
                byte_range_valid: r.byte_range_valid,
                byte_range_covers_whole_file: r.byte_range_covers_whole_file,
                has_dss: r.has_dss,
                dss_crl_count: r.dss_crl_count,
                dss_ocsp_count: r.dss_ocsp_count,
                dss_cert_count: r.dss_cert_count,
                has_vri: r.has_vri,
                has_cms_revocation_data: r.has_cms_revocation_data,
                has_timestamp: r.has_timestamp,
                is_ltv_enabled: r.is_ltv_enabled,
                no_unauthorized_modifications: r.no_unauthorized_modifications,
                modification_notes: r.modification_notes.clone(),
                signature_not_wrapped: r.signature_not_wrapped,
                certification_level: r.certification_level,
                certification_permission_ok: r.certification_permission_ok,
                security_warnings: r.security_warnings.clone(),
                chain_warnings: r.chain_warnings.clone(),
                certificates,
                errors: r.errors.clone(),
                is_encrypted: r.is_encrypted,
                is_document_timestamp: r.field_info.is_document_timestamp,
            }
        })
        .collect();

    log::info!(
        "Validation complete: {} signature(s), all_valid={}",
        signature_count,
        all_valid
    );

    HttpResponse::Ok().json(ValidateResponse {
        signature_count,
        all_valid,
        signatures,
    })
}

/// Configure validation routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/v1/validate", web::post().to(validate_handler))
        .route("/api/v1/validate/form", web::post().to(validate_form_handler));
}

