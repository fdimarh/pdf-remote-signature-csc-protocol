//! `/api/v1/signPdf` endpoint — server-side full PDF signing.
//!
//! Accepts a complete PDF file + optional signature image, and performs
//! the entire pipeline server-side:
//! 1. Prepare PDF (insert signature placeholder with optional visible image)
//! 2. Compute hash of the byte ranges
//! 3. Build CMS/PKCS#7 signature
//! 4. Embed signature into PDF
//! 5. Return the fully signed PDF
//!
//! This is the "full server-side rendering" model — the client just uploads
//! the PDF and image, and downloads the signed result in one HTTP call.

use actix_multipart::Multipart;
use actix_web::{web, HttpRequest, HttpResponse};
use base64::Engine;

use crate::common::csc_types::{CscErrorResponse, SignPdfRequest, SignPdfResponse};
use crate::server::app::AppState;
use crate::server::auth::validate_bearer_token;
use crate::server::multipart::extract_multipart_fields;
use crate::server::signing::{
    build_cms_with_options, has_credential_access, forbidden_response, CmsSigningOptions,
};
use crate::client::pdf_finalizer;
use crate::client::pdf_preparer::{self, VisibleSignatureConfigBytes};

/// `POST /api/v1/signPdf`
///
/// Full server-side PDF signing with optional visible signature image.
///
/// Accepts:
/// - `pdfContent`: Base64-encoded PDF file bytes
/// - `imageContent`: Optional Base64-encoded PNG/JPEG image
/// - `sigRect`: [x1, y1, x2, y2] rectangle for visible signature
/// - `sigPage`: target page number (1-based)
/// - Format/level/TSA options same as signDoc
///
/// Returns the fully signed PDF as Base64.
pub async fn sign_pdf_handler(
    req: HttpRequest,
    body: web::Json<SignPdfRequest>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let claims = match validate_bearer_token(&req) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    if !has_credential_access(&claims.sub, &body.credential_id) {
        return forbidden_response(&body.credential_id);
    }

    let b64 = base64::engine::general_purpose::STANDARD;

    // Decode PDF bytes
    let pdf_bytes = match b64.decode(&body.pdf_content) {
        Ok(b) => b,
        Err(e) => {
            return HttpResponse::BadRequest().json(CscErrorResponse {
                error: "invalid_request".into(),
                error_description: format!("Invalid Base64 in pdfContent: {}", e),
            });
        }
    };

    // Decode optional image bytes
    let image_bytes = if let Some(ref img_b64) = body.image_content {
        match b64.decode(img_b64) {
            Ok(b) => Some(b),
            Err(e) => {
                return HttpResponse::BadRequest().json(CscErrorResponse {
                    error: "invalid_request".into(),
                    error_description: format!("Invalid Base64 in imageContent: {}", e),
                });
            }
        }
    } else {
        None
    };

    let params = SignPdfParams {
        credential_id: body.credential_id.clone(),
        pdf_bytes,
        image_bytes,
        sig_rect: body.sig_rect,
        sig_page: body.sig_page,
        signer_name: body.signer_name.clone(),
        signature_format: body.signature_format.clone(),
        pades_level: body.pades_level.clone(),
        timestamp_url: body.timestamp_url.clone(),
        include_crl: body.include_crl,
        include_ocsp: body.include_ocsp,
    };

    let (signed_pdf, sig_format, pades_level_resp, has_visible) =
        match execute_sign_pdf(&params, &state.pki, &claims.sub) {
            Ok(result) => result,
            Err(resp) => return resp,
        };

    HttpResponse::Ok().json(SignPdfResponse {
        signed_pdf: b64.encode(&signed_pdf),
        signature_format: sig_format,
        pades_level: pades_level_resp,
        has_visible_signature: has_visible,
    })
}

/// Configure sign-pdf routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/v1/signPdf", web::post().to(sign_pdf_handler))
        .route("/api/v1/signPdf/form", web::post().to(sign_pdf_form_handler));
}

// ──────────────────────────────────────────────────────────────
// Core signing logic (shared by JSON and form-data handlers)
// ──────────────────────────────────────────────────────────────

/// Parameters extracted from either JSON body or multipart form.
struct SignPdfParams {
    credential_id: String,
    pdf_bytes: Vec<u8>,
    image_bytes: Option<Vec<u8>>,
    sig_rect: Option<[f32; 4]>,
    sig_page: u32,
    signer_name: String,
    signature_format: String,
    pades_level: String,
    timestamp_url: Option<String>,
    include_crl: bool,
    include_ocsp: bool,
}

/// Execute the full server-side signing pipeline.
///
/// Shared by `sign_pdf_handler` (JSON) and `sign_pdf_form_handler` (form-data).
fn execute_sign_pdf(
    params: &SignPdfParams,
    pki: &crate::server::pki::PkiState,
    username: &str,
) -> Result<(Vec<u8>, String, Option<String>, bool), HttpResponse> {
    // Build visible signature config
    let visible_config = if let Some(ref img_bytes) = params.image_bytes {
        let rect = match params.sig_rect {
            Some(r) => r,
            None => {
                return Err(HttpResponse::BadRequest().json(CscErrorResponse {
                    error: "invalid_request".into(),
                    error_description: "sigRect is required when image is provided".into(),
                }));
            }
        };
        Some(VisibleSignatureConfigBytes {
            image_bytes: img_bytes.clone(),
            page: params.sig_page,
            rect,
        })
    } else {
        None
    };

    let has_visible = visible_config.is_some();

    log::info!(
        "Server-side signPdf: {} bytes, visible={}, format={}, level={}",
        params.pdf_bytes.len(),
        has_visible,
        params.signature_format,
        params.pades_level,
    );

    // Step 1: Prepare PDF
    let prepared = match pdf_preparer::prepare_pdf_for_signing_from_bytes(
        &params.pdf_bytes,
        &params.signer_name,
        visible_config.as_ref(),
    ) {
        Ok(p) => p,
        Err(e) => {
            log::error!("PDF preparation failed: {}", e);
            return Err(HttpResponse::BadRequest().json(CscErrorResponse {
                error: "preparation_error".into(),
                error_description: format!("Failed to prepare PDF: {}", e),
            }));
        }
    };

    log::info!(
        "PDF prepared: {} bytes, hash={}",
        prepared.pdf_bytes.len(),
        prepared.hash.iter().map(|b| format!("{:02x}", b)).collect::<String>()
    );

    // Step 2: Build CMS signature
    let sig_format = params.signature_format.to_lowercase();
    let pades_level = params.pades_level.to_uppercase()
        .replace("BB", "B-B").replace("BT", "B-T")
        .replace("BLT", "B-LT").replace("BLTA", "B-LTA");

    let cms_options = CmsSigningOptions {
        signature_format: sig_format.clone(),
        pades_level: pades_level.clone(),
        timestamp_url: params.timestamp_url.clone(),
        include_crl: params.include_crl,
        include_ocsp: params.include_ocsp,
    };

    let cms_der = match build_cms_with_options(pki, &prepared.content_to_sign, &cms_options) {
        Ok(cms) => cms,
        Err(e) => {
            log::error!("CMS signing failed: {}", e);
            return Err(HttpResponse::InternalServerError().json(CscErrorResponse {
                error: "server_error".into(),
                error_description: format!("CMS signing failed: {}", e),
            }));
        }
    };

    log::info!("CMS signature: {} bytes, format={}, level={}", cms_der.len(), sig_format, pades_level);

    // Step 3: Embed CMS into PDF
    let signed_pdf = match pdf_finalizer::embed_signature(
        &prepared.pdf_bytes,
        &cms_der,
        prepared.signature_size,
    ) {
        Ok(pdf) => pdf,
        Err(e) => {
            log::error!("Signature embedding failed: {}", e);
            return Err(HttpResponse::InternalServerError().json(CscErrorResponse {
                error: "server_error".into(),
                error_description: format!("Failed to embed signature: {}", e),
            }));
        }
    };

    log::info!(
        "User '{}' signed PDF (server-side): {} → {} bytes, format={}, level={}, visible={}",
        username, params.pdf_bytes.len(), signed_pdf.len(), sig_format, pades_level, has_visible,
    );

    let pades_level_resp = if sig_format == "pades" { Some(pades_level) } else { None };
    Ok((signed_pdf, sig_format, pades_level_resp, has_visible))
}

// ──────────────────────────────────────────────────────────────
// Form-data handler: POST /api/v1/signPdf/form
// ──────────────────────────────────────────────────────────────

/// `POST /api/v1/signPdf/form`
///
/// Multipart form-data alternative for server-side PDF signing.
///
/// Form fields:
/// - `file` (required): PDF file upload
/// - `image`: Optional PNG/JPEG signature image file upload
/// - `credentialID`: Signing credential ID [default: "credential-001"]
/// - `signerName`: Display name [default: "Digital Signature"]
/// - `signatureFormat`: "pkcs7" or "pades" [default: "pades"]
/// - `padesLevel`: "B-B", "B-T", "B-LT", "B-LTA" [default: "B-B"]
/// - `timestampUrl`: TSA URL (optional)
/// - `sigPage`: Page number, 1-based [default: 1]
/// - `sigRect`: "x1,y1,x2,y2" rectangle [default: "50,50,250,150"]
/// - `includeCrl`: "true"/"false" [default: false]
/// - `includeOcsp`: "true"/"false" [default: false]
/// - `responseFormat`: "json" or "binary" [default: "binary"]
///
/// Returns:
/// - If `responseFormat=binary` (default): raw signed PDF bytes with
///   `Content-Type: application/pdf` and `Content-Disposition: attachment`
/// - If `responseFormat=json`: same JSON as the JSON endpoint
///
/// Example with curl:
/// ```sh
/// curl -X POST http://localhost:8080/api/v1/signPdf/form \
///   -H "Authorization: Bearer <token>" \
///   -F "file=@document.pdf" \
///   -F "image=@signature.png" \
///   -F "sigRect=50,50,250,150" \
///   -F "signerName=John Doe" \
///   -o signed.pdf
/// ```
pub async fn sign_pdf_form_handler(
    req: HttpRequest,
    payload: Multipart,
    state: web::Data<AppState>,
) -> HttpResponse {
    let claims = match validate_bearer_token(&req) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    // Extract multipart fields
    let fields = match extract_multipart_fields(payload).await {
        Ok(f) => f,
        Err(e) => {
            return HttpResponse::BadRequest().json(CscErrorResponse {
                error: "invalid_request".into(),
                error_description: format!("Failed to parse form data: {}", e),
            });
        }
    };

    // Required: PDF file
    let pdf_bytes = match fields.get("file") {
        Some(f) if !f.bytes.is_empty() => f.bytes.clone(),
        _ => {
            return HttpResponse::BadRequest().json(CscErrorResponse {
                error: "invalid_request".into(),
                error_description: "Missing required field 'file' (PDF file upload)".into(),
            });
        }
    };

    // Optional: image file
    let image_bytes = fields
        .get("image")
        .filter(|f| !f.bytes.is_empty())
        .map(|f| f.bytes.clone());

    // Text fields with defaults
    let credential_id = fields
        .get("credentialID")
        .and_then(|f| f.as_text())
        .unwrap_or("credential-001")
        .to_string();

    let signer_name = fields
        .get("signerName")
        .and_then(|f| f.as_text())
        .unwrap_or("Digital Signature")
        .to_string();

    let signature_format = fields
        .get("signatureFormat")
        .and_then(|f| f.as_text())
        .unwrap_or("pades")
        .to_string();

    let pades_level = fields
        .get("padesLevel")
        .and_then(|f| f.as_text())
        .unwrap_or("B-B")
        .to_string();

    let timestamp_url = fields
        .get("timestampUrl")
        .and_then(|f| f.as_text())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let sig_page = fields
        .get("sigPage")
        .and_then(|f| f.as_u32())
        .unwrap_or(1);

    let include_crl = fields
        .get("includeCrl")
        .map(|f| f.as_bool())
        .unwrap_or(false);

    let include_ocsp = fields
        .get("includeOcsp")
        .map(|f| f.as_bool())
        .unwrap_or(false);

    let response_format = fields
        .get("responseFormat")
        .and_then(|f| f.as_text())
        .unwrap_or("binary")
        .to_lowercase();

    // Parse sigRect: "x1,y1,x2,y2"
    let sig_rect = if image_bytes.is_some() {
        let rect_str = fields
            .get("sigRect")
            .and_then(|f| f.as_text())
            .unwrap_or("50,50,250,150");
        match parse_rect_str(rect_str) {
            Ok(r) => Some(r),
            Err(e) => {
                return HttpResponse::BadRequest().json(CscErrorResponse {
                    error: "invalid_request".into(),
                    error_description: format!("Invalid sigRect '{}': {}", rect_str, e),
                });
            }
        }
    } else {
        None
    };

    // Check credential access
    if !has_credential_access(&claims.sub, &credential_id) {
        return forbidden_response(&credential_id);
    }

    log::info!(
        "Form-data signPdf: {} bytes, image={}, format={}, level={}, response={}",
        pdf_bytes.len(),
        image_bytes.as_ref().map(|b| b.len()).unwrap_or(0),
        signature_format,
        pades_level,
        response_format,
    );

    let params = SignPdfParams {
        credential_id,
        pdf_bytes,
        image_bytes,
        sig_rect,
        sig_page,
        signer_name,
        signature_format,
        pades_level,
        timestamp_url,
        include_crl,
        include_ocsp,
    };

    let (signed_pdf, sig_format, pades_level_resp, has_visible) =
        match execute_sign_pdf(&params, &state.pki, &claims.sub) {
            Ok(result) => result,
            Err(resp) => return resp,
        };

    // Return based on responseFormat
    if response_format == "json" {
        let b64 = base64::engine::general_purpose::STANDARD;
        HttpResponse::Ok().json(SignPdfResponse {
            signed_pdf: b64.encode(&signed_pdf),
            signature_format: sig_format,
            pades_level: pades_level_resp,
            has_visible_signature: has_visible,
        })
    } else {
        // Default: return raw binary PDF
        HttpResponse::Ok()
            .content_type("application/pdf")
            .insert_header((
                "Content-Disposition",
                "attachment; filename=\"signed.pdf\"",
            ))
            .insert_header(("X-Signature-Format", sig_format.as_str()))
            .insert_header((
                "X-Has-Visible-Signature",
                if has_visible { "true" } else { "false" },
            ))
            .body(signed_pdf)
    }
}

/// Parse "x1,y1,x2,y2" string into [f32; 4].
fn parse_rect_str(s: &str) -> Result<[f32; 4], String> {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() != 4 {
        return Err(format!("Expected 4 values, got {}", parts.len()));
    }
    let vals: Result<Vec<f32>, _> = parts.iter().map(|p| p.trim().parse::<f32>()).collect();
    let vals = vals.map_err(|e| format!("Invalid number: {}", e))?;
    Ok([vals[0], vals[1], vals[2], vals[3]])
}

