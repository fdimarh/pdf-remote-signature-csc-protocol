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

use actix_web::{web, HttpRequest, HttpResponse};
use base64::Engine;

use crate::common::csc_types::{CscErrorResponse, SignPdfRequest, SignPdfResponse};
use crate::server::app::AppState;
use crate::server::auth::validate_bearer_token;
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

    // ── Decode PDF bytes ──
    let pdf_bytes = match b64.decode(&body.pdf_content) {
        Ok(b) => b,
        Err(e) => {
            return HttpResponse::BadRequest().json(CscErrorResponse {
                error: "invalid_request".into(),
                error_description: format!("Invalid Base64 in pdfContent: {}", e),
            });
        }
    };

    // ── Decode optional image bytes ──
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

    // ── Build visible signature config ──
    let visible_config = if let Some(img_bytes) = image_bytes {
        let rect = match body.sig_rect {
            Some(r) => r,
            None => {
                return HttpResponse::BadRequest().json(CscErrorResponse {
                    error: "invalid_request".into(),
                    error_description: "sigRect is required when imageContent is provided".into(),
                });
            }
        };
        Some(VisibleSignatureConfigBytes {
            image_bytes: img_bytes,
            page: body.sig_page,
            rect,
        })
    } else {
        None
    };

    let has_visible = visible_config.is_some();

    log::info!(
        "Server-side signPdf: {} bytes, visible={}, format={}, level={}",
        pdf_bytes.len(),
        has_visible,
        body.signature_format,
        body.pades_level,
    );

    // ── Step 1: Prepare the PDF (insert placeholder + optional image appearance) ──
    let prepared = match pdf_preparer::prepare_pdf_for_signing_from_bytes(
        &pdf_bytes,
        &body.signer_name,
        visible_config.as_ref(),
    ) {
        Ok(p) => p,
        Err(e) => {
            log::error!("PDF preparation failed: {}", e);
            return HttpResponse::BadRequest().json(CscErrorResponse {
                error: "preparation_error".into(),
                error_description: format!("Failed to prepare PDF: {}", e),
            });
        }
    };

    log::info!(
        "PDF prepared: {} bytes, hash={}",
        prepared.pdf_bytes.len(),
        prepared.hash.iter().map(|b| format!("{:02x}", b)).collect::<String>()
    );

    // ── Step 2: Build CMS signature ──
    let sig_format = body.signature_format.to_lowercase();
    let pades_level = body.pades_level.to_uppercase()
        .replace("BB", "B-B").replace("BT", "B-T")
        .replace("BLT", "B-LT").replace("BLTA", "B-LTA");

    let cms_options = CmsSigningOptions {
        signature_format: sig_format.clone(),
        pades_level: pades_level.clone(),
        timestamp_url: body.timestamp_url.clone(),
        include_crl: body.include_crl,
        include_ocsp: body.include_ocsp,
    };

    let pki = &state.pki;
    let cms_der = match build_cms_with_options(pki, &prepared.content_to_sign, &cms_options) {
        Ok(cms) => cms,
        Err(e) => {
            log::error!("CMS signing failed: {}", e);
            return HttpResponse::InternalServerError().json(CscErrorResponse {
                error: "server_error".into(),
                error_description: format!("CMS signing failed: {}", e),
            });
        }
    };

    log::info!(
        "CMS signature: {} bytes, format={}, level={}",
        cms_der.len(),
        sig_format,
        pades_level,
    );

    // ── Step 3: Embed CMS signature into prepared PDF ──
    let signed_pdf = match pdf_finalizer::embed_signature(
        &prepared.pdf_bytes,
        &cms_der,
        prepared.signature_size,
    ) {
        Ok(pdf) => pdf,
        Err(e) => {
            log::error!("Signature embedding failed: {}", e);
            return HttpResponse::InternalServerError().json(CscErrorResponse {
                error: "server_error".into(),
                error_description: format!("Failed to embed signature: {}", e),
            });
        }
    };

    log::info!(
        "User '{}' signed PDF (server-side): {} → {} bytes, format={}, level={}, visible={}",
        claims.sub,
        pdf_bytes.len(),
        signed_pdf.len(),
        sig_format,
        pades_level,
        has_visible,
    );

    // ── Step 4: Return signed PDF ──
    let pades_level_resp = if sig_format == "pades" {
        Some(pades_level)
    } else {
        None
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
    cfg.route("/api/v1/signPdf", web::post().to(sign_pdf_handler));
}

