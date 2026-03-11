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
use x509_certificate::CapturedX509Certificate;

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
        sig_tag: body.sig_tag.clone(),
        sig_tag_width: body.sig_tag_width,
        sig_tag_height: body.sig_tag_height,
        sig_tag_mode: body.sig_tag_mode.clone(),
    };

    let (signed_pdf, sig_format, pades_level_resp, has_visible, is_tag_mode) =
        match execute_sign_pdf(&params, &state.pki, &claims.sub, &state).await {
            Ok(result) => result,
            Err(resp) => return resp,
        };

    HttpResponse::Ok().json(SignPdfResponse {
        signed_pdf: b64.encode(&signed_pdf),
        signature_format: sig_format,
        pades_level: pades_level_resp,
        has_visible_signature: has_visible,
        tag_mode: if is_tag_mode { Some(true) } else { None },
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
    /// Tag mode: text marker to locate in the PDF content stream
    sig_tag: Option<String>,
    /// Tag mode: width of the visible signature box
    sig_tag_width: Option<f64>,
    /// Tag mode: height of the visible signature box
    sig_tag_height: Option<f64>,
    /// Tag mode: placement mode ("in_front" or "overlay")
    sig_tag_mode: Option<String>,
}

/// Execute the full server-side signing pipeline.
///
/// Shared by `sign_pdf_handler` (JSON) and `sign_pdf_form_handler` (form-data).
///
/// When tag mode is active (`sig_tag` is set), the pipeline delegates to the
/// `pdf_signing` library's `sign_document_no_placeholder` which handles tag
/// resolution, visible signature placement, and cryptographic signing internally.
async fn execute_sign_pdf(
    params: &SignPdfParams,
    pki: &crate::server::pki::PkiState,
    username: &str,
    state: &web::Data<AppState>,
) -> Result<(Vec<u8>, String, Option<String>, bool, bool), HttpResponse> {
    let is_tag_mode = params.sig_tag.is_some();

    // ── TAG MODE: Use the library's sign_document_no_placeholder ──
    if is_tag_mode {
        return execute_sign_pdf_tag_mode(params, pki, username, state).await;
    }

    // ── STANDARD MODE: Use the existing prepare → CMS → embed pipeline ──
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

    // Run CMS building on a blocking thread — the TSA timestamp request
    // uses a synchronous HTTP client internally which would deadlock tokio.
    let pki_clone = pki.clone();
    let content = prepared.content_to_sign.clone();
    let cms_opts = cms_options.clone();
    let backend = state.backend.clone();
    let cms_der = match tokio::task::spawn_blocking(move || {
        build_cms_with_options(&pki_clone, &content, &cms_opts, Some(backend.as_ref()))
    })
    .await
    {
        Ok(Ok(cms)) => cms,
        Ok(Err(e)) => {
            log::error!("CMS signing failed: {}", e);
            return Err(HttpResponse::InternalServerError().json(CscErrorResponse {
                error: "server_error".into(),
                error_description: format!("CMS signing failed: {}", e),
            }));
        }
        Err(e) => {
            log::error!("CMS signing task panicked: {}", e);
            return Err(HttpResponse::InternalServerError().json(CscErrorResponse {
                error: "server_error".into(),
                error_description: "Internal signing error".into(),
            }));
        }
    };

    log::info!("CMS signature: {} bytes, format={}, level={}", cms_der.len(), sig_format, pades_level);

    // Step 3: Embed CMS into PDF
    let mut signed_pdf = match pdf_finalizer::embed_signature(
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

    // Step 4: Append DSS dictionary for B-LT and B-LTA (incremental update)
    let is_pades = sig_format == "pades";
    let include_dss = is_pades && matches!(pades_level.as_str(), "B-LT" | "B-LTA");

    if include_dss {
        log::info!("Appending DSS dictionary for PAdES {}", pades_level);

        // Build the full certificate chain for DSS
        let pki_clone = pki.clone();
        let pdf_for_dss = signed_pdf.clone();
        let dss_result = tokio::task::spawn_blocking(move || {
            let user_cert = CapturedX509Certificate::from_der(pki_clone.user_cert_der.clone())
                .map_err(|e| format!("{}", e))?;
            let mut chain = vec![user_cert];
            for ca_der in &pki_clone.ca_chain_der {
                let ca = CapturedX509Certificate::from_der(ca_der.clone())
                    .map_err(|e| format!("{}", e))?;
                chain.push(ca);
            }
            crate::server::ltv::append_dss_dictionary(pdf_for_dss, chain)
        })
        .await;

        match dss_result {
            Ok(Ok(pdf_with_dss)) => {
                log::info!(
                    "DSS appended: {} → {} bytes",
                    signed_pdf.len(),
                    pdf_with_dss.len()
                );
                signed_pdf = pdf_with_dss;
            }
            Ok(Err(e)) => {
                log::error!("DSS append failed: {}", e);
                return Err(HttpResponse::InternalServerError().json(CscErrorResponse {
                    error: "server_error".into(),
                    error_description: format!("Failed to append DSS: {}", e),
                }));
            }
            Err(e) => {
                log::error!("DSS task panicked: {}", e);
                return Err(HttpResponse::InternalServerError().json(CscErrorResponse {
                    error: "server_error".into(),
                    error_description: "Internal error appending DSS".into(),
                }));
            }
        }
    }

    // Step 5: Append document-level timestamp for B-LTA (incremental update)
    if is_pades && pades_level == "B-LTA" {
        if let Some(ref tsa_url) = params.timestamp_url {
            log::info!("Appending document timestamp for PAdES B-LTA");

            let pdf_for_ts = signed_pdf.clone();
            let tsa = tsa_url.clone();
            let ts_result = tokio::task::spawn_blocking(move || {
                crate::server::ltv::append_document_timestamp(pdf_for_ts, &tsa, 30_000)
            })
            .await;

            match ts_result {
                Ok(Ok(pdf_with_ts)) => {
                    log::info!(
                        "Document timestamp appended: {} → {} bytes",
                        signed_pdf.len(),
                        pdf_with_ts.len()
                    );
                    signed_pdf = pdf_with_ts;
                }
                Ok(Err(e)) => {
                    log::error!("Document timestamp failed: {}", e);
                    return Err(HttpResponse::InternalServerError().json(CscErrorResponse {
                        error: "server_error".into(),
                        error_description: format!("Failed to add document timestamp: {}", e),
                    }));
                }
                Err(e) => {
                    log::error!("Document timestamp task panicked: {}", e);
                    return Err(HttpResponse::InternalServerError().json(CscErrorResponse {
                        error: "server_error".into(),
                        error_description: "Internal error adding document timestamp".into(),
                    }));
                }
            }
        } else {
            log::warn!("B-LTA requested but no TSA URL provided for document timestamp");
        }
    }

    log::info!(
        "User '{}' signed PDF (server-side): {} → {} bytes, format={}, level={}, visible={}",
        username, params.pdf_bytes.len(), signed_pdf.len(), sig_format, pades_level, has_visible,
    );

    let pades_level_resp = if sig_format == "pades" { Some(pades_level) } else { None };
    Ok((signed_pdf, sig_format, pades_level_resp, has_visible, false))
}

// ──────────────────────────────────────────────────────────────
// Tag mode signing — uses pdf_signing library's internal pipeline
// ──────────────────────────────────────────────────────────────

/// Execute server-side signing using tag mode.
///
/// Delegates to `PDFSigningDocument::sign_document_no_placeholder` from the
/// `pdf_signing` library, which locates the text tag in the PDF content stream
/// and places the visible signature relative to it.
///
/// The library handles the entire pipeline:
/// - Tag resolution → rect computation
/// - Signature field + widget creation
/// - Image embedding
/// - Cryptographic CMS signing
///
/// After the library signing, we apply post-signing DSS/timestamp as usual.
async fn execute_sign_pdf_tag_mode(
    params: &SignPdfParams,
    pki: &crate::server::pki::PkiState,
    username: &str,
    _state: &web::Data<AppState>,
) -> Result<(Vec<u8>, String, Option<String>, bool, bool), HttpResponse> {
    use pdf_signing::signature_options::{
        PadesLevel, SignatureAnchorMode, SignatureFormat,
    };
    use pdf_signing::{PDFSigningDocument, SignatureOptions, UserSignatureInfo};
    use cryptographic_message_syntax::SignerBuilder;
    use x509_certificate::{CapturedX509Certificate, InMemorySigningKeyPair};

    let tag = params.sig_tag.as_deref().unwrap_or("#SIGN_HERE");
    let tag_width = params.sig_tag_width.unwrap_or(200.0);
    let tag_height = params.sig_tag_height.unwrap_or(70.0);
    let anchor_mode = match params.sig_tag_mode.as_deref() {
        Some("overlay") => SignatureAnchorMode::Overlay,
        _ => SignatureAnchorMode::InFront,
    };

    let sig_format = params.signature_format.to_lowercase();
    let pades_level_str = params.pades_level.to_uppercase()
        .replace("BB", "B-B").replace("BT", "B-T")
        .replace("BLT", "B-LT").replace("BLTA", "B-LTA");

    let format = if sig_format == "pkcs7" {
        SignatureFormat::PKCS7
    } else {
        SignatureFormat::PADES
    };

    let pades_level = match pades_level_str.as_str() {
        "B-T" => PadesLevel::B_T,
        "B-LT" => PadesLevel::B_LT,
        "B-LTA" => PadesLevel::B_LTA,
        _ => PadesLevel::B_B,
    };

    let has_visible = params.image_bytes.is_some();

    log::info!(
        "Server-side signPdf (TAG MODE): {} bytes, tag='{}', width={}, height={}, mode={:?}, visible={}, format={}, level={}",
        params.pdf_bytes.len(), tag, tag_width, tag_height, anchor_mode,
        has_visible, sig_format, pades_level_str,
    );

    // Build UserSignatureInfo from PKI state
    let pki_clone = pki.clone();
    let pdf_bytes = params.pdf_bytes.clone();
    let image_bytes = params.image_bytes.clone().unwrap_or_else(|| {
        // Use a 1x1 transparent PNG as placeholder if no image provided
        // but tag mode still needs a visible signature
        include_bytes!("../../test-files/signature-image.png").to_vec()
    });
    let tag_owned = tag.to_string();
    let timestamp_url = params.timestamp_url.clone();
    let sig_page = params.sig_page;
    let include_crl = params.include_crl;
    let include_ocsp = params.include_ocsp;

    // Use blocking thread for the library signing
    let sign_result = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, String> {
        // Parse certificates
        let user_cert = CapturedX509Certificate::from_der(pki_clone.user_cert_der.clone())
            .map_err(|e| format!("Failed to parse user cert: {}", e))?;
        let mut cert_chain = vec![user_cert.clone()];
        for ca_der in &pki_clone.ca_chain_der {
            let ca = CapturedX509Certificate::from_der(ca_der.clone())
                .map_err(|e| format!("Failed to parse CA cert: {}", e))?;
            cert_chain.push(ca);
        }

        // Parse private key
        let key = InMemorySigningKeyPair::from_pkcs8_der(&pki_clone.user_key_der)
            .map_err(|e| format!("Failed to parse private key: {}", e))?;

        // Build signer
        let signer = SignerBuilder::new(&key, user_cert);

        let user_info = UserSignatureInfo {
            user_id: "server-tag".to_string(),
            user_name: "Server Tag Signer".to_string(),
            user_email: "server@tag.sign".to_string(),
            user_signature: image_bytes,
            user_signing_keys: signer,
            user_certificate_chain: cert_chain,
        };

        let opts = SignatureOptions {
            format,
            timestamp_url,
            signature_size: 50_000,
            include_dss: false, // We'll handle DSS post-signing
            signed_attribute_include_crl: include_crl,
            signed_attribute_include_ocsp: include_ocsp,
            signature_page: Some(sig_page),
            signature_rect: None,
            visible_signature: has_visible,
            signature_anchor_tag: Some(tag_owned),
            signature_anchor_width: Some(tag_width),
            signature_anchor_height: Some(tag_height),
            signature_anchor_mode: anchor_mode,
            pades_level,
        };

        let mut pdf_doc = PDFSigningDocument::read_from(&*pdf_bytes, "upload.pdf".to_owned())
            .map_err(|e| format!("Failed to load PDF: {}", e))?;

        pdf_doc.sign_document_no_placeholder(&user_info, &opts)
            .map_err(|e| format!("Tag mode signing failed: {}", e))
    })
    .await;

    let mut signed_pdf = match sign_result {
        Ok(Ok(pdf)) => pdf,
        Ok(Err(e)) => {
            log::error!("Tag mode signing failed: {}", e);
            return Err(HttpResponse::BadRequest().json(CscErrorResponse {
                error: "signing_error".into(),
                error_description: e,
            }));
        }
        Err(e) => {
            log::error!("Tag mode signing task panicked: {}", e);
            return Err(HttpResponse::InternalServerError().json(CscErrorResponse {
                error: "server_error".into(),
                error_description: "Internal signing error".into(),
            }));
        }
    };

    log::info!("Tag mode signing complete: {} bytes", signed_pdf.len());

    // Post-signing: DSS dictionary for B-LT and B-LTA
    let is_pades = sig_format == "pades";
    let include_dss = is_pades && matches!(pades_level_str.as_str(), "B-LT" | "B-LTA");

    if include_dss {
        log::info!("Appending DSS dictionary for PAdES {} (tag mode)", pades_level_str);

        let pki_clone = pki.clone();
        let pdf_for_dss = signed_pdf.clone();
        let dss_result = tokio::task::spawn_blocking(move || {
            let user_cert = CapturedX509Certificate::from_der(pki_clone.user_cert_der.clone())
                .map_err(|e| format!("{}", e))?;
            let mut chain = vec![user_cert];
            for ca_der in &pki_clone.ca_chain_der {
                let ca = CapturedX509Certificate::from_der(ca_der.clone())
                    .map_err(|e| format!("{}", e))?;
                chain.push(ca);
            }
            crate::server::ltv::append_dss_dictionary(pdf_for_dss, chain)
        })
        .await;

        match dss_result {
            Ok(Ok(pdf_with_dss)) => {
                log::info!("DSS appended (tag mode): {} → {} bytes", signed_pdf.len(), pdf_with_dss.len());
                signed_pdf = pdf_with_dss;
            }
            Ok(Err(e)) => {
                log::error!("DSS append failed (tag mode): {}", e);
                return Err(HttpResponse::InternalServerError().json(CscErrorResponse {
                    error: "server_error".into(),
                    error_description: format!("Failed to append DSS: {}", e),
                }));
            }
            Err(e) => {
                log::error!("DSS task panicked (tag mode): {}", e);
                return Err(HttpResponse::InternalServerError().json(CscErrorResponse {
                    error: "server_error".into(),
                    error_description: "Internal error appending DSS".into(),
                }));
            }
        }
    }

    // Post-signing: document timestamp for B-LTA
    if is_pades && pades_level_str == "B-LTA" {
        if let Some(ref tsa_url) = params.timestamp_url {
            log::info!("Appending document timestamp for PAdES B-LTA (tag mode)");

            let pdf_for_ts = signed_pdf.clone();
            let tsa = tsa_url.clone();
            let ts_result = tokio::task::spawn_blocking(move || {
                crate::server::ltv::append_document_timestamp(pdf_for_ts, &tsa, 30_000)
            })
            .await;

            match ts_result {
                Ok(Ok(pdf_with_ts)) => {
                    log::info!("Document timestamp appended (tag mode): {} → {} bytes", signed_pdf.len(), pdf_with_ts.len());
                    signed_pdf = pdf_with_ts;
                }
                Ok(Err(e)) => {
                    log::error!("Document timestamp failed (tag mode): {}", e);
                    return Err(HttpResponse::InternalServerError().json(CscErrorResponse {
                        error: "server_error".into(),
                        error_description: format!("Failed to add document timestamp: {}", e),
                    }));
                }
                Err(e) => {
                    log::error!("Document timestamp task panicked (tag mode): {}", e);
                    return Err(HttpResponse::InternalServerError().json(CscErrorResponse {
                        error: "server_error".into(),
                        error_description: "Internal error adding document timestamp".into(),
                    }));
                }
            }
        } else {
            log::warn!("B-LTA requested but no TSA URL provided for document timestamp (tag mode)");
        }
    }

    log::info!(
        "User '{}' signed PDF (tag mode): {} → {} bytes, format={}, level={}, visible={}, tag='{}'",
        username, params.pdf_bytes.len(), signed_pdf.len(), sig_format, pades_level_str, has_visible,
        params.sig_tag.as_deref().unwrap_or(""),
    );

    let pades_level_resp = if sig_format == "pades" { Some(pades_level_str) } else { None };
    Ok((signed_pdf, sig_format, pades_level_resp, has_visible, true))
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
/// **Tag mode fields** (anchor-based signature placement):
/// - `sigTag`: Text marker to locate in the PDF (e.g., "#SIGN_HERE")
/// - `sigTagWidth`: Width of signature box in points [default: 200]
/// - `sigTagHeight`: Height of signature box in points [default: 70]
/// - `sigTagMode`: "in_front" (default) or "overlay"
///
/// When `sigTag` is set, the server uses tag-based anchor positioning:
/// it scans the PDF content stream for the tag text and places the visible
/// signature at that location. `sigRect` is then optional.
///
/// Returns:
/// - If `responseFormat=binary` (default): raw signed PDF bytes with
///   `Content-Type: application/pdf` and `Content-Disposition: attachment`
/// - If `responseFormat=json`: same JSON as the JSON endpoint
///
/// Example with curl (tag mode):
/// ```sh
/// curl -X POST http://localhost:8080/api/v1/signPdf/form \
///   -H "Authorization: Bearer <token>" \
///   -F "file=@document.pdf" \
///   -F "image=@signature.png" \
///   -F "sigTag=#SIGN_HERE" \
///   -F "sigTagWidth=200" \
///   -F "sigTagHeight=70" \
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

    // Parse sigRect: "x1,y1,x2,y2" (only required when image is provided and sigTag is not set)
    let sig_tag = fields
        .get("sigTag")
        .and_then(|f| f.as_text())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let sig_tag_width = fields
        .get("sigTagWidth")
        .and_then(|f| f.as_text())
        .and_then(|s| s.parse::<f64>().ok());

    let sig_tag_height = fields
        .get("sigTagHeight")
        .and_then(|f| f.as_text())
        .and_then(|s| s.parse::<f64>().ok());

    let sig_tag_mode = fields
        .get("sigTagMode")
        .and_then(|f| f.as_text())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let sig_rect = if sig_tag.is_none() && image_bytes.is_some() {
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
        // In tag mode, sigRect is optional (tag determines position)
        fields
            .get("sigRect")
            .and_then(|f| f.as_text())
            .and_then(|s| parse_rect_str(s).ok())
    };

    // Check credential access
    if !has_credential_access(&claims.sub, &credential_id) {
        return forbidden_response(&credential_id);
    }

    log::info!(
        "Form-data signPdf: {} bytes, image={}, format={}, level={}, response={}, tag={:?}",
        pdf_bytes.len(),
        image_bytes.as_ref().map(|b| b.len()).unwrap_or(0),
        signature_format,
        pades_level,
        response_format,
        sig_tag,
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
        sig_tag,
        sig_tag_width,
        sig_tag_height,
        sig_tag_mode,
    };

    let (signed_pdf, sig_format, pades_level_resp, has_visible, is_tag_mode) =
        match execute_sign_pdf(&params, &state.pki, &claims.sub, &state).await {
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
            tag_mode: if is_tag_mode { Some(true) } else { None },
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
            .insert_header((
                "X-Tag-Mode",
                if is_tag_mode { "true" } else { "false" },
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

