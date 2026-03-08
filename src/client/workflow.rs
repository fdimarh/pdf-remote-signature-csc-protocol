//! End-to-end client signing workflow.
//!
//! Orchestrates the full CSC remote signing flow:
//! 1. Login to CSC server
//! 2. List credentials
//! 3. Get credential info (certificate chain)
//! 4. Prepare PDF (insert placeholder, compute hash)
//! 5. Call server to sign the hash
//! 6. Embed signature into PDF
//! 7. Save signed PDF

use anyhow::{Context, Result};
use std::path::Path;

use crate::client::csc_client::CscClient;
use crate::client::pdf_finalizer;
use crate::client::pdf_preparer;
use crate::client::pdf_preparer::VisibleSignatureConfig;

/// Signing options passed from CLI
pub struct SignOptions {
    pub signature_format: String,
    pub pades_level: String,
    pub timestamp_url: Option<String>,
    /// Optional visible signature configuration
    pub visible_signature: Option<VisibleSignatureConfig>,
    /// Include CRL revocation data in CMS signed attributes
    pub include_crl: bool,
    /// Include OCSP revocation data in CMS signed attributes
    pub include_ocsp: bool,
    /// Use CSC signHash instead of signDoc (bandwidth-efficient, simplified CMS)
    pub use_sign_hash: bool,
}

impl Default for SignOptions {
    fn default() -> Self {
        SignOptions {
            signature_format: "pades".to_string(),
            pades_level: "B-B".to_string(),
            timestamp_url: None,
            visible_signature: None,
            include_crl: false,
            include_ocsp: false,
            use_sign_hash: false,
        }
    }
}

/// Execute the full remote signing workflow.
pub async fn sign_pdf(
    server_url: &str,
    username: &str,
    password: &str,
    input_path: &Path,
    output_path: &Path,
    sign_options: &SignOptions,
) -> Result<()> {
    use base64::Engine;
    let b64_engine = base64::engine::general_purpose::STANDARD;

    // ── Step 1: Create client and get server info ──
    let mut client = CscClient::new(server_url);

    log::info!("Connecting to CSC server at {}", server_url);
    let info = client.info().await?;
    log::info!("Server: {} (specs {})", info.name, info.specs);
    log::info!(
        "  Formats: {:?}, Levels: {:?}",
        info.signature_formats,
        info.pades_levels
    );

    // ── Step 2: Authenticate ──
    log::info!("Authenticating as '{}'...", username);
    client.login(username, password).await?;

    // ── Step 3: List credentials ──
    let creds = client.list_credentials().await?;
    if creds.credential_ids.is_empty() {
        anyhow::bail!("No signing credentials available for user '{}'", username);
    }
    let credential_id = &creds.credential_ids[0];
    log::info!("Using credential: {}", credential_id);

    // ── Step 4: Get credential info (cert chain) ──
    let cred_info = client.get_credential_info(credential_id).await?;
    log::info!(
        "Certificate subject: {}, issuer: {}",
        cred_info.cert.subject_dn,
        cred_info.cert.issuer_dn
    );
    log::info!(
        "Certificate chain: {} certificate(s)",
        cred_info.cert.certificates.len()
    );

    // ── Step 5: Prepare the PDF ──
    log::info!("Preparing PDF for signing...");
    if sign_options.visible_signature.is_some() {
        log::info!("  Visible signature: enabled (with image)");
    }
    let signer_name = &cred_info.cert.subject_dn;
    let prepared = pdf_preparer::prepare_pdf_for_signing(
        input_path,
        signer_name,
        sign_options.visible_signature.as_ref(),
    )?;
    log::info!(
        "PDF prepared: {} bytes, hash={}",
        prepared.pdf_bytes.len(),
        prepared
            .hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );

    // ── Step 6: Sign via CSC server (signDoc or signHash) ──
    let cms_der = if sign_options.use_sign_hash {
        // signHash: only send the 32-byte hash — bandwidth-efficient
        log::info!(
            "Requesting remote signature via signHash (hash-only, {} bytes over wire, format={}, level={}, tsa={:?})",
            prepared.hash.len(),
            sign_options.signature_format,
            sign_options.pades_level,
            sign_options.timestamp_url,
        );
        let sign_response = client
            .sign_hash(
                credential_id,
                &prepared.hash,
                &sign_options.signature_format,
                &sign_options.pades_level,
                sign_options.timestamp_url.as_deref(),
                sign_options.include_crl,
                sign_options.include_ocsp,
            )
            .await?;

        if sign_response.signatures.is_empty() {
            anyhow::bail!("signHash returned empty signatures array");
        }
        let cms_b64 = &sign_response.signatures[0];
        let der = b64_engine
            .decode(cms_b64)
            .context("Failed to decode CMS signature from Base64")?;
        log::info!(
            "Received CMS signature via signHash: {} bytes (simplified CMS)",
            der.len(),
        );
        der
    } else {
        // signDoc: send full byte range content — produces proper CMS
        log::info!(
            "Requesting remote signature via signDoc — format={}, level={}, tsa={:?} ({} bytes over wire)",
            sign_options.signature_format,
            sign_options.pades_level,
            sign_options.timestamp_url,
            prepared.content_to_sign.len(),
        );
        let sign_response = client
            .sign_doc(
                credential_id,
                &prepared.content_to_sign,
                &sign_options.signature_format,
                &sign_options.pades_level,
                sign_options.timestamp_url.as_deref(),
                sign_options.include_crl,
                sign_options.include_ocsp,
            )
            .await?;

        let cms_b64 = &sign_response.signature;
        let der = b64_engine
            .decode(cms_b64)
            .context("Failed to decode CMS signature from Base64")?;
        log::info!(
            "Received CMS signature via signDoc: {} bytes (format={}, level={:?})",
            der.len(),
            sign_response.signature_format,
            sign_response.pades_level,
        );
        der
    };

    // ── Step 7: Embed signature into PDF ──
    log::info!("Embedding signature into PDF...");
    let mut signed_pdf = pdf_finalizer::embed_signature(
        &prepared.pdf_bytes,
        &cms_der,
        prepared.signature_size,
    )?;

    // ── Step 8: Post-signing DSS + Document Timestamp (PAdES B-LT / B-LTA) ──
    let is_pades = sign_options.signature_format == "pades";
    let pades_upper = sign_options.pades_level.to_uppercase();
    let needs_dss = is_pades && matches!(pades_upper.as_str(), "B-LT" | "B-LTA");
    let needs_doc_ts = is_pades && pades_upper == "B-LTA";

    if needs_dss {
        log::info!("Appending DSS dictionary for PAdES {} ...", pades_upper);

        // Build certificate chain from the credential info
        let cert_chain = build_cert_chain_from_b64(&cred_info.cert.certificates)?;

        let pdf_for_dss = signed_pdf.clone();
        signed_pdf = tokio::task::spawn_blocking(move || {
            crate::server::ltv::append_dss_dictionary(pdf_for_dss, cert_chain)
        })
        .await
        .context("DSS task panicked")?
        .map_err(|e| anyhow::anyhow!("Failed to append DSS dictionary: {}", e))?;

        log::info!("DSS dictionary appended: {} bytes", signed_pdf.len());
    }

    if needs_doc_ts {
        if let Some(ref tsa_url) = sign_options.timestamp_url {
            log::info!("Appending document-level timestamp for PAdES B-LTA ...");

            let pdf_for_ts = signed_pdf.clone();
            let tsa = tsa_url.clone();
            signed_pdf = tokio::task::spawn_blocking(move || {
                crate::server::ltv::append_document_timestamp(pdf_for_ts, &tsa, 30_000)
            })
            .await
            .context("Document timestamp task panicked")?
            .map_err(|e| anyhow::anyhow!("Failed to append document timestamp: {}", e))?;

            log::info!("Document timestamp appended: {} bytes", signed_pdf.len());
        } else {
            log::warn!("B-LTA requested but no TSA URL provided — skipping document timestamp");
        }
    }

    // ── Step 9: Save ──
    pdf_finalizer::save_signed_pdf(&signed_pdf, output_path)?;

    log::info!("✅ PDF signed successfully!");
    log::info!("   Input:  {:?}", input_path);
    log::info!("   Output: {:?}", output_path);
    log::info!(
        "   Method: {} | Format: {} / {}",
        if sign_options.use_sign_hash { "signHash" } else { "signDoc" },
        sign_options.signature_format,
        sign_options.pades_level,
    );

    Ok(())
}

/// Parse Base64 DER certificates from the CSC credential info into
/// `CapturedX509Certificate` objects suitable for DSS / LTV operations.
fn build_cert_chain_from_b64(
    certs_b64: &[String],
) -> anyhow::Result<Vec<x509_certificate::CapturedX509Certificate>> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut chain = Vec::with_capacity(certs_b64.len());
    for (i, cert_b64) in certs_b64.iter().enumerate() {
        let der = b64
            .decode(cert_b64)
            .with_context(|| format!("Invalid Base64 in certificate #{}", i))?;
        let cert = x509_certificate::CapturedX509Certificate::from_der(der)
            .map_err(|e| anyhow::anyhow!("Failed to parse certificate #{}: {}", i, e))?;
        chain.push(cert);
    }
    Ok(chain)
}

