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
}

impl Default for SignOptions {
    fn default() -> Self {
        SignOptions {
            signature_format: "pades".to_string(),
            pades_level: "B-B".to_string(),
            timestamp_url: None,
            visible_signature: None,
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

    // ── Step 6: Sign the document content via CSC server ──
    log::info!(
        "Requesting remote signature — format={}, level={}, tsa={:?}",
        sign_options.signature_format,
        sign_options.pades_level,
        sign_options.timestamp_url,
    );
    let sign_response = client
        .sign_doc(
            credential_id,
            &prepared.content_to_sign,
            &sign_options.signature_format,
            &sign_options.pades_level,
            sign_options.timestamp_url.as_deref(),
        )
        .await?;

    let cms_b64 = &sign_response.signature;
    let cms_der = b64_engine
        .decode(cms_b64)
        .context("Failed to decode CMS signature from Base64")?;
    log::info!(
        "Received CMS signature: {} bytes (format={}, level={:?})",
        cms_der.len(),
        sign_response.signature_format,
        sign_response.pades_level,
    );

    // ── Step 7: Embed signature into PDF ──
    log::info!("Embedding signature into PDF...");
    let signed_pdf = pdf_finalizer::embed_signature(
        &prepared.pdf_bytes,
        &cms_der,
        prepared.signature_size,
    )?;

    // ── Step 8: Save ──
    pdf_finalizer::save_signed_pdf(&signed_pdf, output_path)?;

    log::info!("✅ PDF signed successfully!");
    log::info!("   Input:  {:?}", input_path);
    log::info!("   Output: {:?}", output_path);
    log::info!(
        "   Format: {} / {:?}",
        sign_response.signature_format,
        sign_response.pades_level.as_deref().unwrap_or("n/a")
    );

    Ok(())
}
