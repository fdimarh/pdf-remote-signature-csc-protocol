//! Remote Signature PDF — CSC Protocol Prototype
//!
//! A client-server application for remotely signing PDFs using the
//! Cloud Signature Consortium (CSC) API v2 protocol.
//!
//! Usage:
//!   # Start the signing server
//!   remote-signature-pdf server --cert-dir ./certs --port 8080
//!
//!   # Sign a PDF document (PAdES B-B, default)
//!   remote-signature-pdf sign --input document.pdf --output signed.pdf
//!
//!   # Sign with specific format and level
//!   remote-signature-pdf sign --input doc.pdf --output signed.pdf \
//!     --format pades --level b-t --tsa-url http://timestamp.digicert.com
//!
//!   # Verify a signed PDF (local)
//!   remote-signature-pdf verify --input signed.pdf
//!
//!   # Validate via server API
//!   remote-signature-pdf validate --server-url http://localhost:8080 \
//!     --input signed.pdf

mod common;
mod server;
mod client;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "remote-signature-pdf",
    about = "Remote PDF signing using CSC v2 protocol — supports PKCS7, PAdES B-B/B-T/B-LT/B-LTA",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the CSC signing server (PKI/TSP)
    Server {
        /// Directory containing certificate PEM files.
        /// Use ./certs/nowina for Nowina DSS test certs (3-level chain),
        /// or ./certs for the legacy self-signed certs.
        #[arg(long, default_value = "./certs/nowina")]
        cert_dir: PathBuf,

        /// Host to bind to
        #[arg(long, default_value = "127.0.0.1")]
        host: String,

        /// Port to listen on
        #[arg(long, default_value_t = 8080)]
        port: u16,

        /// PKI backend: "pem" (default) or "hsm" (PKCS#11)
        #[arg(long, default_value = "pem")]
        pki_backend: String,

        /// Path to PKCS#11 shared library (for HSM backend)
        /// e.g., /usr/lib/softhsm/libsofthsm2.so
        #[arg(long)]
        pkcs11_lib: Option<String>,

        /// PKCS#11 token slot index (for HSM backend)
        #[arg(long, default_value_t = 0)]
        hsm_slot: usize,

        /// PKCS#11 user PIN (for HSM backend)
        #[arg(long)]
        hsm_pin: Option<String>,

        /// Label of the private key in the HSM token
        #[arg(long, default_value = "user-key")]
        hsm_key_label: String,
    },

    /// Sign a PDF document using the remote CSC server
    Sign {
        /// URL of the CSC signing server
        #[arg(long, default_value = "http://localhost:8080")]
        server_url: String,

        /// Input PDF file path
        #[arg(long, short)]
        input: PathBuf,

        /// Output signed PDF file path
        #[arg(long, short)]
        output: PathBuf,

        /// Username for CSC authentication
        #[arg(long, short, default_value = "testuser")]
        username: String,

        /// Password for CSC authentication
        #[arg(long, short, default_value = "testpass")]
        password: String,

        /// Signature format: "pkcs7" or "pades"
        #[arg(long, short, default_value = "pades")]
        format: String,

        /// PAdES conformance level: "B-B", "B-T", "B-LT", "B-LTA"
        #[arg(long, short, default_value = "B-B")]
        level: String,

        /// TSA URL for timestamp (required for B-T, B-LT, B-LTA)
        #[arg(long)]
        tsa_url: Option<String>,

        /// Path to a signature image (PNG or JPEG) for a visible signature.
        /// When provided, the signature becomes visible on the PDF page.
        #[arg(long)]
        image: Option<PathBuf>,

        /// Page number for the visible signature (1-based, default: 1)
        #[arg(long, default_value_t = 1)]
        sig_page: u32,

        /// Rectangle for the visible signature in PDF points: "x1,y1,x2,y2"
        /// (0,0) = bottom-left. Example: "50,50,250,150" places a 200x100pt
        /// signature box near the bottom-left of the page.
        #[arg(long, default_value = "50,50,250,150")]
        sig_rect: String,

        /// Include CRL revocation data in CMS signed attributes (PKCS7 LTV)
        #[arg(long, default_value_t = false)]
        include_crl: bool,

        /// Include OCSP revocation data in CMS signed attributes (PKCS7 LTV)
        #[arg(long, default_value_t = false)]
        include_ocsp: bool,

        /// Use CSC signHash instead of signDoc for bandwidth efficiency.
        /// Only the 32-byte SHA-256 hash is sent over the wire (vs full byte ranges).
        /// Trade-off: Produces a simplified CMS signature (PAdES B-B equivalent).
        #[arg(long, default_value_t = false)]
        use_sign_hash: bool,

        /// Tag mode: text marker to locate in the PDF content stream (e.g., "#SIGN_HERE").
        /// When set, the visible signature is positioned relative to this tag.
        /// Requires --image to be set for a visible signature.
        #[arg(long)]
        sig_tag: Option<String>,

        /// Tag mode: width of the signature box in PDF points (default: 200)
        #[arg(long)]
        sig_tag_width: Option<f64>,

        /// Tag mode: height of the signature box in PDF points (default: 70)
        #[arg(long)]
        sig_tag_height: Option<f64>,

        /// Tag mode: placement relative to the tag text.
        /// "in_front" (default) = right of tag, "overlay" = on top of tag.
        #[arg(long)]
        sig_tag_mode: Option<String>,
    },

    /// Verify a signed PDF document (local validation using pdf_signing library)
    Verify {
        /// Input signed PDF file path
        #[arg(long, short)]
        input: PathBuf,

        /// Password for encrypted PDFs
        #[arg(long)]
        password: Option<String>,
    },

    /// Validate a signed PDF via the server's validation API
    Validate {
        /// URL of the CSC signing server
        #[arg(long, default_value = "http://localhost:8080")]
        server_url: String,

        /// Input signed PDF file path
        #[arg(long, short)]
        input: PathBuf,

        /// Password for encrypted PDFs
        #[arg(long)]
        password: Option<String>,
    },

    /// Sign a PDF entirely on the server (server-side rendering).
    /// The server handles PDF preparation, visible image embedding,
    /// CMS signing, and signature embedding in a single API call.
    #[command(name = "sign-remote")]
    SignRemote {
        /// URL of the CSC signing server
        #[arg(long, default_value = "http://localhost:8080")]
        server_url: String,

        /// Input PDF file path
        #[arg(long, short)]
        input: PathBuf,

        /// Output signed PDF file path
        #[arg(long, short)]
        output: PathBuf,

        /// Username for CSC authentication
        #[arg(long, short, default_value = "testuser")]
        username: String,

        /// Password for CSC authentication
        #[arg(long, short, default_value = "testpass")]
        password: String,

        /// Signature format: "pkcs7" or "pades"
        #[arg(long, short, default_value = "pades")]
        format: String,

        /// PAdES conformance level: "B-B", "B-T", "B-LT", "B-LTA"
        #[arg(long, short, default_value = "B-B")]
        level: String,

        /// TSA URL for timestamp
        #[arg(long)]
        tsa_url: Option<String>,

        /// Path to a signature image (PNG or JPEG) for a visible signature.
        /// The image is uploaded to the server which handles rendering.
        #[arg(long)]
        image: Option<PathBuf>,

        /// Page number for the visible signature (1-based, default: 1)
        #[arg(long, default_value_t = 1)]
        sig_page: u32,

        /// Rectangle for the visible signature: "x1,y1,x2,y2"
        #[arg(long, default_value = "50,50,250,150")]
        sig_rect: String,

        /// Display name for the signer
        #[arg(long, default_value = "Digital Signature")]
        signer_name: String,

        /// Tag mode: text marker to locate in the PDF (e.g., "#SIGN_HERE").
        #[arg(long)]
        sig_tag: Option<String>,

        /// Tag mode: width of the signature box in PDF points (default: 200)
        #[arg(long)]
        sig_tag_width: Option<f64>,

        /// Tag mode: height of the signature box in PDF points (default: 70)
        #[arg(long)]
        sig_tag_height: Option<f64>,

        /// Tag mode: placement mode ("in_front" or "overlay")
        #[arg(long)]
        sig_tag_mode: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Server {
            cert_dir,
            host,
            port,
            pki_backend,
            pkcs11_lib,
            hsm_slot,
            hsm_pin,
            hsm_key_label,
        } => {
            log::info!("Starting CSC signing server...");
            log::info!("  Certificate dir: {:?}", cert_dir);
            log::info!("  PKI backend:     {}", pki_backend);
            log::info!("  Listening on:    {}:{}", host, port);

            let backend: Option<std::sync::Arc<dyn server::pki_backend::PkiBackend>> =
                match pki_backend.as_str() {
                    "hsm" | "pkcs11" => {
                        #[cfg(feature = "hsm")]
                        {
                            let lib = pkcs11_lib.as_deref().unwrap_or(
                                "/usr/lib/softhsm/libsofthsm2.so",
                            );
                            let pin = hsm_pin.as_deref().unwrap_or("1234");
                            log::info!("  PKCS#11 lib:     {}", lib);
                            log::info!("  HSM slot:        {}", hsm_slot);
                            log::info!("  HSM key label:   {}", hsm_key_label);
                            let hsm_backend = server::pki_backend::HsmBackend::new(
                                lib,
                                hsm_slot,
                                pin,
                                &hsm_key_label,
                                &cert_dir,
                            )
                            .expect("Failed to initialize HSM backend");
                            Some(std::sync::Arc::new(hsm_backend))
                        }
                        #[cfg(not(feature = "hsm"))]
                        {
                            eprintln!("ERROR: HSM backend requires the 'hsm' feature.");
                            eprintln!("  Rebuild with: cargo build --features hsm");
                            std::process::exit(1);
                        }
                    }
                    "pem" | _ => None, // Will use PEM backend as default
                };

            server::app::run_server_with_backend(&cert_dir, &host, port, backend).await?;
        }

        Commands::Sign {
            server_url,
            input,
            output,
            username,
            password,
            format,
            level,
            tsa_url,
            image,
            sig_page,
            sig_rect,
            include_crl,
            include_ocsp,
            use_sign_hash,
            sig_tag,
            sig_tag_width,
            sig_tag_height,
            sig_tag_mode,
        } => {
            log::info!("Starting remote PDF signing...");
            log::info!("  Format: {}, Level: {}", format, level);
            if sig_tag.is_some() {
                log::info!("  Tag mode: {:?}", sig_tag);
            }

            // Parse visible signature config if --image is provided
            let visible_config = if let Some(image_path) = image {
                let rect = if sig_tag.is_none() {
                    parse_rect(&sig_rect)?
                } else {
                    // In tag mode, sig_rect is just a placeholder — tag resolution
                    // will override it with the actual position.
                    [0.0, 0.0, 0.0, 0.0]
                };
                log::info!(
                    "  Visible signature: image={:?}, page={}, rect={:?}",
                    image_path,
                    sig_page,
                    rect
                );
                Some(client::pdf_preparer::VisibleSignatureConfig {
                    image_path,
                    page: sig_page,
                    rect,
                })
            } else {
                None
            };

            let sign_options = client::workflow::SignOptions {
                signature_format: format.to_lowercase(),
                pades_level: level.to_uppercase(),
                timestamp_url: tsa_url,
                visible_signature: visible_config,
                include_crl,
                include_ocsp,
                use_sign_hash,
                sig_tag,
                sig_tag_width,
                sig_tag_height,
                sig_tag_mode,
            };

            client::workflow::sign_pdf(
                &server_url,
                &username,
                &password,
                &input,
                &output,
                &sign_options,
            )
            .await?;
        }

        Commands::Verify { input, password } => {
            log::info!("Verifying signed PDF: {:?}", input);
            let pdf_bytes = std::fs::read(&input)?;
            let pw = password.as_ref().map(|p| p.as_bytes());
            let result = pdf_signing::signature_validator::SignatureValidator::validate_with_password(&pdf_bytes, pw);
            match result {
                Ok(results) => {
                    println!("Found {} signature(s)", results.len());
                    println!();
                    for (i, r) in results.iter().enumerate() {
                        println!("═══ Signature #{} ═══", i + 1);
                        println!(
                            "  Field:             {}",
                            r.field_info.field_name.as_deref().unwrap_or("(unnamed)")
                        );
                        println!(
                            "  Signer:            {}",
                            r.signer_name.as_deref().unwrap_or("(unknown)")
                        );
                        println!(
                            "  Filter:            {}",
                            r.filter.as_deref().unwrap_or("(unknown)")
                        );
                        println!(
                            "  SubFilter:         {}",
                            r.sub_filter.as_deref().unwrap_or("(unknown)")
                        );
                        println!(
                            "  Signing time:      {}",
                            r.signing_time.as_deref().unwrap_or("(unknown)")
                        );
                        println!(
                            "  Doc timestamp:     {}",
                            r.field_info.is_document_timestamp
                        );
                        println!();
                        println!("  ── Validity ──");
                        println!("  Valid:             {}", r.is_valid());
                        println!("  Digest match:      {}", r.digest_match);
                        println!("  CMS valid:         {}", r.cms_signature_valid);
                        println!("  Chain valid:       {}", r.certificate_chain_valid);
                        println!("  Chain trusted:     {}", r.certificate_chain_trusted);
                        println!("  ByteRange valid:   {}", r.byte_range_valid);
                        println!("  Not wrapped:       {}", r.signature_not_wrapped);
                        println!("  Covers whole file: {}", r.byte_range_covers_whole_file);
                        println!(
                            "  No unauthorized:   {}",
                            r.no_unauthorized_modifications
                        );
                        if let Some(level) = r.certification_level {
                            println!("  MDP level:         {}", level);
                        }
                        println!(
                            "  MDP permission ok: {}",
                            r.certification_permission_ok
                        );
                        println!();
                        println!("  ── LTV / Long-Term ──");
                        println!("  Has timestamp:     {}", r.has_timestamp);
                        println!("  Has DSS:           {}", r.has_dss);
                        if r.has_dss {
                            println!(
                                "    DSS CRLs:        {}",
                                r.dss_crl_count
                            );
                            println!(
                                "    DSS OCSPs:       {}",
                                r.dss_ocsp_count
                            );
                            println!(
                                "    DSS Certs:       {}",
                                r.dss_cert_count
                            );
                        }
                        println!("  Has VRI:           {}", r.has_vri);
                        println!("  CMS revocation:    {}", r.has_cms_revocation_data);
                        println!("  LTV enabled:       {}", r.is_ltv_enabled);
                        if !r.errors.is_empty() {
                            println!();
                            println!("  ── Errors ──");
                            for err in &r.errors {
                                println!("    ✗ {}", err);
                            }
                        }
                        if !r.security_warnings.is_empty() {
                            println!();
                            println!("  ── Security warnings ──");
                            for warn in &r.security_warnings {
                                println!("    ⚠ {}", warn);
                            }
                        }
                        if !r.chain_warnings.is_empty() {
                            println!();
                            println!("  ── Chain warnings ──");
                            for warn in &r.chain_warnings {
                                println!("    ⚠ {}", warn);
                            }
                        }
                        if !r.modification_notes.is_empty() {
                            println!();
                            println!("  ── Modifications ──");
                            for note in &r.modification_notes {
                                println!("    • {}", note);
                            }
                        }
                        println!();
                        println!("  ── Certificates ({}) ──", r.certificates.len());
                        for cert in &r.certificates {
                            println!(
                                "    {} → issued by: {}{}{}",
                                cert.subject,
                                cert.issuer,
                                if cert.is_expired { " [EXPIRED]" } else { "" },
                                if cert.is_self_signed { " [SELF-SIGNED]" } else { "" }
                            );
                        }
                        println!();
                    }
                    // Summary
                    let all_valid = results.iter().all(|r| r.is_valid());
                    if all_valid {
                        println!("✅ All {} signature(s) are VALID", results.len());
                    } else {
                        println!("❌ Some signatures are INVALID");
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    log::error!("Verification failed: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Validate {
            server_url,
            input,
            password,
        } => {
            log::info!("Validating PDF via server API: {:?}", input);
            let pdf_bytes = std::fs::read(&input)?;
            let client = client::csc_client::CscClient::new(&server_url);
            let result = client
                .validate_pdf(&pdf_bytes, password.as_deref())
                .await?;

            println!("Found {} signature(s)", result.signature_count);
            println!("All valid: {}", result.all_valid);
            println!();

            for (i, sig) in result.signatures.iter().enumerate() {
                println!("═══ Signature #{} ═══", i + 1);
                if let Some(name) = &sig.signer_name {
                    println!("  Signer: {}", name);
                }
                if let Some(sf) = &sig.sub_filter {
                    println!("  SubFilter: {}", sf);
                }
                println!("  Valid: {}", sig.is_valid);
                println!("  Digest match: {}", sig.digest_match);
                println!("  CMS valid: {}", sig.cms_signature_valid);
                println!("  Chain valid: {}", sig.certificate_chain_valid);
                println!("  ByteRange valid: {}", sig.byte_range_valid);
                println!("  Has timestamp: {}", sig.has_timestamp);
                println!("  Has DSS: {}", sig.has_dss);
                println!("  LTV enabled: {}", sig.is_ltv_enabled);
                println!("  Doc timestamp: {}", sig.is_document_timestamp);
                if !sig.errors.is_empty() {
                    println!("  Errors:");
                    for e in &sig.errors {
                        println!("    ✗ {}", e);
                    }
                }
                println!();
            }

            if result.all_valid {
                println!("✅ All signature(s) VALID");
            } else {
                println!("❌ Some signatures INVALID");
                std::process::exit(1);
            }
        }

        Commands::SignRemote {
            server_url,
            input,
            output,
            username,
            password,
            format,
            level,
            tsa_url,
            image,
            sig_page,
            sig_rect,
            signer_name,
            sig_tag,
            sig_tag_width,
            sig_tag_height,
            sig_tag_mode,
        } => {
            log::info!("Starting server-side PDF signing...");
            log::info!("  Format: {}, Level: {}", format, level);
            if sig_tag.is_some() {
                log::info!("  Tag mode: {:?}", sig_tag);
            }

            // Read PDF file
            let pdf_bytes = std::fs::read(&input)
                .map_err(|e| anyhow::anyhow!("Failed to read input PDF {:?}: {}", input, e))?;

            // Read optional image file
            let image_bytes = if let Some(ref img_path) = image {
                let bytes = std::fs::read(img_path)
                    .map_err(|e| anyhow::anyhow!("Failed to read image {:?}: {}", img_path, e))?;
                log::info!("  Visible signature: image={:?} ({} bytes)", img_path, bytes.len());
                Some(bytes)
            } else {
                None
            };

            let sig_rect_arr = if image.is_some() {
                Some(parse_rect(&sig_rect)?)
            } else {
                None
            };

            // Authenticate
            let mut csc_client = client::csc_client::CscClient::new(&server_url);
            log::info!("Authenticating as '{}'...", username);
            csc_client.login(&username, &password).await?;

            // List credentials
            let creds = csc_client.list_credentials().await?;
            if creds.credential_ids.is_empty() {
                anyhow::bail!("No signing credentials available");
            }
            let credential_id = &creds.credential_ids[0];
            log::info!("Using credential: {}", credential_id);

            // Call server-side signPdf
            log::info!("Uploading PDF for server-side signing...");
            let response = csc_client
                .sign_pdf_remote(
                    credential_id,
                    &pdf_bytes,
                    image_bytes.as_deref(),
                    sig_rect_arr,
                    sig_page,
                    &signer_name,
                    &format.to_lowercase(),
                    &level.to_uppercase(),
                    tsa_url.as_deref(),
                    sig_tag.as_deref(),
                    sig_tag_width,
                    sig_tag_height,
                    sig_tag_mode.as_deref(),
                )
                .await?;

            // Decode and save signed PDF
            use base64::Engine;
            let signed_pdf = base64::engine::general_purpose::STANDARD
                .decode(&response.signed_pdf)
                .map_err(|e| anyhow::anyhow!("Failed to decode signed PDF: {}", e))?;

            std::fs::write(&output, &signed_pdf)
                .map_err(|e| anyhow::anyhow!("Failed to write output {:?}: {}", output, e))?;

            log::info!("✅ PDF signed successfully (server-side)!");
            log::info!("   Input:  {:?}", input);
            log::info!("   Output: {:?} ({} bytes)", output, signed_pdf.len());
            log::info!(
                "   Format: {} / {}",
                response.signature_format,
                response.pades_level.as_deref().unwrap_or("n/a")
            );
            log::info!("   Visible: {}", response.has_visible_signature);
        }
    }

    Ok(())
}

/// Parse a rectangle string "x1,y1,x2,y2" into [f32; 4].
fn parse_rect(s: &str) -> anyhow::Result<[f32; 4]> {
    let parts: Vec<f32> = s
        .split(',')
        .map(|p| {
            p.trim()
                .parse::<f32>()
                .map_err(|e| anyhow::anyhow!("Invalid rect value '{}': {}", p.trim(), e))
        })
        .collect::<anyhow::Result<Vec<f32>>>()?;
    if parts.len() != 4 {
        anyhow::bail!(
            "Rectangle must have 4 values (x1,y1,x2,y2), got {}",
            parts.len()
        );
    }
    Ok([parts[0], parts[1], parts[2], parts[3]])
}

