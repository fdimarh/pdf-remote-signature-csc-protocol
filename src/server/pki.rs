//! PKI module — loads and manages certificates and private keys.
//!
//! Supports two directory layouts:
//!
//! **Legacy layout** (`load_from_dir`):
//!   - `user-cert.pem`, `user-key.pem`, `ca-cert.pem` (single CA)
//!
//! **Chain layout** (`load_from_chain_dir`):
//!   - `user-cert.pem`, `user-key.pem`, `ca-chain.pem` (multi-cert CA chain)
//!
//! The chain layout is used when `ca-chain.pem` exists in the directory.

use anyhow::{Context, Result};
use std::path::Path;
use std::sync::Arc;

/// Holds the loaded PKI material for the server.
#[derive(Clone)]
pub struct PkiState {
    /// User/signer certificate in DER format
    pub user_cert_der: Vec<u8>,
    /// Full CA certificate chain in DER format (intermediate → root order)
    pub ca_chain_der: Vec<Vec<u8>>,
    /// User private key in DER (PKCS#8) format
    pub user_key_der: Vec<u8>,
    /// Parsed user certificate for metadata extraction
    pub user_cert_parsed: Arc<x509_certificate::CapturedX509Certificate>,
    /// Parsed CA certificates (for metadata)
    pub ca_chain_parsed: Vec<Arc<x509_certificate::CapturedX509Certificate>>,
}

// Backward-compatible aliases
impl PkiState {
    /// First CA cert DER (for backward compatibility)
    pub fn ca_cert_der(&self) -> &[u8] {
        self.ca_chain_der.first().map(|v| v.as_slice()).unwrap_or(&[])
    }
}

impl PkiState {
    /// Load PKI material from a directory.
    ///
    /// Auto-detects the layout:
    /// - If `ca-chain.pem` exists → chain layout (multi-cert CA chain)
    /// - Otherwise → legacy layout (`ca-cert.pem` single CA)
    pub fn load_from_dir(cert_dir: &Path) -> Result<Self> {
        if cert_dir.join("ca-chain.pem").exists() {
            Self::load_chain_layout(cert_dir)
        } else {
            Self::load_legacy_layout(cert_dir)
        }
    }

    /// Load chain layout: `user-cert.pem`, `user-key.pem`, `ca-chain.pem`
    ///
    /// `ca-chain.pem` may contain multiple PEM certificates (intermediate + root).
    fn load_chain_layout(cert_dir: &Path) -> Result<Self> {
        let user_cert_pem = std::fs::read_to_string(cert_dir.join("user-cert.pem"))
            .context("Failed to read user-cert.pem")?;
        let ca_chain_pem = std::fs::read_to_string(cert_dir.join("ca-chain.pem"))
            .context("Failed to read ca-chain.pem")?;
        let user_key_pem = std::fs::read_to_string(cert_dir.join("user-key.pem"))
            .context("Failed to read user-key.pem")?;

        // Parse user cert
        let user_cert_der = pem_to_der(&user_cert_pem, "CERTIFICATE")
            .context("Failed to parse user certificate PEM")?;

        // Parse all CA certs from chain PEM
        let ca_chain_der = pem_to_der_multi(&ca_chain_pem, "CERTIFICATE")
            .context("Failed to parse CA chain PEM")?;

        if ca_chain_der.is_empty() {
            anyhow::bail!("ca-chain.pem contains no certificates");
        }

        // Parse key
        let user_key_der = pem_to_der_key(&user_key_pem)
            .context("Failed to parse user private key PEM")?;

        // Parse with x509-certificate for metadata
        let user_cert_parsed = x509_certificate::CapturedX509Certificate::from_der(user_cert_der.clone())
            .context("Failed to parse user certificate DER")?;

        let mut ca_chain_parsed = Vec::new();
        for (i, ca_der) in ca_chain_der.iter().enumerate() {
            let parsed = x509_certificate::CapturedX509Certificate::from_der(ca_der.clone())
                .context(format!("Failed to parse CA cert #{} DER", i))?;
            ca_chain_parsed.push(Arc::new(parsed));
        }

        log::info!(
            "Loaded PKI (chain): user_cert subject={:?}, chain={} CA cert(s)",
            user_cert_parsed
                .subject_name()
                .user_friendly_str()
                .unwrap_or_default(),
            ca_chain_parsed.len(),
        );
        for (i, ca) in ca_chain_parsed.iter().enumerate() {
            log::info!(
                "  CA[{}]: subject={:?}, issuer={:?}",
                i,
                ca.subject_name().user_friendly_str().unwrap_or_default(),
                ca.issuer_name().user_friendly_str().unwrap_or_default(),
            );
        }

        Ok(PkiState {
            user_cert_der,
            ca_chain_der,
            user_key_der,
            user_cert_parsed: Arc::new(user_cert_parsed),
            ca_chain_parsed,
        })
    }

    /// Load legacy layout: `user-cert.pem`, `user-key.pem`, `ca-cert.pem`
    ///
    /// Single CA certificate (2-level chain).
    fn load_legacy_layout(cert_dir: &Path) -> Result<Self> {
        let user_cert_pem = std::fs::read_to_string(cert_dir.join("user-cert.pem"))
            .context("Failed to read user-cert.pem")?;
        let ca_cert_pem = std::fs::read_to_string(cert_dir.join("ca-cert.pem"))
            .context("Failed to read ca-cert.pem")?;
        let user_key_pem = std::fs::read_to_string(cert_dir.join("user-key.pem"))
            .context("Failed to read user-key.pem")?;

        let user_cert_der = pem_to_der(&user_cert_pem, "CERTIFICATE")
            .context("Failed to parse user certificate PEM")?;
        let ca_cert_der = pem_to_der(&ca_cert_pem, "CERTIFICATE")
            .context("Failed to parse CA certificate PEM")?;
        let user_key_der = pem_to_der_key(&user_key_pem)
            .context("Failed to parse user private key PEM")?;

        let user_cert_parsed = x509_certificate::CapturedX509Certificate::from_der(user_cert_der.clone())
            .context("Failed to parse user certificate DER")?;
        let ca_cert_parsed = x509_certificate::CapturedX509Certificate::from_der(ca_cert_der.clone())
            .context("Failed to parse CA certificate DER")?;

        log::info!(
            "Loaded PKI (legacy): user_cert subject={:?}, ca_cert subject={:?}",
            user_cert_parsed
                .subject_name()
                .user_friendly_str()
                .unwrap_or_default(),
            ca_cert_parsed
                .subject_name()
                .user_friendly_str()
                .unwrap_or_default(),
        );

        Ok(PkiState {
            user_cert_der,
            ca_chain_der: vec![ca_cert_der],
            user_key_der,
            user_cert_parsed: Arc::new(user_cert_parsed),
            ca_chain_parsed: vec![Arc::new(ca_cert_parsed)],
        })
    }

    /// Get the full certificate chain as Base64-encoded DER strings.
    /// Returns [user_cert, ca_cert_1, ca_cert_2, ...] order.
    pub fn cert_chain_base64(&self) -> Vec<String> {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        let mut chain = vec![engine.encode(&self.user_cert_der)];
        for ca_der in &self.ca_chain_der {
            chain.push(engine.encode(ca_der));
        }
        chain
    }
}

/// Parse a PEM block with the given expected tag into DER bytes.
fn pem_to_der(pem_str: &str, expected_tag: &str) -> Result<Vec<u8>> {
    let parsed = pem::parse(pem_str).context("Invalid PEM format")?;
    if parsed.tag() != expected_tag {
        anyhow::bail!(
            "Expected PEM tag '{}', got '{}'",
            expected_tag,
            parsed.tag()
        );
    }
    Ok(parsed.into_contents())
}

/// Parse multiple PEM blocks from a single string (e.g., certificate chain).
fn pem_to_der_multi(pem_str: &str, expected_tag: &str) -> Result<Vec<Vec<u8>>> {
    let parsed_many = pem::parse_many(pem_str).context("Invalid PEM format")?;
    let mut results = Vec::new();
    for parsed in parsed_many {
        if parsed.tag() == expected_tag {
            results.push(parsed.into_contents());
        }
    }
    Ok(results)
}

/// Parse a private key PEM (either "PRIVATE KEY" PKCS#8 or "RSA PRIVATE KEY" PKCS#1)
fn pem_to_der_key(pem_str: &str) -> Result<Vec<u8>> {
    let parsed = pem::parse(pem_str).context("Invalid PEM format for private key")?;
    match parsed.tag() {
        "PRIVATE KEY" | "RSA PRIVATE KEY" => Ok(parsed.into_contents()),
        other => anyhow::bail!("Unexpected PEM tag for private key: '{}'", other),
    }
}
