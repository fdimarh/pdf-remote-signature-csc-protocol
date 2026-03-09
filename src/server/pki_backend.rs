//! PKI Backend trait — abstraction layer for swappable signing backends.
//!
//! Provides a uniform interface for:
//! - **PEM backend** — loads keys from PEM files (in-memory signing)
//! - **HSM backend** — signs via PKCS#11 (keys never leave the HSM)
//!
//! Both backends provide the same certificate data (DER certs, CA chain)
//! but differ in how RSA signing is performed.

use anyhow::Result;
use std::sync::Arc;

/// Trait for PKI signing backends.
///
/// The signing server uses this trait to abstract over different
/// key storage mechanisms. All handlers receive `&dyn PkiBackend`
/// and don't need to know whether keys are in memory or in an HSM.
pub trait PkiBackend: Send + Sync {
    /// Sign data using RSA-SHA256.
    ///
    /// For CMS construction: pass the DER-encoded signed attributes (SET).
    /// The backend handles hashing + RSA signature internally.
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>>;

    /// Sign a pre-computed SHA-256 hash using RSA PKCS#1 v1.5.
    ///
    /// Used by `build_cms_from_hash` where we already have the
    /// DER-encoded signed attributes and need to sign them.
    /// Default implementation just calls `sign_data`.
    fn sign_attrs(&self, signed_attrs_der: &[u8]) -> Result<Vec<u8>> {
        self.sign_data(signed_attrs_der)
    }

    /// User/signer certificate in DER format.
    fn user_cert_der(&self) -> &[u8];

    /// Full CA certificate chain in DER format (intermediate → root order).
    fn ca_chain_der(&self) -> &[Vec<u8>];

    /// User private key in DER (PKCS#8) format.
    ///
    /// Returns `None` for HSM backends where the key is not extractable.
    fn user_key_der(&self) -> Option<&[u8]>;

    /// Parsed user certificate.
    fn user_cert_parsed(&self) -> &x509_certificate::CapturedX509Certificate;

    /// Parsed CA certificates.
    fn ca_chain_parsed(&self) -> &[Arc<x509_certificate::CapturedX509Certificate>];

    /// Full certificate chain as Base64-encoded DER strings.
    /// Returns `[user_cert, ca_cert_1, ca_cert_2, ...]` order.
    fn cert_chain_base64(&self) -> Vec<String> {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        let mut chain = vec![engine.encode(self.user_cert_der())];
        for ca_der in self.ca_chain_der() {
            chain.push(engine.encode(ca_der));
        }
        chain
    }

    /// Backend name for logging.
    fn backend_name(&self) -> &str;
}

// ──────────────────────────────────────────────────────────────
// PEM Backend — in-memory signing from PEM files (existing behavior)
// ──────────────────────────────────────────────────────────────

/// PEM-based PKI backend — loads keys from PEM files into memory.
///
/// This is the original behavior: private key is loaded as PKCS#8 DER
/// and signing uses `InMemorySigningKeyPair` from the `x509-certificate` crate.
pub struct PemBackend {
    pub pki: crate::server::pki::PkiState,
}

impl PemBackend {
    pub fn new(pki: crate::server::pki::PkiState) -> Self {
        PemBackend { pki }
    }

    pub fn load_from_dir(cert_dir: &std::path::Path) -> Result<Self> {
        let pki = crate::server::pki::PkiState::load_from_dir(cert_dir)?;
        Ok(PemBackend { pki })
    }
}

impl PkiBackend for PemBackend {
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        use signature::Signer;
        use x509_certificate::InMemorySigningKeyPair;

        let key_pair = InMemorySigningKeyPair::from_pkcs8_der(&self.pki.user_key_der)
            .map_err(|e| anyhow::anyhow!("Failed to load signing key: {}", e))?;

        let sig = key_pair
            .try_sign(data)
            .map_err(|e| anyhow::anyhow!("RSA signing failed: {}", e))?;

        Ok(sig.into())
    }

    fn user_cert_der(&self) -> &[u8] {
        &self.pki.user_cert_der
    }

    fn ca_chain_der(&self) -> &[Vec<u8>] {
        &self.pki.ca_chain_der
    }

    fn user_key_der(&self) -> Option<&[u8]> {
        Some(&self.pki.user_key_der)
    }

    fn user_cert_parsed(&self) -> &x509_certificate::CapturedX509Certificate {
        &self.pki.user_cert_parsed
    }

    fn ca_chain_parsed(&self) -> &[Arc<x509_certificate::CapturedX509Certificate>] {
        &self.pki.ca_chain_parsed
    }

    fn backend_name(&self) -> &str {
        "PEM (in-memory)"
    }
}

// ──────────────────────────────────────────────────────────────
// HSM Backend — PKCS#11 signing via SoftHSM / hardware HSM
// ──────────────────────────────────────────────────────────────

/// HSM-based PKI backend — private key operations via PKCS#11.
///
/// The private key never leaves the HSM. Certificate data is still
/// loaded from PEM files (public data, not security-sensitive).
#[cfg(feature = "hsm")]
pub struct HsmBackend {
    signer: crate::server::hsm::HsmSigner,
    /// Certificates loaded from PEM files
    user_cert_der: Vec<u8>,
    ca_chain_der: Vec<Vec<u8>>,
    user_cert_parsed: Arc<x509_certificate::CapturedX509Certificate>,
    ca_chain_parsed: Vec<Arc<x509_certificate::CapturedX509Certificate>>,
}

#[cfg(feature = "hsm")]
impl HsmBackend {
    /// Create an HSM backend.
    ///
    /// - `pkcs11_lib` — Path to PKCS#11 shared library
    /// - `slot` — Token slot index
    /// - `pin` — User PIN
    /// - `key_label` — Label of the private key in the token
    /// - `cert_dir` — Directory with PEM certificate files (for public cert data)
    pub fn new(
        pkcs11_lib: &str,
        slot: usize,
        pin: &str,
        key_label: &str,
        cert_dir: &std::path::Path,
    ) -> Result<Self> {
        // Initialize the PKCS#11 signer
        let signer = crate::server::hsm::HsmSigner::new(pkcs11_lib, slot, pin, key_label)?;

        // Load certificates from PEM files (public data)
        let pki = crate::server::pki::PkiState::load_from_dir(cert_dir)?;

        log::info!(
            "HSM backend initialized: key='{}' via PKCS#11, certs from {:?}",
            key_label, cert_dir
        );

        Ok(HsmBackend {
            signer,
            user_cert_der: pki.user_cert_der,
            ca_chain_der: pki.ca_chain_der,
            user_cert_parsed: pki.user_cert_parsed,
            ca_chain_parsed: pki.ca_chain_parsed,
        })
    }
}

#[cfg(feature = "hsm")]
impl PkiBackend for HsmBackend {
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        // CKM_SHA256_RSA_PKCS: the HSM hashes + signs internally
        self.signer.sign(data)
    }

    fn user_cert_der(&self) -> &[u8] {
        &self.user_cert_der
    }

    fn ca_chain_der(&self) -> &[Vec<u8>] {
        &self.ca_chain_der
    }

    fn user_key_der(&self) -> Option<&[u8]> {
        None // Key is not extractable from HSM
    }

    fn user_cert_parsed(&self) -> &x509_certificate::CapturedX509Certificate {
        &self.user_cert_parsed
    }

    fn ca_chain_parsed(&self) -> &[Arc<x509_certificate::CapturedX509Certificate>] {
        &self.ca_chain_parsed
    }

    fn backend_name(&self) -> &str {
        "HSM (PKCS#11)"
    }
}

