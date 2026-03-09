//! PKCS#11 HSM signer — signs data via SoftHSM v2 (or any PKCS#11 token).
//!
//! This module provides `HsmSigner`, which opens a PKCS#11 session to a
//! hardware (or software) security module and performs RSA-SHA256 signing
//! using the private key stored in the token.
//!
//! The key never leaves the HSM — all signing happens inside the
//! PKCS#11 boundary. Certificates are still loaded from PEM files
//! (they are public data, not security-sensitive).
//!
//! # Example
//!
//! ```ignore
//! let signer = HsmSigner::new(
//!     "/usr/lib/softhsm/libsofthsm2.so",
//!     0,       // slot index
//!     "1234",  // user PIN
//!     "user-key",
//! )?;
//! let signature = signer.sign(b"data to sign")?;
//! ```
//!
//! # Thread Safety
//!
//! `HsmSigner` wraps the PKCS#11 session in a `Mutex` for safe concurrent
//! access from actix-web handler threads (via `spawn_blocking`).

use anyhow::{Context, Result};
use std::sync::Mutex;

use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;

/// PKCS#11 HSM signer — holds an authenticated session and key handle.
pub struct HsmSigner {
    /// PKCS#11 context (keeps the library loaded)
    _ctx: Pkcs11,
    /// Authenticated session (wrapped in Mutex for thread safety)
    session: Mutex<Session>,
    /// Handle to the private key object in the token
    key_handle: ObjectHandle,
    /// Key label (for logging)
    key_label: String,
}

impl HsmSigner {
    /// Connect to a PKCS#11 token and locate the signing key.
    ///
    /// # Arguments
    /// - `lib_path` — Path to the PKCS#11 shared library (e.g., `/usr/lib/softhsm/libsofthsm2.so`)
    /// - `slot_index` — Token slot index (typically 0)
    /// - `pin` — User PIN for the token
    /// - `key_label` — Label of the private key to use for signing
    pub fn new(lib_path: &str, slot_index: usize, pin: &str, key_label: &str) -> Result<Self> {
        log::info!(
            "Initializing PKCS#11 HSM: lib={}, slot={}, key={}",
            lib_path, slot_index, key_label
        );

        // Initialize the PKCS#11 library
        let ctx = Pkcs11::new(lib_path)
            .context(format!("Failed to load PKCS#11 library: {}", lib_path))?;
        ctx.initialize(CInitializeArgs::OsThreads)
            .context("Failed to initialize PKCS#11")?;

        // Get available slots with tokens
        let slots = ctx
            .get_slots_with_initialized_token()
            .context("Failed to list PKCS#11 slots")?;

        if slots.is_empty() {
            anyhow::bail!("No initialized PKCS#11 tokens found");
        }
        if slot_index >= slots.len() {
            anyhow::bail!(
                "Slot index {} out of range (available: {})",
                slot_index,
                slots.len()
            );
        }

        let slot = slots[slot_index];
        let token_info = ctx.get_token_info(slot).context("Failed to get token info")?;
        log::info!(
            "PKCS#11 token: label='{}', model='{}', serial='{}'",
            String::from_utf8_lossy(token_info.label()),
            String::from_utf8_lossy(token_info.model()),
            String::from_utf8_lossy(token_info.serial_number()),
        );

        // Open a read/write session and login
        let session = ctx
            .open_rw_session(slot)
            .context("Failed to open PKCS#11 session")?;

        session
            .login(UserType::User, Some(&AuthPin::new(pin.into())))
            .context("Failed to login to PKCS#11 token")?;

        log::info!("PKCS#11 session authenticated (User)");

        // Find the private key by label
        let key_handle = Self::find_private_key(&session, key_label)?;
        log::info!(
            "Found private key: label='{}', handle={:?}",
            key_label, key_handle
        );

        Ok(HsmSigner {
            _ctx: ctx,
            session: Mutex::new(session),
            key_handle,
            key_label: key_label.to_string(),
        })
    }

    /// Find a private key in the token by label.
    fn find_private_key(session: &Session, label: &str) -> Result<ObjectHandle> {
        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Label(label.as_bytes().to_vec()),
        ];

        let objects = session
            .find_objects(&template)
            .context("Failed to search for private key in token")?;

        match objects.first() {
            Some(handle) => Ok(*handle),
            None => anyhow::bail!(
                "Private key with label '{}' not found in PKCS#11 token",
                label
            ),
        }
    }

    /// Sign data using RSA-SHA256 via the HSM.
    ///
    /// The PKCS#11 `CKM_SHA256_RSA_PKCS` mechanism hashes the input
    /// and produces an RSA PKCS#1 v1.5 signature internally.
    ///
    /// **Important**: Pass the raw data (e.g., DER-encoded signed attributes),
    /// NOT a pre-computed hash. The mechanism handles hashing internally.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let session = self
            .session
            .lock()
            .map_err(|e| anyhow::anyhow!("Failed to lock PKCS#11 session: {}", e))?;

        let mechanism = Mechanism::Sha256RsaPkcs;

        let signature = session
            .sign(&mechanism, self.key_handle, data)
            .context("PKCS#11 RSA-SHA256 signing failed")?;

        log::debug!(
            "HSM sign: {} bytes input → {} bytes signature (key={})",
            data.len(),
            signature.len(),
            self.key_label,
        );

        Ok(signature)
    }

    /// Sign a pre-computed hash using RSA PKCS#1 v1.5 (without internal hashing).
    ///
    /// Uses `CKM_RSA_PKCS` mechanism — the input must be a properly formatted
    /// DigestInfo structure (DER-encoded AlgorithmIdentifier + hash).
    ///
    /// For SHA-256, the DigestInfo prefix is:
    /// `30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20` + hash
    pub fn sign_hash_raw(&self, hash: &[u8]) -> Result<Vec<u8>> {
        let session = self
            .session
            .lock()
            .map_err(|e| anyhow::anyhow!("Failed to lock PKCS#11 session: {}", e))?;

        // Build DigestInfo = SEQUENCE { AlgorithmIdentifier, OCTET STRING hash }
        // For SHA-256: 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
        let mut digest_info = vec![
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
            0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
        ];
        digest_info.extend_from_slice(hash);

        let mechanism = Mechanism::RsaPkcs;

        let signature = session
            .sign(&mechanism, self.key_handle, &digest_info)
            .context("PKCS#11 RSA_PKCS signing (raw hash) failed")?;

        log::debug!(
            "HSM sign_hash_raw: {} bytes hash → {} bytes signature",
            hash.len(),
            signature.len(),
        );

        Ok(signature)
    }

    /// Get key metadata for logging/diagnostics.
    pub fn key_info(&self) -> Result<String> {
        let session = self
            .session
            .lock()
            .map_err(|e| anyhow::anyhow!("Failed to lock session: {}", e))?;

        let template = vec![Attribute::Class(ObjectClass::PRIVATE_KEY)];
        let objects = session.find_objects(&template).unwrap_or_default();

        let mut info = format!("PKCS#11 token: {} key(s)\n", objects.len());
        for obj in &objects {
            let attrs = session
                .get_attributes(*obj, &[AttributeType::Label, AttributeType::KeyType])
                .unwrap_or_default();
            for attr in &attrs {
                match attr {
                    Attribute::Label(l) => {
                        info.push_str(&format!(
                            "  Key: label='{}'\n",
                            String::from_utf8_lossy(l)
                        ));
                    }
                    _ => {}
                }
            }
        }
        Ok(info)
    }
}

impl std::fmt::Debug for HsmSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HsmSigner")
            .field("key_label", &self.key_label)
            .finish()
    }
}

