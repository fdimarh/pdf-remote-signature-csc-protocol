//! CSC API v2 request/response types
//!
//! Based on the Cloud Signature Consortium API specification v2.0.
//! See: <https://cloudsignatureconsortium.org/resources/download-api-specifications/>

use serde::{Deserialize, Serialize};

// ─────────────────────── /csc/v2/info ───────────────────────

/// Response for `POST /csc/v2/info`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfoResponse {
    pub specs: String,
    pub name: String,
    pub logo: String,
    pub region: String,
    pub lang: String,
    pub description: String,
    #[serde(rename = "authType")]
    pub auth_type: Vec<String>,
    pub methods: Vec<String>,
    /// Supported signature formats
    #[serde(rename = "signatureFormats")]
    pub signature_formats: Vec<String>,
    /// Supported PAdES conformance levels
    #[serde(rename = "padesLevels")]
    pub pades_levels: Vec<String>,
}

// ─────────────────────── /csc/v2/auth/login ─────────────────

/// Request for `POST /csc/v2/auth/login`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthLoginRequest {
    #[serde(rename = "rememberMe", default)]
    pub remember_me: bool,
}

/// Response for `POST /csc/v2/auth/login`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthLoginResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

// ─────────────────── /csc/v2/credentials/list ───────────────

/// Request for `POST /csc/v2/credentials/list`
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CredentialsListRequest {
    #[serde(rename = "maxResults", skip_serializing_if = "Option::is_none")]
    pub max_results: Option<u32>,
}

/// Response for `POST /csc/v2/credentials/list`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialsListResponse {
    #[serde(rename = "credentialIDs")]
    pub credential_ids: Vec<String>,
}

// ─────────────────── /csc/v2/credentials/info ───────────────

/// Request for `POST /csc/v2/credentials/info`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialsInfoRequest {
    #[serde(rename = "credentialID")]
    pub credential_id: String,
    #[serde(default = "default_certificates_param")]
    pub certificates: String,
}

fn default_certificates_param() -> String {
    "single".to_string()
}

/// Key information in credentials/info response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    pub status: String,
    pub algo: Vec<String>,
    pub len: u32,
}

/// Certificate information in credentials/info response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertInfo {
    pub status: String,
    /// Base64-encoded DER certificates
    pub certificates: Vec<String>,
    #[serde(rename = "issuerDN")]
    pub issuer_dn: String,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    #[serde(rename = "subjectDN")]
    pub subject_dn: String,
    #[serde(rename = "validFrom")]
    pub valid_from: String,
    #[serde(rename = "validTo")]
    pub valid_to: String,
}

/// Response for `POST /csc/v2/credentials/info`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialsInfoResponse {
    pub key: KeyInfo,
    pub cert: CertInfo,
    #[serde(rename = "authMode")]
    pub auth_mode: String,
}

// ──────────────── /csc/v2/signatures/signHash ───────────────

/// Request for `POST /csc/v2/signatures/signHash`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignHashRequest {
    #[serde(rename = "credentialID")]
    pub credential_id: String,
    /// Signature Activation Data (simplified for prototype)
    #[serde(rename = "SAD", skip_serializing_if = "Option::is_none")]
    pub sad: Option<String>,
    /// Base64-encoded hash(es) to sign
    pub hashes: Vec<String>,
    /// OID of the hash algorithm (SHA-256 = "2.16.840.1.101.3.4.2.1")
    #[serde(rename = "hashAlgo")]
    pub hash_algo: String,
    /// OID of the signature algorithm (RSA-SHA256 = "1.2.840.113549.1.1.11")
    #[serde(rename = "signAlgo")]
    pub sign_algo: String,
    /// Signature format: "pkcs7" or "pades" (default: "pades")
    #[serde(rename = "signatureFormat", default = "default_sig_format_hash")]
    pub signature_format: String,
    /// PAdES conformance level: "B-B", "B-T", "B-LT", "B-LTA" (default: "B-B")
    #[serde(rename = "padesLevel", default = "default_pades_level_hash")]
    pub pades_level: String,
    /// TSA URL for timestamp
    #[serde(rename = "timestampUrl", skip_serializing_if = "Option::is_none", default)]
    pub timestamp_url: Option<String>,
    /// Include CRL in CMS signed attributes
    #[serde(rename = "includeCrl", default)]
    pub include_crl: bool,
    /// Include OCSP in CMS signed attributes
    #[serde(rename = "includeOcsp", default)]
    pub include_ocsp: bool,
}

fn default_sig_format_hash() -> String {
    "pades".to_string()
}

fn default_pades_level_hash() -> String {
    "B-B".to_string()
}

/// Response for `POST /csc/v2/signatures/signHash`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignHashResponse {
    /// Base64-encoded CMS/PKCS#7 signature(s)
    pub signatures: Vec<String>,
}

// ──────────────── /csc/v2/signatures/signDoc ────────────────
// Extension endpoint: accepts raw document content bytes so the server
// can build a complete CMS SignedData with correct messageDigest.

/// Request for `POST /csc/v2/signatures/signDoc`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignDocRequest {
    #[serde(rename = "credentialID")]
    pub credential_id: String,
    /// Base64-encoded document content bytes (byte ranges concatenated)
    #[serde(rename = "documentContent")]
    pub document_content: String,
    /// OID of the hash algorithm
    #[serde(rename = "hashAlgo")]
    pub hash_algo: String,
    /// OID of the signature algorithm
    #[serde(rename = "signAlgo")]
    pub sign_algo: String,
    /// Signature format: "pkcs7" or "pades" (default: "pades")
    #[serde(rename = "signatureFormat", default = "default_sig_format")]
    pub signature_format: String,
    /// PAdES conformance level: "B-B", "B-T", "B-LT", "B-LTA" (default: "B-B")
    /// Only used when signatureFormat is "pades"
    #[serde(rename = "padesLevel", default = "default_pades_level")]
    pub pades_level: String,
    /// TSA URL for timestamp (used for B-T, B-LT, B-LTA)
    #[serde(rename = "timestampUrl", skip_serializing_if = "Option::is_none")]
    pub timestamp_url: Option<String>,
    /// Include CRL in CMS signed attributes
    #[serde(rename = "includeCrl", default)]
    pub include_crl: bool,
    /// Include OCSP in CMS signed attributes
    #[serde(rename = "includeOcsp", default)]
    pub include_ocsp: bool,
}

fn default_sig_format() -> String {
    "pades".to_string()
}

fn default_pades_level() -> String {
    "B-B".to_string()
}

/// Response for `POST /csc/v2/signatures/signDoc`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignDocResponse {
    /// Base64-encoded CMS/PKCS#7 signature
    pub signature: String,
    /// The format that was used
    #[serde(rename = "signatureFormat")]
    pub signature_format: String,
    /// The PAdES level that was used (if applicable)
    #[serde(rename = "padesLevel", skip_serializing_if = "Option::is_none")]
    pub pades_level: Option<String>,
}

// ──────────────── /api/v1/validate ──────────────────────────

/// Request for `POST /api/v1/validate`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateRequest {
    /// Base64-encoded PDF bytes
    #[serde(rename = "pdfContent")]
    pub pdf_content: String,
    /// Optional password for encrypted PDFs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// Certificate info in validation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateCertInfo {
    pub subject: String,
    pub issuer: String,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    #[serde(rename = "notBefore", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(rename = "notAfter", skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(rename = "isExpired")]
    pub is_expired: bool,
    #[serde(rename = "isSelfSigned")]
    pub is_self_signed: bool,
}

/// Per-signature validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureValidationResult {
    /// Field name in the PDF
    #[serde(rename = "fieldName", skip_serializing_if = "Option::is_none")]
    pub field_name: Option<String>,
    /// Signer name from the signature dictionary
    #[serde(rename = "signerName", skip_serializing_if = "Option::is_none")]
    pub signer_name: Option<String>,
    /// Contact info
    #[serde(rename = "contactInfo", skip_serializing_if = "Option::is_none")]
    pub contact_info: Option<String>,
    /// Signing reason
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Signing time
    #[serde(rename = "signingTime", skip_serializing_if = "Option::is_none")]
    pub signing_time: Option<String>,
    /// Filter (e.g. "Adobe.PPKLite")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    /// SubFilter (e.g. "adbe.pkcs7.detached" or "ETSI.CAdES.detached")
    #[serde(rename = "subFilter", skip_serializing_if = "Option::is_none")]
    pub sub_filter: Option<String>,

    /// Overall validity
    #[serde(rename = "isValid")]
    pub is_valid: bool,

    // ── Cryptographic checks ──
    #[serde(rename = "digestMatch")]
    pub digest_match: bool,
    #[serde(rename = "cmsSignatureValid")]
    pub cms_signature_valid: bool,
    #[serde(rename = "certificateChainValid")]
    pub certificate_chain_valid: bool,
    #[serde(rename = "certificateChainTrusted")]
    pub certificate_chain_trusted: bool,

    // ── ByteRange checks ──
    #[serde(rename = "byteRange")]
    pub byte_range: Vec<i64>,
    #[serde(rename = "byteRangeValid")]
    pub byte_range_valid: bool,
    #[serde(rename = "byteRangeCoversWholeFile")]
    pub byte_range_covers_whole_file: bool,

    // ── LTV / Long-Term Validation ──
    #[serde(rename = "hasDss")]
    pub has_dss: bool,
    #[serde(rename = "dssCrlCount")]
    pub dss_crl_count: usize,
    #[serde(rename = "dssOcspCount")]
    pub dss_ocsp_count: usize,
    #[serde(rename = "dssCertCount")]
    pub dss_cert_count: usize,
    #[serde(rename = "hasVri")]
    pub has_vri: bool,
    #[serde(rename = "hasCmsRevocationData")]
    pub has_cms_revocation_data: bool,
    #[serde(rename = "hasTimestamp")]
    pub has_timestamp: bool,
    #[serde(rename = "isLtvEnabled")]
    pub is_ltv_enabled: bool,

    // ── Modification detection ──
    #[serde(rename = "noUnauthorizedModifications")]
    pub no_unauthorized_modifications: bool,
    #[serde(rename = "modificationNotes")]
    pub modification_notes: Vec<String>,

    // ── Security / Attack detection ──
    #[serde(rename = "signatureNotWrapped")]
    pub signature_not_wrapped: bool,
    #[serde(rename = "certificationLevel", skip_serializing_if = "Option::is_none")]
    pub certification_level: Option<u8>,
    #[serde(rename = "certificationPermissionOk")]
    pub certification_permission_ok: bool,
    #[serde(rename = "securityWarnings")]
    pub security_warnings: Vec<String>,
    #[serde(rename = "chainWarnings")]
    pub chain_warnings: Vec<String>,

    // ── Certificates ──
    pub certificates: Vec<ValidateCertInfo>,

    // ── Errors ──
    pub errors: Vec<String>,

    // ── Encryption ──
    #[serde(rename = "isEncrypted")]
    pub is_encrypted: bool,
    /// Is this a document timestamp (PAdES B-LTA)?
    #[serde(rename = "isDocumentTimestamp")]
    pub is_document_timestamp: bool,
}

/// Response for `POST /api/v1/validate`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateResponse {
    /// Number of signatures found
    #[serde(rename = "signatureCount")]
    pub signature_count: usize,
    /// `true` when ALL signatures are valid
    #[serde(rename = "allValid")]
    pub all_valid: bool,
    /// Per-signature results
    pub signatures: Vec<SignatureValidationResult>,
}

// ──────────────── /api/v1/signPdf ────────────────────────────
// Server-side full PDF signing — server handles preparation,
// visible image embedding, CMS signing, and embedding.

/// Request for `POST /api/v1/signPdf`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignPdfRequest {
    #[serde(rename = "credentialID")]
    pub credential_id: String,
    /// Base64-encoded PDF file bytes
    #[serde(rename = "pdfContent")]
    pub pdf_content: String,
    /// Optional Base64-encoded signature image (PNG or JPEG) for visible signatures
    #[serde(rename = "imageContent", skip_serializing_if = "Option::is_none")]
    pub image_content: Option<String>,
    /// Signature rectangle [x1, y1, x2, y2] in PDF points (required when image is provided)
    #[serde(rename = "sigRect", skip_serializing_if = "Option::is_none")]
    pub sig_rect: Option<[f32; 4]>,
    /// Page number for the visible signature (1-based, default: 1)
    #[serde(rename = "sigPage", default = "default_page")]
    pub sig_page: u32,
    /// Signer display name (used in signature dictionary)
    #[serde(rename = "signerName", default = "default_signer_name")]
    pub signer_name: String,
    /// Signature format: "pkcs7" or "pades" (default: "pades")
    #[serde(rename = "signatureFormat", default = "default_sig_format")]
    pub signature_format: String,
    /// PAdES level: "B-B", "B-T", "B-LT", "B-LTA" (default: "B-B")
    #[serde(rename = "padesLevel", default = "default_pades_level")]
    pub pades_level: String,
    /// TSA URL for timestamp
    #[serde(rename = "timestampUrl", skip_serializing_if = "Option::is_none")]
    pub timestamp_url: Option<String>,
    /// Include CRL in CMS
    #[serde(rename = "includeCrl", default)]
    pub include_crl: bool,
    /// Include OCSP in CMS
    #[serde(rename = "includeOcsp", default)]
    pub include_ocsp: bool,
}

fn default_page() -> u32 {
    1
}

fn default_signer_name() -> String {
    "Digital Signature".to_string()
}

/// Response for `POST /api/v1/signPdf`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignPdfResponse {
    /// Base64-encoded signed PDF
    #[serde(rename = "signedPdf")]
    pub signed_pdf: String,
    /// Signature format used
    #[serde(rename = "signatureFormat")]
    pub signature_format: String,
    /// PAdES level used (if applicable)
    #[serde(rename = "padesLevel", skip_serializing_if = "Option::is_none")]
    pub pades_level: Option<String>,
    /// Whether a visible signature image was embedded
    #[serde(rename = "hasVisibleSignature")]
    pub has_visible_signature: bool,
}

// ──────────────────── Error Response ────────────────────────

/// CSC API error response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CscErrorResponse {
    pub error: String,
    pub error_description: String,
}

// ──────────────────── Constants ─────────────────────────────

/// SHA-256 OID
pub const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
/// RSA-SHA256 OID
pub const OID_RSA_SHA256: &str = "1.2.840.113549.1.1.11";

