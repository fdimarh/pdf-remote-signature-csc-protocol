//! `/csc/v2/signatures/signHash` and `/csc/v2/signatures/signDoc` endpoints.
//!
//! `signHash` — standard CSC: receives a pre-computed hash, builds a proper
//!              CMS SignedData with the hash as messageDigest (manual DER).
//! `signDoc`  — extension: receives raw content bytes, builds proper CMS
//!              with correct messageDigest via the `cryptographic-message-syntax` library.

use actix_multipart::Multipart;
use actix_web::{web, HttpRequest, HttpResponse};
use base64::Engine;
use bcder::Mode::Der;
use bcder::{encode::{PrimitiveContent, Values}, Captured, OctetString};
use cryptographic_message_syntax::{Bytes, Oid, SignedDataBuilder, SignerBuilder};
use sha2::{Digest, Sha256};
use x509_certificate::rfc5652::AttributeValue;
use x509_certificate::{CapturedX509Certificate, InMemorySigningKeyPair};

use crate::common::csc_types::{
    CscErrorResponse, SignDocRequest, SignDocResponse, SignHashRequest, SignHashResponse,
    OID_SHA256,
};
use crate::server::app::AppState;
use crate::server::auth::{validate_bearer_token, USERS};

/// `POST /csc/v2/signatures/signHash`
///
/// Standard CSC endpoint. Receives Base64-encoded SHA-256 hash(es).
/// The hash is used directly as the CMS `messageDigest` signed attribute,
/// then the signed attributes are RSA-signed and packaged into a
/// PKCS#7/CMS SignedData structure.
///
/// This produces a valid detached CMS signature suitable for embedding
/// into a PDF whose byte-range content hashes to the provided value.
pub async fn sign_hash_handler(
    req: HttpRequest,
    body: web::Json<SignHashRequest>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let claims = match validate_bearer_token(&req) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    if !has_credential_access(&claims.sub, &body.credential_id) {
        return forbidden_response(&body.credential_id);
    }

    if body.hash_algo != OID_SHA256 {
        return HttpResponse::BadRequest().json(CscErrorResponse {
            error: "invalid_request".to_string(),
            error_description: format!(
                "Unsupported hash algorithm. Only SHA-256 ({}) is supported.",
                OID_SHA256
            ),
        });
    }

    if body.hashes.is_empty() {
        return HttpResponse::BadRequest().json(CscErrorResponse {
            error: "invalid_request".to_string(),
            error_description: "No hashes provided".to_string(),
        });
    }

    let pki = &state.pki;
    let b64 = base64::engine::general_purpose::STANDARD;

    let mut signatures = Vec::with_capacity(body.hashes.len());
    for (i, hash_b64) in body.hashes.iter().enumerate() {
        let hash_bytes = match b64.decode(hash_b64) {
            Ok(h) if h.len() == 32 => h,
            Ok(h) => {
                return HttpResponse::BadRequest().json(CscErrorResponse {
                    error: "invalid_request".to_string(),
                    error_description: format!(
                        "Hash[{}] is {} bytes, expected 32",
                        i,
                        h.len()
                    ),
                });
            }
            Err(e) => {
                return HttpResponse::BadRequest().json(CscErrorResponse {
                    error: "invalid_request".to_string(),
                    error_description: format!("Invalid Base64 in hash[{}]: {}", i, e),
                });
            }
        };

        // Build CMS with the hash directly as messageDigest (no double-hashing)
        let pki_clone = pki.clone();
        let hash = hash_bytes.clone();
        let cms_opts = CmsSigningOptions {
            signature_format: body.signature_format.to_lowercase(),
            pades_level: body.pades_level.to_uppercase()
                .replace("BB", "B-B").replace("BT", "B-T")
                .replace("BLT", "B-LT").replace("BLTA", "B-LTA"),
            timestamp_url: body.timestamp_url.clone(),
            include_crl: body.include_crl,
            include_ocsp: body.include_ocsp,
        };
        match tokio::task::spawn_blocking(move || {
            build_cms_from_hash(&pki_clone, &hash, &cms_opts)
        }).await {
            Ok(Ok(cms_der)) => signatures.push(b64.encode(&cms_der)),
            Ok(Err(e)) => {
                log::error!("CMS build failed for hash[{}]: {}", i, e);
                return HttpResponse::InternalServerError().json(CscErrorResponse {
                    error: "server_error".to_string(),
                    error_description: format!("Signing failed: {}", e),
                });
            }
            Err(e) => {
                log::error!("CMS signing task panicked for hash[{}]: {}", i, e);
                return HttpResponse::InternalServerError().json(CscErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Internal signing error".to_string(),
                });
            }
        }
    }

    log::info!(
        "User '{}' signed {} hash(es) with '{}'",
        claims.sub,
        signatures.len(),
        body.credential_id
    );

    HttpResponse::Ok().json(SignHashResponse { signatures })
}

/// `POST /csc/v2/signatures/signDoc`
///
/// Extension endpoint. Receives Base64-encoded raw document content bytes
/// (the concatenated byte ranges). The server computes the hash internally
/// and builds a proper CMS SignedData with correct messageDigest.
///
/// Supports all signing variants:
/// - signatureFormat: "pkcs7" (adbe.pkcs7.detached) or "pades" (ETSI.CAdES.detached)
/// - padesLevel: "B-B", "B-T", "B-LT", "B-LTA"
/// - timestampUrl: TSA URL for B-T/B-LT/B-LTA levels
/// - includeCrl / includeOcsp: CMS signed attribute revocation data
pub async fn sign_doc_handler(
    req: HttpRequest,
    body: web::Json<SignDocRequest>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let claims = match validate_bearer_token(&req) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    if !has_credential_access(&claims.sub, &body.credential_id) {
        return forbidden_response(&body.credential_id);
    }

    if body.hash_algo != OID_SHA256 {
        return HttpResponse::BadRequest().json(CscErrorResponse {
            error: "invalid_request".to_string(),
            error_description: "Only SHA-256 is supported".to_string(),
        });
    }

    let pki = &state.pki;
    let b64 = base64::engine::general_purpose::STANDARD;

    let content_bytes = match b64.decode(&body.document_content) {
        Ok(c) => c,
        Err(e) => {
            return HttpResponse::BadRequest().json(CscErrorResponse {
                error: "invalid_request".to_string(),
                error_description: format!("Invalid Base64 in documentContent: {}", e),
            });
        }
    };

    let sig_format = body.signature_format.to_lowercase();
    let pades_level = body.pades_level.to_uppercase()
        .replace("BB", "B-B").replace("BT", "B-T")
        .replace("BLT", "B-LT").replace("BLTA", "B-LTA");

    log::info!(
        "Building CMS for {} bytes — format={}, level={}, tsa={:?}, crl={}, ocsp={}",
        content_bytes.len(),
        sig_format,
        pades_level,
        body.timestamp_url,
        body.include_crl,
        body.include_ocsp,
    );

    let cms_options = CmsSigningOptions {
        signature_format: sig_format.clone(),
        pades_level: pades_level.clone(),
        timestamp_url: body.timestamp_url.clone(),
        include_crl: body.include_crl,
        include_ocsp: body.include_ocsp,
    };

    let pki_clone = pki.clone();
    let content = content_bytes.clone();
    let cms_opts = cms_options.clone();
    let cms_result = tokio::task::spawn_blocking(move || {
        build_cms_with_options(&pki_clone, &content, &cms_opts)
    }).await;

    match cms_result {
        Ok(Ok(cms_der)) => {
            log::info!(
                "User '{}' signed document with '{}' — format={}, level={}, CMS {} bytes",
                claims.sub,
                body.credential_id,
                sig_format,
                pades_level,
                cms_der.len()
            );
            let pades_level_resp = if sig_format == "pades" {
                Some(pades_level)
            } else {
                None
            };
            HttpResponse::Ok().json(SignDocResponse {
                signature: b64.encode(&cms_der),
                signature_format: sig_format,
                pades_level: pades_level_resp,
            })
        }
        Ok(Err(e)) => {
            log::error!("CMS build failed: {}", e);
            HttpResponse::InternalServerError().json(CscErrorResponse {
                error: "server_error".to_string(),
                error_description: format!("Signing failed: {}", e),
            })
        }
        Err(e) => {
            log::error!("CMS signing task panicked: {}", e);
            HttpResponse::InternalServerError().json(CscErrorResponse {
                error: "server_error".to_string(),
                error_description: "Internal signing error".to_string(),
            })
        }
    }
}

// ──────────────────── helpers ────────────────────────────────

pub(crate) fn has_credential_access(username: &str, credential_id: &str) -> bool {
    USERS
        .iter()
        .any(|u| u.username == username && u.credential_id == credential_id)
}

pub(crate) fn forbidden_response(credential_id: &str) -> HttpResponse {
    HttpResponse::Forbidden().json(CscErrorResponse {
        error: "invalid_request".to_string(),
        error_description: format!("No access to credential '{}'", credential_id),
    })
}

/// Options for CMS signature building
#[derive(Clone)]
pub(crate) struct CmsSigningOptions {
    pub(crate) signature_format: String,
    pub(crate) pades_level: String,
    pub(crate) timestamp_url: Option<String>,
    pub(crate) include_crl: bool,
    pub(crate) include_ocsp: bool,
}

/// Build a CMS/PKCS#7 `SignedData` from a **pre-computed hash**.
///
/// This is the correct implementation for the CSC signHash endpoint:
/// the received 32-byte SHA-256 hash is used **directly** as the
/// `messageDigest` signed attribute (no double-hashing).
///
/// Supports all signing variants via `CmsSigningOptions`:
/// - TSA timestamp (via unsigned `timeStampToken` attribute)
/// - CRL/OCSP revocation data (via `adbe-revocationInfoArchival` signed attribute)
///
/// The CMS SignedData structure is built manually because the
/// `cryptographic-message-syntax` library always re-hashes content
/// passed via `content_external()`.
fn build_cms_from_hash(
    pki: &crate::server::pki::PkiState,
    hash: &[u8], // 32-byte SHA-256 hash of the original byte-range content
    options: &CmsSigningOptions,
) -> Result<Vec<u8>, String> {
    use signature::Signer;

    let key_pair = InMemorySigningKeyPair::from_pkcs8_der(&pki.user_key_der)
        .map_err(|e| format!("Failed to load signing key: {}", e))?;

    let user_cert = CapturedX509Certificate::from_der(pki.user_cert_der.clone())
        .map_err(|e| format!("Failed to parse user cert: {}", e))?;

    // Parse CA chain certificates
    let mut ca_certs = Vec::new();
    for (i, ca_der) in pki.ca_chain_der.iter().enumerate() {
        let ca_cert = CapturedX509Certificate::from_der(ca_der.clone())
            .map_err(|e| format!("Failed to parse CA cert #{}: {}", i, e))?;
        ca_certs.push(ca_cert);
    }

    // Full certificate chain for revocation data fetching
    let mut full_chain = vec![user_cert.clone()];
    full_chain.extend(ca_certs.iter().cloned());

    // Extract issuer and serial number from user cert for SignerIdentifier
    let issuer_der = user_cert.issuer_name().encode_ref().to_captured(Der);
    let serial_der = user_cert.serial_number_asn1().encode_ref().to_captured(Der);

    // ── Determine what to include based on format and level ──
    let is_pades = options.signature_format == "pades";
    let (include_cms_revocation, include_timestamp) = if is_pades {
        match options.pades_level.as_str() {
            "B-B" => (false, false),
            "B-T" => (options.include_crl || options.include_ocsp, true),
            "B-LT" | "B-LTA" => (true, true),
            _ => (false, false),
        }
    } else {
        // PKCS7
        let wants_revocation = options.include_crl || options.include_ocsp;
        (wants_revocation, options.timestamp_url.is_some())
    };

    // ── Build signed attributes ──
    // 1. content-type attribute (OID 1.2.840.113549.1.9.3) = id-data (1.2.840.113549.1.7.1)
    let content_type_attr = der_attribute(
        &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03], // OID 1.2.840.113549.1.9.3 (id-contentType)
        &der_set_of(&[&der_oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01])]), // value = id-data
    );

    // 2. messageDigest = the pre-computed hash (NOT hashed again)
    let message_digest_attr = der_attribute(
        &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04], // OID 1.2.840.113549.1.9.4
        &der_set_of(&[&der_octet_string(hash)]),
    );

    // 3. signingTime
    let now = chrono::Utc::now();
    let time_str = now.format("%y%m%d%H%M%SZ").to_string();
    let signing_time_attr = der_attribute(
        &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05], // OID 1.2.840.113549.1.9.5
        &der_set_of(&[&der_utc_time(&time_str)]),
    );

    // 4. ESS-signing-certificate-v2 (1.2.840.113549.1.9.16.2.47)
    let cert_hash = {
        let mut hasher = Sha256::new();
        hasher.update(user_cert.encode_der().map_err(|e| format!("{}", e))?);
        hasher.finalize().to_vec()
    };
    let ess_cert_id_v2 = der_sequence(&der_sequence(&der_sequence(&der_octet_string(&cert_hash))));
    let signing_cert_v2_attr = der_attribute(
        &[0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x2f], // OID 1.2.840.113549.1.9.16.2.47
        &der_set_of(&[&ess_cert_id_v2]),
    );

    // Collect and sort attributes (DER SET must be sorted)
    let mut attrs = vec![
        content_type_attr,
        message_digest_attr,
        signing_time_attr,
        signing_cert_v2_attr,
    ];

    // 5. adbe-revocationInfoArchival (CRL/OCSP in CMS signed attributes)
    if include_cms_revocation {
        let crl_flag = if is_pades {
            matches!(options.pades_level.as_str(), "B-LT" | "B-LTA") || options.include_crl
        } else {
            true
        };
        let ocsp_flag = if is_pades {
            matches!(options.pades_level.as_str(), "B-LT" | "B-LTA") || options.include_ocsp
        } else {
            true
        };

        log::info!(
            "signHash: fetching revocation data: crl={}, ocsp={} for {} cert(s)",
            crl_flag, ocsp_flag, full_chain.len()
        );

        // Use the LTV module to build the attribute, then DER-encode it manually
        // for inclusion in our hand-built CMS
        let (crl_data, ocsp_data) =
            crate::server::ltv::fetch_revocation_data(&full_chain, crl_flag, ocsp_flag);

        if !crl_data.is_empty() || !ocsp_data.is_empty() {
            let revocation_attr = build_adbe_revocation_attr_der(&crl_data, &ocsp_data);
            log::info!("signHash: added adbe-revocationInfoArchival ({} bytes)", revocation_attr.len());
            attrs.push(revocation_attr);
        } else {
            log::warn!("signHash: no revocation data could be fetched");
        }
    }

    attrs.sort();

    // Build SET OF signed attributes
    let mut attrs_content = Vec::new();
    for attr in &attrs {
        attrs_content.extend_from_slice(attr);
    }

    // For signing, the signed attributes are DER-encoded as a SET (tag 0x31)
    let signed_attrs_for_sig = der_tlv(0x31, &attrs_content);

    // Sign the DER-encoded signed attributes using the signature::Signer trait
    let sig = key_pair
        .try_sign(&signed_attrs_for_sig)
        .map_err(|e| format!("RSA signing failed: {}", e))?;
    let signature_bytes: Vec<u8> = sig.into();

    // ── Build unsigned attributes (TSA timestamp) ──
    let unsigned_attrs_content = if include_timestamp {
        if let Some(tsa_url) = &options.timestamp_url {
            // Hash the signature value for the timestamp
            let sig_hash = {
                let mut hasher = Sha256::new();
                hasher.update(&signature_bytes);
                hasher.finalize().to_vec()
            };

            log::info!("signHash: fetching timestamp from {}", tsa_url);
            match crate::server::ltv::fetch_timestamp_token(tsa_url, &sig_hash) {
                Ok(ts_token) => {
                    log::info!("signHash: got timestamp token: {} bytes", ts_token.len());
                    // Build timeStampToken unsigned attribute
                    // OID 1.2.840.113549.1.9.16.2.14 (id-smime-aa-timeStampToken)
                    let ts_attr = der_attribute(
                        &[0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x0e],
                        &der_set_of(&[&ts_token]),
                    );
                    let mut content = Vec::new();
                    content.extend_from_slice(&ts_attr);
                    Some(content)
                }
                Err(e) => {
                    log::warn!("signHash: TSA timestamp failed: {}", e);
                    None
                }
            }
        } else {
            log::warn!("signHash: timestamp requested but no TSA URL provided");
            None
        }
    } else {
        None
    };

    // ── Build SignerInfo ──
    let signer_info = {
        let mut si = Vec::new();

        // version = 1
        si.extend_from_slice(&der_integer_small(1));

        // sid = IssuerAndSerialNumber
        let mut ias = Vec::new();
        ias.extend_from_slice(issuer_der.as_slice());
        ias.extend_from_slice(serial_der.as_slice());
        si.extend_from_slice(&der_sequence(&ias));

        // digestAlgorithm = SHA-256 (2.16.840.1.101.3.4.2.1)
        let sha256_alg_id = der_sequence_raw(&[
            &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01][..],
            &[0x05, 0x00], // NULL parameters
        ]);
        si.extend_from_slice(&sha256_alg_id);

        // signedAttrs [0] IMPLICIT
        si.extend_from_slice(&der_tlv(0xa0, &attrs_content));

        // signatureAlgorithm = RSA-SHA256 (1.2.840.113549.1.1.11)
        let rsa_sha256_alg_id = der_sequence_raw(&[
            &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b][..],
            &[0x05, 0x00],
        ]);
        si.extend_from_slice(&rsa_sha256_alg_id);

        // signature = OCTET STRING
        si.extend_from_slice(&der_octet_string(&signature_bytes));

        // unsignedAttrs [1] IMPLICIT (optional — contains timestamp)
        if let Some(ref ua_content) = unsigned_attrs_content {
            si.extend_from_slice(&der_tlv(0xa1, ua_content));
        }

        der_sequence(&si)
    };

    // ── Build SignedData ──
    let signed_data = {
        let mut sd = Vec::new();

        // version = 1
        sd.extend_from_slice(&der_integer_small(1));

        // digestAlgorithms SET OF AlgorithmIdentifier
        let sha256_alg_id = der_sequence_raw(&[
            &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01][..],
            &[0x05, 0x00],
        ]);
        sd.extend_from_slice(&der_set_of(&[&sha256_alg_id]));

        // encapContentInfo = SEQUENCE { contentType, [no content for detached] }
        let ecinfo = der_sequence_raw(&[
            &der_oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01]),
        ]);
        sd.extend_from_slice(&ecinfo);

        // certificates [0] IMPLICIT — include user cert + CA chain
        let mut certs_content = Vec::new();
        certs_content.extend_from_slice(&pki.user_cert_der);
        for ca_der in &pki.ca_chain_der {
            certs_content.extend_from_slice(ca_der);
        }
        sd.extend_from_slice(&der_tlv(0xa0, &certs_content));

        // signerInfos SET OF
        sd.extend_from_slice(&der_set_of(&[&signer_info]));

        der_sequence_raw(&[&sd])
    };

    // ── Wrap in ContentInfo (OID = id-signedData) ──
    let content_info = {
        let mut ci = Vec::new();
        // contentType = id-signedData (1.2.840.113549.1.7.2)
        ci.extend_from_slice(&der_oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]));
        // content [0] EXPLICIT
        ci.extend_from_slice(&der_tlv(0xa0, &signed_data));
        der_sequence_raw(&[&ci])
    };

    log::info!(
        "Built CMS from hash: {} bytes (format={}, level={}, ts={}, rev={})",
        content_info.len(),
        options.signature_format,
        options.pades_level,
        include_timestamp,
        include_cms_revocation,
    );
    Ok(content_info)
}

/// Build the adbe-revocationInfoArchival DER attribute for manual CMS construction.
///
/// OID: 1.2.840.113583.1.1.8
/// Encodes CRL and OCSP data into the RevocationInfoArchival ASN.1 structure,
/// then wraps it as a DER SEQUENCE { OID, SET { value } } attribute.
fn build_adbe_revocation_attr_der(crl_data: &[Vec<u8>], ocsp_data: &[Vec<u8>]) -> Vec<u8> {
    // Build RevocationInfoArchival SEQUENCE content
    let mut rev_content = Vec::new();

    // CRL data: [0] SEQUENCE OF CRL
    if !crl_data.is_empty() {
        let mut crls_content = Vec::new();
        for crl in crl_data {
            crls_content.extend_from_slice(crl); // Each CRL is already DER-encoded
        }
        let crls_seq = der_sequence(&crls_content);
        rev_content.extend_from_slice(&der_tlv(0xa0, &crls_seq)); // [0] IMPLICIT
    }

    // OCSP data: [1] SEQUENCE OF OCSPResponse
    if !ocsp_data.is_empty() {
        let mut ocsps_content = Vec::new();
        for ocsp in ocsp_data {
            // Wrap each OCSP response as OCSPResponse { responseStatus, responseBytes }
            let mut ocsp_resp = Vec::new();
            // responseStatus ENUMERATED 0 (successful)
            ocsp_resp.extend_from_slice(&[0x0a, 0x01, 0x00]);
            // responseBytes [0] EXPLICIT SEQUENCE { OID, OCTET STRING }
            let pkix_basic_oid = der_oid(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01]); // 1.3.6.1.5.5.7.48.1.1
            let ocsp_octet = der_octet_string(ocsp);
            let resp_bytes_seq = der_sequence(&[pkix_basic_oid, ocsp_octet].concat());
            ocsp_resp.extend_from_slice(&der_tlv(0xa0, &resp_bytes_seq));
            ocsps_content.extend_from_slice(&der_sequence(&ocsp_resp));
        }
        let ocsps_seq = der_sequence(&ocsps_content);
        rev_content.extend_from_slice(&der_tlv(0xa1, &ocsps_seq)); // [1] IMPLICIT
    }

    let rev_archival = der_sequence(&rev_content);

    // Wrap as attribute: SEQUENCE { OID, SET { value } }
    // OID 1.2.840.113583.1.1.8 = adbe-revocationInfoArchival
    der_attribute(
        &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x2f, 0x01, 0x01, 0x08],
        &der_set_of(&[&rev_archival]),
    )
}

// ── DER encoding helpers for manual CMS construction ──

fn der_push_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(0x81);
        buf.push(len as u8);
    } else if len < 0x10000 {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    } else if len < 0x1000000 {
        buf.push(0x83);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    } else {
        buf.push(0x84);
        buf.push((len >> 24) as u8);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    der_push_length(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

fn der_sequence(content: &[u8]) -> Vec<u8> {
    der_tlv(0x30, content)
}

fn der_sequence_raw(parts: &[&[u8]]) -> Vec<u8> {
    let mut content = Vec::new();
    for part in parts {
        content.extend_from_slice(part);
    }
    der_tlv(0x30, &content)
}

fn der_set_of(items: &[&[u8]]) -> Vec<u8> {
    let mut content = Vec::new();
    for item in items {
        content.extend_from_slice(item);
    }
    der_tlv(0x31, &content)
}

fn der_oid(encoded_oid: &[u8]) -> Vec<u8> {
    der_tlv(0x06, encoded_oid)
}

fn der_octet_string(data: &[u8]) -> Vec<u8> {
    der_tlv(0x04, data)
}

fn der_utc_time(time_str: &str) -> Vec<u8> {
    der_tlv(0x17, time_str.as_bytes())
}

fn der_integer_small(val: u8) -> Vec<u8> {
    vec![0x02, 0x01, val]
}

fn der_attribute(oid_tlv: &[u8], value_set: &[u8]) -> Vec<u8> {
    let mut content = Vec::new();
    content.extend_from_slice(oid_tlv);
    content.extend_from_slice(value_set);
    der_sequence_raw(&[&content])
}

/// Build a CMS/PKCS#7 `SignedData` with configurable options.
///
/// Supports:
/// - PKCS7 (adbe.pkcs7.detached) and PAdES (ETSI.CAdES.detached) formats
/// - PAdES levels: B-B, B-T, B-LT, B-LTA
/// - Timestamp via TSA URL
/// - CRL/OCSP in CMS signed attributes
pub(crate) fn build_cms_with_options(
    pki: &crate::server::pki::PkiState,
    content_bytes: &[u8],
    options: &CmsSigningOptions,
) -> Result<Vec<u8>, String> {
    let key_pair = InMemorySigningKeyPair::from_pkcs8_der(&pki.user_key_der)
        .map_err(|e| format!("Failed to load signing key: {}", e))?;

    let user_cert = CapturedX509Certificate::from_der(pki.user_cert_der.clone())
        .map_err(|e| format!("Failed to parse user cert: {}", e))?;

    // Parse all CA certificates in the chain
    let mut ca_certs = Vec::new();
    for (i, ca_der) in pki.ca_chain_der.iter().enumerate() {
        let ca_cert = CapturedX509Certificate::from_der(ca_der.clone())
            .map_err(|e| format!("Failed to parse CA cert #{}: {}", i, e))?;
        ca_certs.push(ca_cert);
    }

    // Full certificate chain: user + CA certs
    let mut full_chain = vec![user_cert.clone()];
    full_chain.extend(ca_certs.iter().cloned());

    // ESS-signing-certificate-v2 attribute (always included for both PKCS7 and PAdES)
    let cert_hash = {
        let mut hasher = Sha256::new();
        hasher.update(user_cert.encode_der().map_err(|e| format!("{}", e))?);
        hasher.finalize().to_vec()
    };
    let signing_cert_v2_value = build_signing_certificate_v2_attribute_value(cert_hash);

    // OID: 1.2.840.113549.1.9.16.2.47
    let signing_certificate_v2_oid = Oid(Bytes::copy_from_slice(&[
        42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 47,
    ]));

    let mut signer = SignerBuilder::new(&key_pair, user_cert.clone()).signed_attribute(
        signing_certificate_v2_oid,
        vec![AttributeValue::new(signing_cert_v2_value)],
    );

    // Determine what to include based on format and level
    // (matching the reference library's digitally_sign_document logic)
    let is_pades = options.signature_format == "pades";
    let include_cms_revocation;
    let include_timestamp;

    if is_pades {
        match options.pades_level.as_str() {
            "B-B" => {
                include_cms_revocation = false;
                include_timestamp = false;
            }
            "B-T" => {
                include_cms_revocation = options.include_crl || options.include_ocsp;
                include_timestamp = true;
            }
            "B-LT" | "B-LTA" => {
                // Long-Term: always include CMS revocation + timestamp
                include_cms_revocation = true;
                include_timestamp = true;
            }
            _ => {
                include_cms_revocation = false;
                include_timestamp = false;
            }
        }
    } else {
        // PKCS7: include revocation when user requests CRL or OCSP
        let wants_revocation = options.include_crl || options.include_ocsp;
        include_cms_revocation = wants_revocation;
        include_timestamp = options.timestamp_url.is_some();
    }

    // Add adbe-revocationInfoArchival signed attribute (CRL/OCSP in CMS)
    if include_cms_revocation {
        let crl_flag = if is_pades {
            matches!(options.pades_level.as_str(), "B-LT" | "B-LTA") || options.include_crl
        } else {
            true // PKCS7 LTV: always include both
        };
        let ocsp_flag = if is_pades {
            matches!(options.pades_level.as_str(), "B-LT" | "B-LTA") || options.include_ocsp
        } else {
            true
        };

        log::info!(
            "Fetching revocation data: crl={}, ocsp={} for {} cert(s)",
            crl_flag, ocsp_flag, full_chain.len()
        );

        if let Some((oid, values)) =
            crate::server::ltv::build_adbe_revocation_attribute(&full_chain, crl_flag, ocsp_flag)
        {
            log::info!("Added adbe-revocationInfoArchival signed attribute");
            signer = signer.signed_attribute(oid, values);
        } else {
            log::warn!("No revocation data could be fetched for CMS attribute");
        }
    }

    // Add timestamp via TSA
    if include_timestamp {
        if let Some(tsa_url) = &options.timestamp_url {
            signer = signer
                .time_stamp_url(tsa_url)
                .map_err(|e| format!("Failed to set TSA URL: {}", e))?;
        } else {
            log::warn!(
                "Timestamp requested (level={}) but no TSA URL provided",
                options.pades_level
            );
        }
    }

    let mut builder = SignedDataBuilder::default()
        .content_external(content_bytes.to_vec())
        .content_type(Oid(Bytes::copy_from_slice(
            cryptographic_message_syntax::asn1::rfc5652::OID_ID_DATA.as_ref(),
        )))
        .signer(signer)
        .certificate(user_cert.clone());

    // Add all CA certificates in the chain
    for ca_cert in &ca_certs {
        builder = builder.certificate(ca_cert.clone());
    }

    let signature = builder
        .build_der()
        .map_err(|e| format!("CMS build failed: {}", e))?;

    Ok(signature)
}

/// Build ESS-signing-certificate-v2 attribute value (prevents cert substitution).
fn build_signing_certificate_v2_attribute_value(cert_hash: Vec<u8>) -> Captured {
    let certificate_hash_octet_string = OctetString::new(Bytes::from(cert_hash));
    let ess_cert_id_v2 = bcder::encode::sequence(certificate_hash_octet_string.encode());
    let signing_certificate_v2 = bcder::encode::sequence(ess_cert_id_v2);
    let attr_value = bcder::encode::sequence(signing_certificate_v2);
    attr_value.to_captured(Der)
}

/// Configure signing routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route(
        "/csc/v2/signatures/signHash",
        web::post().to(sign_hash_handler),
    )
    .route(
        "/csc/v2/signatures/signDoc",
        web::post().to(sign_doc_handler),
    )
    .route(
        "/csc/v2/signatures/signDoc/form",
        web::post().to(sign_doc_form_handler),
    );
}

/// `POST /csc/v2/signatures/signDoc/form`
///
/// Multipart form-data alternative for signDoc.
///
/// Form fields:
/// - `file` (required): Raw byte-range content file upload
/// - `credentialID`: Signing credential [default: "credential-001"]
/// - `signatureFormat`: "pkcs7" or "pades" [default: "pades"]
/// - `padesLevel`: PAdES level [default: "B-B"]
/// - `timestampUrl`: TSA URL (optional)
/// - `includeCrl`: "true"/"false" [default: false]
/// - `includeOcsp`: "true"/"false" [default: false]
///
/// Returns JSON with base64-encoded CMS signature (same as JSON endpoint),
/// or raw CMS DER bytes if `responseFormat=binary` is set.
///
/// Example with curl:
/// ```sh
/// curl -X POST http://localhost:8080/csc/v2/signatures/signDoc/form \
///   -H "Authorization: Bearer <token>" \
///   -F "file=@byte_range_content.bin" \
///   -F "signatureFormat=pades" \
///   -F "padesLevel=B-B"
/// ```
pub async fn sign_doc_form_handler(
    req: HttpRequest,
    payload: Multipart,
    state: web::Data<AppState>,
) -> HttpResponse {
    use crate::server::multipart::extract_multipart_fields;

    let claims = match validate_bearer_token(&req) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let fields = match extract_multipart_fields(payload).await {
        Ok(f) => f,
        Err(e) => {
            return HttpResponse::BadRequest().json(CscErrorResponse {
                error: "invalid_request".into(),
                error_description: format!("Failed to parse form data: {}", e),
            });
        }
    };

    // Required: content file
    let content_bytes = match fields.get("file") {
        Some(f) if !f.bytes.is_empty() => f.bytes.clone(),
        _ => {
            return HttpResponse::BadRequest().json(CscErrorResponse {
                error: "invalid_request".into(),
                error_description: "Missing required field 'file' (byte-range content)".into(),
            });
        }
    };

    let credential_id = fields
        .get("credentialID")
        .and_then(|f| f.as_text())
        .unwrap_or("credential-001")
        .to_string();

    if !has_credential_access(&claims.sub, &credential_id) {
        return forbidden_response(&credential_id);
    }

    let sig_format = fields
        .get("signatureFormat")
        .and_then(|f| f.as_text())
        .unwrap_or("pades")
        .to_lowercase();

    let pades_level = fields
        .get("padesLevel")
        .and_then(|f| f.as_text())
        .unwrap_or("B-B")
        .to_uppercase()
        .replace("BB", "B-B").replace("BT", "B-T")
        .replace("BLT", "B-LT").replace("BLTA", "B-LTA");

    let timestamp_url = fields
        .get("timestampUrl")
        .and_then(|f| f.as_text())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let include_crl = fields.get("includeCrl").map(|f| f.as_bool()).unwrap_or(false);
    let include_ocsp = fields.get("includeOcsp").map(|f| f.as_bool()).unwrap_or(false);

    let response_format = fields
        .get("responseFormat")
        .and_then(|f| f.as_text())
        .unwrap_or("json")
        .to_lowercase();

    log::info!(
        "Form-data signDoc: {} bytes, format={}, level={}",
        content_bytes.len(), sig_format, pades_level,
    );

    let cms_options = CmsSigningOptions {
        signature_format: sig_format.clone(),
        pades_level: pades_level.clone(),
        timestamp_url,
        include_crl,
        include_ocsp,
    };

    let pki_clone = state.pki.clone();
    let content = content_bytes.clone();
    let cms_opts = cms_options.clone();
    let cms_result = tokio::task::spawn_blocking(move || {
        build_cms_with_options(&pki_clone, &content, &cms_opts)
    }).await;

    match cms_result {
        Ok(Ok(cms_der)) => {
            log::info!(
                "User '{}' form-signed doc with '{}' — format={}, level={}, CMS {} bytes",
                claims.sub, credential_id, sig_format, pades_level, cms_der.len()
            );

            if response_format == "binary" {
                HttpResponse::Ok()
                    .content_type("application/pkcs7-signature")
                    .insert_header(("Content-Disposition", "attachment; filename=\"signature.p7s\""))
                    .body(cms_der)
            } else {
                let b64 = base64::engine::general_purpose::STANDARD;
                let pades_level_resp = if sig_format == "pades" { Some(pades_level) } else { None };
                HttpResponse::Ok().json(SignDocResponse {
                    signature: b64.encode(&cms_der),
                    signature_format: sig_format,
                    pades_level: pades_level_resp,
                })
            }
        }
        Ok(Err(e)) => {
            log::error!("CMS build failed: {}", e);
            HttpResponse::InternalServerError().json(CscErrorResponse {
                error: "server_error".to_string(),
                error_description: format!("Signing failed: {}", e),
            })
        }
        Err(e) => {
            log::error!("CMS signing task panicked: {}", e);
            HttpResponse::InternalServerError().json(CscErrorResponse {
                error: "server_error".to_string(),
                error_description: "Internal signing error".to_string(),
            })
        }
    }
}

