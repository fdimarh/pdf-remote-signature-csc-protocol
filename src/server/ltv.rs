//! LTV (Long-Term Validation) support for CMS/PDF signing.
//!
//! Implements:
//! - CRL/OCSP URL extraction from X.509 certificates
//! - CRL/OCSP data fetching
//! - `adbe-revocationInfoArchival` signed attribute construction
//! - DSS (Document Security Store) dictionary appending
//! - RFC 3161 timestamp token fetching
//! - Document-level timestamp appending (PAdES B-LTA)
//!
//! Based on the approach in the `pdf_signing` reference library.

use bcder::encode::Values;
use bcder::Mode::Der;
use bcder::{encode::PrimitiveContent, Captured, Integer, Mode, OctetString, Oid, Tag};
use cryptographic_message_syntax::Bytes;
use lopdf::Object::Reference;
use lopdf::{Dictionary, IncrementalDocument, Object, Stream};
use reqwest::blocking::Client;
use sha2::{Digest, Sha256};
use std::io::Write;
use x509_certificate::rfc5652::AttributeValue;
use x509_certificate::CapturedX509Certificate;
use x509_parser::extensions::DistributionPointName::FullName;
use x509_parser::extensions::ParsedExtension::AuthorityInfoAccess;
use x509_parser::num_bigint::{BigInt, Sign};
use x509_parser::prelude::ParsedExtension::CRLDistributionPoints;
use x509_parser::prelude::*;

// ─────────────────────── URL Extraction ─────────────────────

/// Extract OCSP and CRL URLs from a certificate's extensions.
pub fn get_ocsp_crl_url(
    captured_cert: &CapturedX509Certificate,
) -> (Option<String>, Option<String>) {
    let binding = match captured_cert.encode_der() {
        Ok(b) => b,
        Err(_) => return (None, None),
    };
    let x509_certificate = X509Certificate::from_der(&binding);
    let cert = match x509_certificate {
        Ok((_, c)) => c,
        Err(_) => return (None, None),
    };
    let mut crl_url = None;
    let mut ocsp_url = None;
    for extension in cert.extensions() {
        let parsed = extension.parsed_extension();
        if let AuthorityInfoAccess(aia) = parsed {
            for access_desc in &aia.accessdescs {
                // OID 1.3.6.1.5.5.7.48.1 = OCSP
                if "1.3.6.1.5.5.7.48.1".eq(&access_desc.access_method.to_string()) {
                    if let GeneralName::URI(ocsp) = &access_desc.access_location {
                        ocsp_url = Some(ocsp.to_string());
                    }
                }
            }
        } else if let CRLDistributionPoints(crl_dp) = parsed {
            for dist_point in &crl_dp.points {
                if let Some(point) = &dist_point.distribution_point {
                    if let FullName(names_list) = point {
                        if !names_list.is_empty() {
                            if let GeneralName::URI(crl) = &names_list[0] {
                                crl_url = Some(crl.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    (ocsp_url, crl_url)
}

// ─────────────────────── Data Fetching ──────────────────────

/// Fetch an OCSP response for the given certificate.
pub fn fetch_ocsp_response(
    captured_cert: &CapturedX509Certificate,
    ocsp_url: &str,
) -> Result<Option<Vec<u8>>, String> {
    let binding = captured_cert
        .encode_der()
        .map_err(|e| format!("encode_der: {}", e))?;
    let cert = X509Certificate::from_der(&binding)
        .map_err(|e| format!("parse cert: {}", e))?
        .1;

    let ocsp_req = create_ocsp_request(&cert)?;

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client: {}", e))?;

    let response = client
        .post(ocsp_url)
        .header("Content-Type", "application/ocsp-request")
        .body(ocsp_req)
        .send()
        .map_err(|e| format!("OCSP request to {}: {}", ocsp_url, e))?;

    if response.status().is_success() {
        let ocsp_resp = response
            .bytes()
            .map_err(|e| format!("OCSP read: {}", e))?;
        Ok(Some(ocsp_resp.to_vec()))
    } else {
        log::warn!("OCSP request to {} failed: {}", ocsp_url, response.status());
        Ok(None)
    }
}

/// Build a minimal OCSP request DER for the given certificate.
fn create_ocsp_request(cert: &X509Certificate) -> Result<Vec<u8>, String> {
    use rasn::ber::encode;
    use rasn::types::ObjectIdentifier;
    use std::borrow::Cow;

    let sha1_oid = ObjectIdentifier::new_unchecked(Cow::from(vec![1, 3, 14, 3, 2, 26]));
    let sha1 = rasn_pkix::AlgorithmIdentifier {
        algorithm: sha1_oid,
        parameters: None,
    };

    let request = rasn_ocsp::Request {
        req_cert: rasn_ocsp::CertId {
            hash_algorithm: sha1,
            issuer_name_hash: Default::default(),
            issuer_key_hash: Default::default(),
            serial_number: BigInt::from_bytes_le(Sign::Plus, cert.raw_serial()).into(),
        },
        single_request_extensions: None,
    };

    let tbs_request = rasn_ocsp::TbsRequest {
        version: Default::default(),
        requestor_name: None,
        request_list: vec![request],
        request_extensions: None,
    };

    let ocsp_req = rasn_ocsp::OcspRequest {
        tbs_request,
        optional_signature: None,
    };

    encode(&ocsp_req).map_err(|e| format!("OCSP encode: {}", e))
}

/// Fetch a CRL from the given URL.
pub fn fetch_crl_response(crl_url: &str) -> Result<Option<Vec<u8>>, String> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client: {}", e))?;

    let response = client
        .get(crl_url)
        .send()
        .map_err(|e| format!("CRL request to {}: {}", crl_url, e))?;

    if response.status().is_success() {
        let crl_resp = response
            .bytes()
            .map_err(|e| format!("CRL read: {}", e))?;
        Ok(Some(crl_resp.to_vec()))
    } else {
        log::warn!("CRL request to {} failed: {}", crl_url, response.status());
        Ok(None)
    }
}

// ─────────────────────── Revocation Data ────────────────────

/// Fetch CRL and OCSP revocation data for the entire certificate chain.
pub fn fetch_revocation_data(
    user_certificate_chain: &[CapturedX509Certificate],
    include_crl: bool,
    include_ocsp: bool,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut crl_data = Vec::new();
    let mut ocsp_data = Vec::new();

    for cert in user_certificate_chain {
        let (ocsp_url, crl_url) = get_ocsp_crl_url(cert);

        if include_ocsp {
            if let Some(ocsp) = ocsp_url {
                match fetch_ocsp_response(cert, &ocsp) {
                    Ok(Some(data)) => {
                        log::info!("Fetched OCSP response: {} bytes from {}", data.len(), ocsp);
                        ocsp_data.push(data);
                    }
                    Ok(None) => log::warn!("No OCSP response from {}", ocsp),
                    Err(e) => log::warn!("OCSP fetch error: {}", e),
                }
            }
        }
        if include_crl {
            if let Some(crl) = crl_url {
                match fetch_crl_response(&crl) {
                    Ok(Some(data)) => {
                        log::info!("Fetched CRL: {} bytes from {}", data.len(), crl);
                        crl_data.push(data);
                    }
                    Ok(None) => log::warn!("No CRL from {}", crl),
                    Err(e) => log::warn!("CRL fetch error: {}", e),
                }
            }
        }
    }

    (crl_data, ocsp_data)
}

// ─────────────────────── CMS Attributes ─────────────────────

/// Helper to emit pre-encoded DER bytes as-is (no extra wrapping).
struct RawDerBytes(Vec<u8>);

impl Values for RawDerBytes {
    fn encoded_len(&self, _: Mode) -> usize {
        self.0.len()
    }
    fn write_encoded<W: Write>(&self, _: Mode, target: &mut W) -> Result<(), std::io::Error> {
        target.write_all(&self.0)
    }
}

struct CrlResponse {
    bytes: Bytes,
}

impl Values for CrlResponse {
    fn encoded_len(&self, _: Mode) -> usize {
        self.bytes.len()
    }
    fn write_encoded<W: Write>(&self, _: Mode, target: &mut W) -> Result<(), std::io::Error> {
        target.write_all(&self.bytes)
    }
}

/// Encode CRL and OCSP data into the `RevocationInfoArchival` ASN.1 structure.
fn encode_revocation_info_archival(
    crls_bytes: Vec<Vec<u8>>,
    ocsps_bytes: Vec<Vec<u8>>,
) -> Option<Captured> {
    let mut revocation_vector = Vec::new();

    if !crls_bytes.is_empty() {
        let crl_responses: Vec<CrlResponse> = crls_bytes
            .into_iter()
            .map(|crl_bytes| CrlResponse {
                bytes: Bytes::copy_from_slice(&crl_bytes),
            })
            .collect();
        let crl_seq = bcder::encode::sequence(crl_responses);
        let crl_tagged = bcder::encode::sequence_as(Tag::CTX_0, crl_seq);
        revocation_vector.push(crl_tagged.to_captured(Der));
    }

    if !ocsps_bytes.is_empty() {
        let mut ocsp_responses = Vec::new();
        for ocsp_bytes in ocsps_bytes {
            let ocsp_encoded = OctetString::new(Bytes::from(ocsp_bytes));
            // 1.3.6.1.5.5.7.48.1.1 - id_pkix_ocsp_basic
            let pkix_ocsp_basic_oid = Oid(Bytes::copy_from_slice(&[43, 6, 1, 5, 5, 7, 48, 1, 1]));
            let basic_ocsp_response =
                bcder::encode::sequence((pkix_ocsp_basic_oid.encode(), ocsp_encoded.encode()));
            let tagged_basic = bcder::encode::sequence_as(Tag::CTX_0, basic_ocsp_response);
            let tagged_seq = Integer::from(0u8)
                .encode_as(Tag::ENUMERATED)
                .to_captured(Der);
            let ocsp_response = bcder::encode::sequence((tagged_seq, tagged_basic));
            ocsp_responses.push(ocsp_response);
        }
        let ocsp_seq = bcder::encode::sequence(ocsp_responses);
        let ocsp_tagged = bcder::encode::sequence_as(Tag::CTX_1, ocsp_seq);
        revocation_vector.push(ocsp_tagged.to_captured(Der));
    }

    if !revocation_vector.is_empty() {
        Some(bcder::encode::sequence(revocation_vector).to_captured(Der))
    } else {
        None
    }
}

/// Build the `adbe-revocationInfoArchival` signed attribute for CMS.
///
/// This fetches CRL/OCSP data for the certificate chain and encodes it
/// as a CMS signed attribute that Adobe/Foxit use for LTV validation.
///
/// OID: 1.2.840.113583.1.1.8
pub fn build_adbe_revocation_attribute(
    user_certificate_chain: &[CapturedX509Certificate],
    include_crl: bool,
    include_ocsp: bool,
) -> Option<(Oid, Vec<AttributeValue>)> {
    let (crl_data, ocsp_data) =
        fetch_revocation_data(user_certificate_chain, include_crl, include_ocsp);

    let encoded = encode_revocation_info_archival(crl_data, ocsp_data)?;

    // OID 1.2.840.113583.1.1.8 = adbe-revocationInfoArchival
    let adbe_revocation_oid = Oid(Bytes::copy_from_slice(&[
        42, 134, 72, 134, 247, 47, 1, 1, 8,
    ]));

    Some((adbe_revocation_oid, vec![AttributeValue::new(encoded)]))
}

// ─────────────────────── DSS Dictionary ─────────────────────

/// Append a DSS (Document Security Store) dictionary to the signed PDF.
///
/// The DSS contains CRL responses, OCSP responses, and certificates
/// that allow offline LTV validation.  It's added as an incremental
/// update after the CMS signature has been embedded.
pub fn append_dss_dictionary(
    pdf_bytes: Vec<u8>,
    user_certificate_chain: Vec<CapturedX509Certificate>,
) -> Result<Vec<u8>, String> {
    let mut doc = IncrementalDocument::load_from(pdf_bytes.as_slice())
        .map_err(|e| format!("Failed to load PDF for DSS: {}", e))?;
    doc.new_document.version = "1.5".parse().unwrap();

    let (crl_data, ocsp_data) = fetch_revocation_data(&user_certificate_chain, true, true);

    log::info!(
        "DSS: fetched {} CRL(s), {} OCSP(s) for {} cert(s)",
        crl_data.len(),
        ocsp_data.len(),
        user_certificate_chain.len()
    );

    let crl_refs: Vec<Object> = crl_data
        .into_iter()
        .map(|crl| {
            let stream = Stream::new(Dictionary::new(), crl);
            Reference(doc.new_document.add_object(stream))
        })
        .collect();

    let ocsp_refs: Vec<Object> = ocsp_data
        .into_iter()
        .map(|ocsp| {
            let stream = Stream::new(Dictionary::new(), ocsp);
            Reference(doc.new_document.add_object(stream))
        })
        .collect();

    let cert_refs: Vec<Object> = user_certificate_chain
        .iter()
        .filter_map(|cert| {
            cert.encode_der().ok().map(|der| {
                let stream = Stream::new(Dictionary::new(), der);
                Reference(doc.new_document.add_object(stream))
            })
        })
        .collect();

    let dss_dict = Dictionary::from_iter(vec![
        ("CRLs", crl_refs.into()),
        ("OCSPs", ocsp_refs.into()),
        ("Certs", cert_refs.into()),
    ]);

    let dss_ref = doc.new_document.add_object(dss_dict);

    // Get root catalog and add DSS reference
    let catalog_id = doc
        .get_prev_documents()
        .trailer
        .get(b"Root")
        .map_err(|e| format!("No Root: {}", e))?
        .as_reference()
        .map_err(|e| format!("Root not ref: {}", e))?;

    doc.opt_clone_object_to_new_document(catalog_id)
        .map_err(|e| format!("Clone root: {}", e))?;

    let catalog = doc
        .new_document
        .get_object_mut(catalog_id)
        .map_err(|e| format!("Get root: {}", e))?
        .as_dict_mut()
        .map_err(|e| format!("Root not dict: {}", e))?;

    catalog.set("DSS", dss_ref);

    let mut buffer = Vec::new();
    doc.save_to(&mut buffer)
        .map_err(|e| format!("Save with DSS: {}", e))?;

    log::info!("Appended DSS dictionary: {} → {} bytes", pdf_bytes.len(), buffer.len());
    Ok(buffer)
}

// ─────────────────────── Timestamp Token ────────────────────

/// Request an RFC 3161 timestamp token from a TSA server.
///
/// Sends a `TimeStampReq` with the given SHA-256 `message_digest`
/// and returns the `TimeStampToken` (CMS ContentInfo DER).
pub fn fetch_timestamp_token(
    tsa_url: &str,
    message_digest: &[u8],
) -> Result<Vec<u8>, String> {
    // Build TimeStampReq DER manually

    // SHA-256 OID DER
    let sha256_oid_der: Vec<u8> = vec![
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    ];

    // AlgorithmIdentifier = SEQUENCE { OID, NULL }
    let mut alg_content = Vec::new();
    alg_content.extend_from_slice(&sha256_oid_der);
    alg_content.push(0x05);
    alg_content.push(0x00);
    let mut alg_id = vec![0x30]; // SEQUENCE
    der_push_length(&mut alg_id, alg_content.len());
    alg_id.extend_from_slice(&alg_content);

    // hashedMessage = OCTET STRING
    let mut hashed_msg = vec![0x04]; // OCTET STRING
    der_push_length(&mut hashed_msg, message_digest.len());
    hashed_msg.extend_from_slice(message_digest);

    // MessageImprint = SEQUENCE
    let mut msg_imprint_content = Vec::new();
    msg_imprint_content.extend_from_slice(&alg_id);
    msg_imprint_content.extend_from_slice(&hashed_msg);
    let mut msg_imprint = vec![0x30]; // SEQUENCE
    der_push_length(&mut msg_imprint, msg_imprint_content.len());
    msg_imprint.extend_from_slice(&msg_imprint_content);

    // version INTEGER 1
    let version_der: Vec<u8> = vec![0x02, 0x01, 0x01];
    // certReq BOOLEAN TRUE
    let cert_req_der: Vec<u8> = vec![0x01, 0x01, 0xff];

    // TimeStampReq = SEQUENCE
    let mut ts_req_content = Vec::new();
    ts_req_content.extend_from_slice(&version_der);
    ts_req_content.extend_from_slice(&msg_imprint);
    ts_req_content.extend_from_slice(&cert_req_der);

    let mut ts_req = vec![0x30]; // SEQUENCE
    der_push_length(&mut ts_req, ts_req_content.len());
    ts_req.extend_from_slice(&ts_req_content);

    // Send to TSA
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("HTTP client: {}", e))?;

    let response = client
        .post(tsa_url)
        .header("Content-Type", "application/timestamp-query")
        .body(ts_req)
        .send()
        .map_err(|e| format!("TSA request to {}: {}", tsa_url, e))?;

    if !response.status().is_success() {
        return Err(format!("TSA returned HTTP {}", response.status()));
    }

    let ts_resp = response
        .bytes()
        .map_err(|e| format!("Read TSA response: {}", e))?;

    // Parse TimeStampResp → extract TimeStampToken
    let data = ts_resp.to_vec();
    if data.len() < 5 || data[0] != 0x30 {
        return Err("Invalid TSA response: not a SEQUENCE".into());
    }

    let (outer_content_start, _) = der_read_length(&data, 1)
        .ok_or_else(|| "Invalid TSA response: bad length".to_string())?;

    // PKIStatusInfo SEQUENCE
    let pos = outer_content_start;
    if pos >= data.len() || data[pos] != 0x30 {
        return Err("Invalid TSA response: missing PKIStatusInfo".into());
    }
    let (status_content_start, status_len) = der_read_length(&data, pos + 1)
        .ok_or_else(|| "Invalid TSA: bad PKIStatusInfo length".to_string())?;

    // Check status
    if status_content_start < data.len() && data[status_content_start] == 0x02 {
        let (val_start, val_len) = der_read_length(&data, status_content_start + 1)
            .ok_or_else(|| "Invalid TSA status".to_string())?;
        if val_len == 1 && val_start < data.len() && data[val_start] > 2 {
            return Err(format!("TSA returned rejection status: {}", data[val_start]));
        }
    }

    let token_start = status_content_start + status_len;
    if token_start >= data.len() {
        return Err("TSA response contains no TimeStampToken".into());
    }

    Ok(data[token_start..].to_vec())
}

// ─────────────────── Document Timestamp (B-LTA) ─────────────

/// Append a document-level timestamp for PAdES B-LTA.
///
/// Creates an incremental update with a `/Type /DocTimeStamp` field
/// whose `/SubFilter` is `ETSI.RFC3161`. The timestamp covers the
/// entire document including the DSS dictionary.
pub fn append_document_timestamp(
    pdf_bytes: Vec<u8>,
    tsa_url: &str,
    sig_size: usize,
) -> Result<Vec<u8>, String> {
    use lopdf::StringFormat;

    let mut doc = IncrementalDocument::load_from(pdf_bytes.as_slice())
        .map_err(|e| format!("Load for doc-ts: {}", e))?;
    doc.new_document.version = "2.0".parse().unwrap();

    let placeholder_size = sig_size;

    // Find page 1 reference
    let page_ref = find_page_object_id(&doc)
        .map_err(|e| format!("Find page: {}", e))?;

    // Signature value dictionary
    let v_dict = Dictionary::from_iter(vec![
        ("Type", Object::Name(b"Sig".to_vec())),
        ("Filter", Object::Name(b"Adobe.PPKLite".to_vec())),
        ("SubFilter", Object::Name(b"ETSI.RFC3161".to_vec())),
        (
            "ByteRange",
            Object::Array(vec![
                Object::Integer(0),
                Object::Integer(10000),
                Object::Integer(20000),
                Object::Integer(10000),
            ]),
        ),
        (
            "Contents",
            Object::String(
                vec![0u8; placeholder_size / 2],
                StringFormat::Hexadecimal,
            ),
        ),
    ]);
    let v_ref = doc.new_document.add_object(Object::Dictionary(v_dict));

    // Field + widget annotation dictionary
    let ts_field_name = format!("DocTimestamp{}", rand::random::<u32>());
    let field_dict = Dictionary::from_iter(vec![
        ("FT", Object::Name(b"Sig".to_vec())),
        (
            "T",
            Object::String(ts_field_name.into_bytes(), StringFormat::Literal),
        ),
        ("V", Object::Reference(v_ref)),
        ("Subtype", Object::Name(b"Widget".to_vec())),
        (
            "Rect",
            Object::Array(vec![0i32.into(), 0i32.into(), 0i32.into(), 0i32.into()]),
        ),
        ("P", Object::Reference(page_ref)),
        ("F", Object::Integer(6)),
    ]);
    let ts_field_ref = doc
        .new_document
        .add_object(Object::Dictionary(field_dict));

    // Add to page Annots
    doc.opt_clone_object_to_new_document(page_ref)
        .map_err(|e| format!("Clone page: {}", e))?;
    let page_mut = doc
        .new_document
        .get_object_mut(page_ref)
        .map_err(|e| format!("Get page: {}", e))?
        .as_dict_mut()
        .map_err(|e| format!("Page dict: {}", e))?;
    let new_annots = if page_mut.has(b"Annots") {
        let mut arr = page_mut
            .get(b"Annots")
            .map_err(|e| format!("{}", e))?
            .as_array()
            .map_err(|e| format!("{}", e))?
            .clone();
        arr.push(Object::Reference(ts_field_ref));
        Object::Array(arr)
    } else {
        Object::Array(vec![Object::Reference(ts_field_ref)])
    };
    page_mut.set("Annots", new_annots);

    // Add to AcroForm.Fields
    let root_id = doc
        .get_prev_documents()
        .trailer
        .get(b"Root")
        .map_err(|e| format!("{}", e))?
        .as_reference()
        .map_err(|e| format!("{}", e))?;
    doc.opt_clone_object_to_new_document(root_id)
        .map_err(|e| format!("{}", e))?;
    let root_dict = doc
        .new_document
        .get_object_mut(root_id)
        .map_err(|e| format!("{}", e))?
        .as_dict_mut()
        .map_err(|e| format!("{}", e))?;

    let acro_ref = if root_dict.has(b"AcroForm") {
        root_dict
            .get(b"AcroForm")
            .map_err(|e| format!("{}", e))?
            .as_reference()
            .map_err(|e| format!("{}", e))?
    } else {
        let acro = Dictionary::from_iter(vec![
            ("Fields", Object::Array(vec![])),
            ("SigFlags", Object::Integer(3)),
        ]);
        let r = doc
            .new_document
            .add_object(Object::Dictionary(acro));
        let rd = doc.new_document.get_object_mut(root_id).unwrap().as_dict_mut().unwrap();
        rd.set("AcroForm", Object::Reference(r));
        r
    };

    doc.opt_clone_object_to_new_document(acro_ref)
        .map_err(|e| format!("{}", e))?;
    let acro_mut = doc
        .new_document
        .get_object_mut(acro_ref)
        .map_err(|e| format!("{}", e))?
        .as_dict_mut()
        .map_err(|e| format!("{}", e))?;
    if acro_mut.has(b"Fields") {
        let mut fields = acro_mut
            .get(b"Fields")
            .map_err(|e| format!("{}", e))?
            .as_array()
            .map_err(|e| format!("{}", e))?
            .clone();
        fields.push(Object::Reference(ts_field_ref));
        acro_mut.set("Fields", Object::Array(fields));
    } else {
        acro_mut.set("Fields", Object::Array(vec![Object::Reference(ts_field_ref)]));
    }
    acro_mut.set("SigFlags", Object::Integer(3));

    // Save incremental update with placeholder
    let mut pdf_file_data = Vec::new();
    doc.save_to(&mut pdf_file_data)
        .map_err(|e| format!("Save doc-ts: {}", e))?;

    // Compute ByteRange and fill in timestamp token
    let (byte_range, mut pdf_file_data) = set_next_byte_range(pdf_file_data, placeholder_size);

    let first_part = &pdf_file_data[byte_range.0..byte_range.1];
    let second_part = &pdf_file_data[byte_range.2..byte_range.3];

    let mut hasher = Sha256::new();
    hasher.update(first_part);
    hasher.update(second_part);
    let file_hash = hasher.finalize().to_vec();

    let ts_token = fetch_timestamp_token(tsa_url, &file_hash)?;

    log::info!(
        "Document timestamp token: {} bytes from {}",
        ts_token.len(),
        tsa_url
    );

    // Write timestamp token into Contents
    set_content(&mut pdf_file_data, &ts_token, placeholder_size);

    Ok(pdf_file_data)
}

// ─────────────────────── Helpers ────────────────────────────

/// DER length encoding helper.
fn der_push_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len <= 0xff {
        buf.push(0x81);
        buf.push(len as u8);
    } else if len <= 0xffff {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    } else {
        buf.push(0x83);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

/// DER length reading helper. Returns (content_start, length).
fn der_read_length(data: &[u8], offset: usize) -> Option<(usize, usize)> {
    if offset >= data.len() {
        return None;
    }
    let first = data[offset] as usize;
    if first < 0x80 {
        Some((offset + 1, first))
    } else if first == 0x81 {
        if offset + 1 >= data.len() { return None; }
        Some((offset + 2, data[offset + 1] as usize))
    } else if first == 0x82 {
        if offset + 2 >= data.len() { return None; }
        let len = ((data[offset + 1] as usize) << 8) | (data[offset + 2] as usize);
        Some((offset + 3, len))
    } else if first == 0x83 {
        if offset + 3 >= data.len() { return None; }
        let len = ((data[offset + 1] as usize) << 16)
            | ((data[offset + 2] as usize) << 8)
            | (data[offset + 3] as usize);
        Some((offset + 4, len))
    } else {
        None
    }
}

/// Find page 1 object ID from an IncrementalDocument.
fn find_page_object_id(doc: &IncrementalDocument) -> Result<lopdf::ObjectId, String> {
    let prev = doc.get_prev_documents();
    let root_ref = prev
        .trailer
        .get(b"Root")
        .map_err(|e| format!("{}", e))?
        .as_reference()
        .map_err(|e| format!("{}", e))?;
    let root = prev
        .get_object(root_ref)
        .map_err(|e| format!("{}", e))?
        .as_dict()
        .map_err(|e| format!("{}", e))?;
    let pages_ref = root
        .get(b"Pages")
        .map_err(|e| format!("{}", e))?
        .as_reference()
        .map_err(|e| format!("{}", e))?;
    let pages = prev
        .get_object(pages_ref)
        .map_err(|e| format!("{}", e))?
        .as_dict()
        .map_err(|e| format!("{}", e))?;
    let kids = pages
        .get(b"Kids")
        .map_err(|e| format!("{}", e))?
        .as_array()
        .map_err(|e| format!("{}", e))?;
    if kids.is_empty() {
        return Err("No pages found".into());
    }
    kids[0]
        .as_reference()
        .map_err(|e| format!("Page ref: {}", e))
}

/// ByteRange tuple: (start1, end1, start2, end2) — absolute byte offsets
struct ByteRangeOffsets(usize, usize, usize, usize);

/// Find the next default ByteRange pattern and compute real offsets.
fn set_next_byte_range(mut pdf_data: Vec<u8>, sig_size: usize) -> (ByteRangeOffsets, Vec<u8>) {
    let pattern_prefix = b"/ByteRange[0 10000 20000 10000]/Contents<";
    let pattern_content = vec![48u8; sig_size]; // '0' characters
    let mut pattern = pattern_prefix.to_vec();
    pattern.extend_from_slice(&pattern_content[..51.min(pattern_content.len())]);

    let found_at = find_binary_pattern(&pdf_data, &pattern)
        .expect("ByteRange pattern not found in PDF");

    let fixed_byte_range_width = 25;
    let pattern_prefix_len = b"/ByteRange[]/Contents<".len() + fixed_byte_range_width;
    let content_len = pattern_content.len() + b"0 10000 20000 10000".len() - fixed_byte_range_width;
    let content_offset = found_at + pattern_prefix_len - 1;

    let br = ByteRangeOffsets(
        0,
        content_offset,
        content_offset + content_len + 2,
        pdf_data.len(),
    );

    // Format byte range string
    let br_str = format!(
        "{} {} {} {}",
        br.0,
        br.1,
        br.2,
        br.3 - br.2
    );
    let padded_br = format!("{:width$}", br_str, width = fixed_byte_range_width);

    let mut new_br_string = format!(
        "/ByteRange[{}]/Contents<0000000000000000000000",
        padded_br
    );

    // Ensure even length parity with original
    if pattern_prefix.len() % 2 != new_br_string.len() % 2 {
        new_br_string = format!(
            "/ByteRange[{} ]/Contents<0000000000000000000000",
            padded_br
        );
    }

    let new_br_bytes = new_br_string.as_bytes().to_vec();
    pdf_data.splice(found_at..(found_at + new_br_bytes.len()), new_br_bytes);

    (br, pdf_data)
}

/// Write CMS/timestamp content into the /Contents hex placeholder.
fn set_content(pdf_data: &mut Vec<u8>, content: &[u8], sig_size: usize) {
    let pattern_prefix = b"/Contents<";
    let pattern_content = vec![48u8; sig_size];
    let mut pattern = pattern_prefix.to_vec();
    pattern.extend_from_slice(&pattern_content[..51.min(pattern_content.len())]);

    let found_at = find_binary_pattern(pdf_data, &pattern)
        .expect("Contents pattern not found");

    let hex_str: String = content.iter().map(|b| format!("{:02x}", b)).collect();
    let new_contents = format!("/Contents<{}", hex_str);
    let new_bytes = new_contents.as_bytes().to_vec();

    pdf_data.splice(found_at..(found_at + new_bytes.len()), new_bytes);
}

/// Find a binary pattern in data. Returns offset of first match.
fn find_binary_pattern(bytes: &[u8], pattern: &[u8]) -> Option<usize> {
    if bytes.is_empty() || pattern.is_empty() {
        return None;
    }
    let _first = pattern[0];
    let mut pi = 0;
    let mut start = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if b == pattern[pi] {
            if pi == 0 {
                start = i;
            }
            pi += 1;
            if pi >= pattern.len() {
                return Some(start);
            }
        } else {
            pi = 0;
        }
    }
    None
}

