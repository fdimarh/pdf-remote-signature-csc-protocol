//! Comprehensive signing test with all variants.
//!
//! Uses the Nowina DSS good-user-crl-ocsp certificate to test:
//! 1. PAdES B-B (basic)
//! 2. PAdES B-T (timestamp)
//! 3. PKCS7 (no timestamp)
//! 4. PKCS7 + timestamp
//!
//! Then validates each signed PDF and prints results.

use pdf_signing::signature_options::{PadesLevel, SignatureFormat, SignatureOptions};
use pdf_signing::signature_validator::SignatureValidator;
use pdf_signing::{PDFSigningDocument, UserSignatureInfo};
use std::fs;
use std::io::Write;
use x509_certificate::{CapturedX509Certificate, InMemorySigningKeyPair};
use cryptographic_message_syntax::SignerBuilder;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .init();

    let cert_pem = fs::read_to_string("test-files/certs-test/chain.pem")
        .expect("Failed to read chain.pem");
    let key_pem = fs::read_to_string("test-files/certs-test/key-pkcs8.pem")
        .expect("Failed to read key-pkcs8.pem");
    let pdf_data = fs::read("test-files/sample.pdf")
        .expect("Failed to read sample.pdf");

    let certs = CapturedX509Certificate::from_pem_multiple(&cert_pem)
        .expect("Failed to parse certificates from chain.pem");
    println!("Loaded {} certificate(s) from chain.pem", certs.len());
    for (i, c) in certs.iter().enumerate() {
        let subj = c.subject_name().user_friendly_str().unwrap_or_default();
        let iss = c.issuer_name().user_friendly_str().unwrap_or_default();
        println!("  [{}] Subject: {} | Issuer: {}", i, subj, iss);
    }

    let private_key = InMemorySigningKeyPair::from_pkcs8_pem(&key_pem)
        .expect("Failed to parse private key");

    // ── Define test variants ──
    struct TestVariant {
        name: &'static str,
        output: &'static str,
        format: SignatureFormat,
        pades_level: PadesLevel,
        timestamp_url: Option<&'static str>,
        include_crl: bool,
        include_ocsp: bool,
        include_dss: bool,
    }

    let variants = vec![
        TestVariant {
            name: "PAdES B-B (basic, no timestamp)",
            output: "test-files/result-pades-bb.pdf",
            format: SignatureFormat::PADES,
            pades_level: PadesLevel::B_B,
            timestamp_url: None,
            include_crl: false,
            include_ocsp: false,
            include_dss: false,
        },
        TestVariant {
            name: "PAdES B-T (with DigiCert timestamp)",
            output: "test-files/result-pades-bt.pdf",
            format: SignatureFormat::PADES,
            pades_level: PadesLevel::B_T,
            timestamp_url: Some("http://timestamp.digicert.com"),
            include_crl: false,
            include_ocsp: false,
            include_dss: false,
        },
        TestVariant {
            name: "PAdES B-LT (long-term with DSS)",
            output: "test-files/result-pades-blt.pdf",
            format: SignatureFormat::PADES,
            pades_level: PadesLevel::B_LT,
            timestamp_url: Some("http://timestamp.digicert.com"),
            include_crl: true,
            include_ocsp: true,
            include_dss: true,
        },
        TestVariant {
            name: "PAdES B-LTA (long-term archival)",
            output: "test-files/result-pades-blta.pdf",
            format: SignatureFormat::PADES,
            pades_level: PadesLevel::B_LTA,
            timestamp_url: Some("http://timestamp.digicert.com"),
            include_crl: true,
            include_ocsp: true,
            include_dss: true,
        },
        TestVariant {
            name: "PKCS7 (basic, no timestamp)",
            output: "test-files/result-pkcs7.pdf",
            format: SignatureFormat::PKCS7,
            pades_level: PadesLevel::B_B,
            timestamp_url: None,
            include_crl: false,
            include_ocsp: false,
            include_dss: false,
        },
        TestVariant {
            name: "PKCS7 + timestamp",
            output: "test-files/result-pkcs7-ts.pdf",
            format: SignatureFormat::PKCS7,
            pades_level: PadesLevel::B_T,
            timestamp_url: Some("http://timestamp.digicert.com"),
            include_crl: false,
            include_ocsp: false,
            include_dss: false,
        },
        TestVariant {
            name: "PKCS7 + CRL + OCSP (LTV-ready)",
            output: "test-files/result-pkcs7-ltv.pdf",
            format: SignatureFormat::PKCS7,
            pades_level: PadesLevel::B_T,
            timestamp_url: Some("http://timestamp.digicert.com"),
            include_crl: true,
            include_ocsp: true,
            include_dss: false,
        },
    ];

    println!();
    println!("═══════════════════════════════════════════════════════════════");
    println!("  Testing {} signing variants with Nowina DSS certificate", variants.len());
    println!("═══════════════════════════════════════════════════════════════");
    println!();

    let mut results: Vec<(&str, &str, bool, String)> = Vec::new();

    for (idx, variant) in variants.iter().enumerate() {
        println!("──────────────────────────────────────────────────────────");
        println!("[{}/{}] {}", idx + 1, variants.len(), variant.name);
        println!("  Output: {}", variant.output);
        println!("──────────────────────────────────────────────────────────");

        // Build fresh signer for each variant (SignerBuilder is consumed)
        let signer = SignerBuilder::new(&private_key, certs[0].clone());

        let user_info = UserSignatureInfo {
            user_id: "good-user-crl-ocsp".to_string(),
            user_name: "Good User (CRL & OCSP)".to_string(),
            user_email: "good-user@nowina.lu".to_string(),
            user_signature: Vec::new(), // invisible signature
            user_signing_keys: signer,
            user_certificate_chain: certs.clone(),
        };

        let mut opts = SignatureOptions::default();
        opts.format = variant.format.clone();
        opts.pades_level = variant.pades_level.clone();
        opts.signature_size = 40_000;
        opts.timestamp_url = variant.timestamp_url.map(|s| s.to_string());
        opts.signed_attribute_include_crl = variant.include_crl;
        opts.signed_attribute_include_ocsp = variant.include_ocsp;
        opts.include_dss = variant.include_dss;
        opts.visible_signature = false;

        // Sign
        let sign_result = {
            let mut doc = PDFSigningDocument::read_from(
                pdf_data.as_slice(),
                "sample.pdf".to_string(),
            ).expect("Failed to load PDF");

            doc.sign_document_no_placeholder(&user_info, &opts)
        };

        match sign_result {
            Ok(signed_pdf) => {
                // Save
                let mut f = fs::File::create(variant.output)
                    .expect("Failed to create output file");
                f.write_all(&signed_pdf).expect("Failed to write PDF");
                println!("  ✅ Signed: {} bytes", signed_pdf.len());

                // Validate
                match SignatureValidator::validate(&signed_pdf) {
                    Ok(val_results) => {
                        let all_valid = val_results.iter().all(|r| r.is_valid());
                        println!("  📋 Signatures found: {}", val_results.len());
                        for (si, vr) in val_results.iter().enumerate() {
                            let sig_type = if vr.field_info.is_document_timestamp {
                                "DocTimestamp"
                            } else {
                                "Signature"
                            };
                            println!(
                                "     [{}] {} — valid={} digest={} cms={} chain={} br={}",
                                si + 1,
                                sig_type,
                                vr.is_valid(),
                                vr.digest_match,
                                vr.cms_signature_valid,
                                vr.certificate_chain_valid,
                                vr.byte_range_valid,
                            );
                            println!(
                                "         signer={} subfilter={:?}",
                                vr.signer_name.as_deref().unwrap_or("?"),
                                vr.sub_filter.as_deref().unwrap_or("?"),
                            );
                            println!(
                                "         timestamp={} dss={} ltv={} no_unauth={}",
                                vr.has_timestamp,
                                vr.has_dss,
                                vr.is_ltv_enabled,
                                vr.no_unauthorized_modifications,
                            );
                            if !vr.errors.is_empty() {
                                for e in &vr.errors {
                                    println!("         ✗ {}", e);
                                }
                            }
                        }
                        let status = if all_valid { "PASS" } else { "FAIL" };
                        println!("  Result: {}", status);
                        results.push((variant.name, variant.output, all_valid, String::new()));
                    }
                    Err(e) => {
                        println!("  ❌ Validation error: {}", e);
                        results.push((variant.name, variant.output, false, format!("{}", e)));
                    }
                }
            }
            Err(e) => {
                println!("  ❌ Signing failed: {}", e);
                results.push((variant.name, variant.output, false, format!("{}", e)));
            }
        }
        println!();
    }

    // ── Summary ──
    println!("═══════════════════════════════════════════════════════════════");
    println!("  SUMMARY");
    println!("═══════════════════════════════════════════════════════════════");
    println!();
    for (name, output, passed, err) in &results {
        let icon = if *passed { "✅" } else { "❌" };
        print!("  {} {} → {}", icon, name, output);
        if !err.is_empty() {
            print!(" ({})", err);
        }
        println!();
    }

    let total = results.len();
    let passed = results.iter().filter(|(_, _, p, _)| *p).count();
    let failed = total - passed;
    println!();
    println!("  Total: {}  Passed: {}  Failed: {}", total, passed, failed);
    println!("═══════════════════════════════════════════════════════════════");

    if failed > 0 {
        std::process::exit(1);
    }
}

