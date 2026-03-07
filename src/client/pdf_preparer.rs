//! PDF preparation — insert signature placeholder and compute hash.
//!
//! Uses `lopdf` for PDF structure manipulation (incremental updates, AcroForm, ByteRange).
//! Supports both invisible and visible (with image) signatures.

use anyhow::{Context, Result};
use lopdf::{Dictionary, Document, IncrementalDocument, Object, ObjectId, StringFormat};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::client::signature_appearance::{self, VisibleSignatureParams};

/// Configuration for a visible signature with an image.
#[derive(Debug, Clone)]
pub struct VisibleSignatureConfig {
    /// Path to the signature image file (PNG or JPEG)
    pub image_path: std::path::PathBuf,
    /// Page number (1-based) where the signature should appear
    pub page: u32,
    /// Rectangle [x1, y1, x2, y2] in PDF points (1 point = 1/72 inch)
    /// (0,0) is the bottom-left corner of the page
    pub rect: [f32; 4],
}

/// Configuration for a visible signature with in-memory image bytes.
/// Used for server-side rendering where image comes from the request body.
#[derive(Debug, Clone)]
pub struct VisibleSignatureConfigBytes {
    /// Image file bytes (PNG or JPEG)
    pub image_bytes: Vec<u8>,
    /// Page number (1-based) where the signature should appear
    pub page: u32,
    /// Rectangle [x1, y1, x2, y2] in PDF points
    pub rect: [f32; 4],
}

/// Result of preparing a PDF for remote signing.
pub struct PreparedPdf {
    /// The serialized PDF bytes (with placeholder Contents)
    pub pdf_bytes: Vec<u8>,
    /// The byte range: [offset1, length1, offset2, length2]
    pub byte_range: Vec<usize>,
    /// The raw bytes that need to be signed (first_part ++ second_part)
    pub content_to_sign: Vec<u8>,
    /// SHA-256 hash of the content to sign
    pub hash: Vec<u8>,
    /// The signature size (capacity of Contents hex string / 2)
    pub signature_size: usize,
}

/// Prepare a PDF for remote signing by inserting a signature placeholder.
///
/// This function:
/// 1. Loads the PDF
/// 2. Creates a new incremental update with a signature field
/// 3. Adds a V dictionary with ByteRange and Contents placeholder
/// 4. [Optional] Adds a visible signature image appearance
/// 5. Serializes the PDF
/// 6. Fixes the ByteRange values to match actual offsets
/// 7. Computes the SHA-256 hash of the signed byte ranges
pub fn prepare_pdf_for_signing(
    input_path: &Path,
    signer_name: &str,
    visible_config: Option<&VisibleSignatureConfig>,
) -> Result<PreparedPdf> {
    let signature_size: usize = 50_000; // hex chars in Contents placeholder (25KB, enough for CMS + CRL/OCSP)

    log::info!("Loading PDF from {:?}", input_path);
    let mut doc = IncrementalDocument::load(input_path)
        .context("Failed to load PDF")?;
    doc.new_document.version = "1.5".parse().unwrap();

    // Collect references from the previous revision first, then drop immutable borrows
    // before mutating the incremental update document.
    let (root_id, acroform_opt, page_ref) = {
        let prev = doc.get_prev_documents().clone();
        let root_id = prev.trailer.get(b"Root")?.as_reference()?;

        let acroform_opt: Option<ObjectId> = {
            let root_prev = prev.get_object(root_id)?.as_dict()?;
            if root_prev.has(b"AcroForm") {
                Some(root_prev.get(b"AcroForm")?.as_reference()?)
            } else {
                None
            }
        };

        let page_ref = find_page_object_id(&prev, Some(1))?;
        (root_id, acroform_opt, page_ref)
    };

    // Determine target page for the signature
    let sig_page = visible_config.map_or(1, |vc| vc.page);
    let page_ref = if sig_page != 1 {
        let prev = doc.get_prev_documents().clone();
        find_page_object_id(&prev, Some(sig_page))?
    } else {
        page_ref
    };

    // Clone Root into new incremental update
    doc.opt_clone_object_to_new_document(root_id)?;

    // Generate field name
    let field_name = format!("RemoteSignature{}", rand::random::<u32>());

    // Build the V (signature value) dictionary with placeholder ByteRange and Contents
    let v_dict = build_placeholder_v_dictionary(signer_name, signature_size);
    let v_ref = doc.new_document.add_object(v_dict);

    // Build merged field-widget annotation
    // For visible signatures: load image, create appearance, set non-zero Rect
    // For invisible signatures: zero Rect, no appearance
    let (sig_rect, appearance_ref) = if let Some(vc) = visible_config {
        let image_bytes = std::fs::read(&vc.image_path)
            .context(format!("Failed to read signature image {:?}", vc.image_path))?;
        log::info!(
            "Loaded signature image: {:?} ({} bytes)",
            vc.image_path,
            image_bytes.len()
        );

        let vis_params = VisibleSignatureParams {
            image_bytes,
            rect: vc.rect,
            page: vc.page,
            signer_name: signer_name.to_string(),
        };

        let appearance = signature_appearance::build_visible_signature(
            &mut doc.new_document,
            &vis_params,
        )?;

        let rect_arr = Object::Array(vec![
            Object::Real(vc.rect[0]),
            Object::Real(vc.rect[1]),
            Object::Real(vc.rect[2]),
            Object::Real(vc.rect[3]),
        ]);

        (rect_arr, Some(appearance.appearance_id))
    } else {
        let rect_arr = Object::Array(vec![
            0i32.into(),
            0i32.into(),
            0i32.into(),
            0i32.into(),
        ]);
        (rect_arr, None)
    };

    let mut merged_dict = Dictionary::from_iter(vec![
        ("FT", Object::Name(b"Sig".to_vec())),
        (
            "T",
            Object::String(field_name.into_bytes(), StringFormat::Literal),
        ),
        ("V", Object::Reference(v_ref)),
        ("Type", Object::Name(b"Annot".to_vec())),
        ("Subtype", Object::Name(b"Widget".to_vec())),
        ("Rect", sig_rect),
        ("P", Object::Reference(page_ref)),
        ("F", Object::Integer(132)), // Print (4) + Locked (128)
    ]);

    // Add appearance dictionary if this is a visible signature
    if let Some(ap_ref) = appearance_ref {
        let mut ap_dict = Dictionary::new();
        ap_dict.set("N", Object::Reference(ap_ref));
        merged_dict.set("AP", Object::Dictionary(ap_dict));
        log::info!("Added visible signature appearance to widget annotation");
    }

    let sig_field_id = doc.new_document.add_object(Object::Dictionary(merged_dict));

    // Add to page Annots
    doc.opt_clone_object_to_new_document(page_ref)?;
    let page_mut = doc
        .new_document
        .get_object_mut(page_ref)?
        .as_dict_mut()?;

    let new_annots = if page_mut.has(b"Annots") {
        let mut arr = page_mut.get(b"Annots")?.as_array()?.clone();
        arr.push(Object::Reference(sig_field_id));
        Object::Array(arr)
    } else {
        Object::Array(vec![Object::Reference(sig_field_id)])
    };
    page_mut.set("Annots", new_annots);

    // Attach field to AcroForm with SigFlags
    match acroform_opt {
        Some(acro_id) => {
            doc.opt_clone_object_to_new_document(acro_id)?;
            let acro_mut = doc
                .new_document
                .get_object_mut(acro_id)?
                .as_dict_mut()?;
            if acro_mut.has(b"Fields") {
                let mut new_fields = acro_mut.get(b"Fields")?.as_array()?.clone();
                new_fields.push(Object::Reference(sig_field_id));
                acro_mut.set("Fields", Object::Array(new_fields));
            } else {
                acro_mut.set(
                    "Fields",
                    Object::Array(vec![Object::Reference(sig_field_id)]),
                );
            }
            acro_mut.set("SigFlags", Object::Integer(3));
        }
        None => {
            let new_acro = Dictionary::from_iter(vec![
                (
                    "Fields",
                    Object::Array(vec![Object::Reference(sig_field_id)]),
                ),
                ("SigFlags", Object::Integer(3)),
            ]);
            let new_acro_id = doc
                .new_document
                .add_object(Object::Dictionary(new_acro));
            let root_mut = doc
                .new_document
                .get_object_mut(root_id)?
                .as_dict_mut()?;
            root_mut.set("AcroForm", Object::Reference(new_acro_id));
        }
    }

    // Serialize the PDF with placeholder
    let mut raw_doc = doc;
    raw_doc.new_document.compress();
    let mut pdf_bytes: Vec<u8> = Vec::new();
    raw_doc.save_to(&mut pdf_bytes)?;

    // Fix ByteRange and compute hash
    let (byte_range, pdf_bytes) = set_byte_range(pdf_bytes, signature_size);

    // Extract the byte ranges that need to be signed
    let first_part = &pdf_bytes[byte_range[0]..byte_range[0] + byte_range[1]];
    let second_part = &pdf_bytes[byte_range[2]..byte_range[2] + byte_range[3]];

    let mut content_to_sign = Vec::with_capacity(first_part.len() + second_part.len());
    content_to_sign.extend_from_slice(first_part);
    content_to_sign.extend_from_slice(second_part);

    // Compute SHA-256
    let hash = {
        let mut hasher = Sha256::new();
        hasher.update(&content_to_sign);
        hasher.finalize().to_vec()
    };

    log::info!(
        "PDF prepared: {} bytes, ByteRange={:?}, Hash={}",
        pdf_bytes.len(),
        byte_range,
        hex::encode(&hash)
    );

    Ok(PreparedPdf {
        pdf_bytes,
        byte_range,
        content_to_sign,
        hash,
        signature_size,
    })
}

/// Prepare a PDF for signing from in-memory bytes (server-side rendering).
///
/// Same as `prepare_pdf_for_signing` but accepts raw PDF bytes + optional
/// in-memory image bytes instead of file paths. Uses a temp file internally
/// because `lopdf::IncrementalDocument::load` requires a file path.
pub fn prepare_pdf_for_signing_from_bytes(
    pdf_bytes_input: &[u8],
    signer_name: &str,
    visible_config: Option<&VisibleSignatureConfigBytes>,
) -> Result<PreparedPdf> {
    use std::io::Write;

    // Write PDF to temp file for lopdf
    let mut tmp = tempfile::NamedTempFile::new()
        .context("Failed to create temp file for PDF")?;
    tmp.write_all(pdf_bytes_input)
        .context("Failed to write PDF to temp file")?;
    tmp.flush()?;

    // Convert VisibleSignatureConfigBytes → VisibleSignatureConfig-like params
    // We'll call the core logic by converting image bytes inline
    let file_config = if let Some(vc) = visible_config {
        // Write image to a temp file too
        let mut img_tmp = tempfile::NamedTempFile::new()
            .context("Failed to create temp file for image")?;
        img_tmp.write_all(&vc.image_bytes)
            .context("Failed to write image to temp file")?;
        img_tmp.flush()?;
        Some((
            VisibleSignatureConfig {
                image_path: img_tmp.path().to_path_buf(),
                page: vc.page,
                rect: vc.rect,
            },
            img_tmp, // keep alive so the file isn't deleted
        ))
    } else {
        None
    };

    let vis_ref = file_config.as_ref().map(|(cfg, _)| cfg);
    prepare_pdf_for_signing(tmp.path(), signer_name, vis_ref)
}

/// Build the V (signature value) dictionary with placeholder ByteRange and Contents.
fn build_placeholder_v_dictionary(signer_name: &str, signature_size: usize) -> Object {
    use chrono::Utc;

    let now = Utc::now();

    Object::Dictionary(Dictionary::from_iter(vec![
        ("Type", Object::Name(b"Sig".to_vec())),
        ("Filter", Object::Name(b"Adobe.PPKLite".to_vec())),
        (
            "SubFilter",
            Object::Name(b"ETSI.CAdES.detached".to_vec()),
        ),
        (
            "ByteRange",
            Object::Array(vec![
                Object::Integer(0),
                Object::Integer(1000000000),
                Object::Integer(1000000000),
                Object::Integer(1000000000),
            ]),
        ),
        (
            "Contents",
            Object::String(
                vec![0u8; signature_size / 2],
                StringFormat::Hexadecimal,
            ),
        ),
        (
            "M",
            Object::String(
                now.format("D:%Y%m%d%H%M%S+00'00'")
                    .to_string()
                    .as_bytes()
                    .to_vec(),
                StringFormat::Literal,
            ),
        ),
        (
            "Name",
            Object::String(signer_name.as_bytes().to_vec(), StringFormat::Literal),
        ),
    ]))
}

/// Find the ObjectId for a page by 1-based page number.
fn find_page_object_id(doc: &Document, page_num: Option<u32>) -> Result<ObjectId> {
    let page_num = page_num.unwrap_or(1);
    let pages = doc.get_pages();
    let page_id = pages
        .get(&page_num)
        .ok_or_else(|| anyhow::anyhow!("Page {} not found in PDF", page_num))?;
    Ok(*page_id)
}

/// Find and fix the ByteRange in the serialized PDF, then return the
/// actual byte range values and the updated PDF bytes.
///
/// Strategy:
///   1. Locate the placeholder `/ByteRange[0 1000000000 1000000000 1000000000]`
///   2. Locate the `<` that opens the Contents hex string
///   3. Locate the `>` that closes it
///   4. Compute offset1 = `<` position (inclusive)
///   5. Compute offset2 = position after `>`
///   6. Write the real byte-range numbers (left-justified, space-padded to
///      keep the total length identical → no byte shifting).
fn set_byte_range(mut pdf_bytes: Vec<u8>, _signature_size: usize) -> (Vec<usize>, Vec<u8>) {
    // ── Step 1: find the placeholder ByteRange array ──
    let br_placeholder = b"/ByteRange[0 1000000000 1000000000 1000000000]";
    let br_pos = find_pattern(&pdf_bytes, br_placeholder)
        .expect("ByteRange placeholder pattern not found in PDF");

    // ── Step 2: find the Contents hex opening `<` after the ByteRange ──
    let search_start = br_pos + br_placeholder.len();
    let contents_tag = b"/Contents<";
    let contents_tag_pos = find_pattern(&pdf_bytes[search_start..], contents_tag)
        .map(|p| p + search_start)
        .expect("/Contents< not found after ByteRange");
    let hex_open = contents_tag_pos + b"/Contents".len(); // position of `<`

    // ── Step 3: find the matching `>` ──
    let hex_close = pdf_bytes[hex_open + 1..]
        .iter()
        .position(|&b| b == b'>')
        .map(|p| p + hex_open + 1)
        .expect("Closing > of Contents hex string not found");

    // ── Step 4: compute the actual ByteRange ──
    //   [0, <offset>, <offset_after_close>, <remaining>]
    //   first_part  = pdf_bytes[0 .. hex_open]
    //   skipped     = pdf_bytes[hex_open .. hex_close+1]   (the <hex> including delimiters)
    //   second_part = pdf_bytes[hex_close+1 .. EOF]
    let offset1: usize = 0;
    let length1: usize = hex_open;            // up to (not including) `<`
    let offset2: usize = hex_close + 1;       // byte after `>`
    let length2: usize = pdf_bytes.len() - offset2;

    let byte_range = vec![offset1, length1, offset2, length2];

    // ── Step 5: write the real values into the ByteRange placeholder ──
    // The placeholder `0 1000000000 1000000000 1000000000` is 34 chars.
    // We must produce exactly the same width so nothing shifts.
    let old_values = b"0 1000000000 1000000000 1000000000";
    let old_values_len = old_values.len(); // 34
    let new_values = format!("{} {} {} {}", offset1, length1, offset2, length2);

    if new_values.len() > old_values_len {
        panic!(
            "ByteRange values too long ({} chars): '{}' — increase placeholder width",
            new_values.len(),
            new_values
        );
    }

    // Left-justify, pad with spaces
    let padded = format!("{:<width$}", new_values, width = old_values_len);

    // Splice exactly into the old position
    let values_start = br_pos + b"/ByteRange[".len();
    pdf_bytes[values_start..values_start + old_values_len]
        .copy_from_slice(padded.as_bytes());

    (byte_range, pdf_bytes)
}

/// Simple binary pattern search.
fn find_pattern(bytes: &[u8], pattern: &[u8]) -> Option<usize> {
    if bytes.is_empty() || pattern.is_empty() {
        return None;
    }
    bytes.windows(pattern.len()).position(|w| w == pattern)
}

/// Hex encoding utility (for logging)
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

