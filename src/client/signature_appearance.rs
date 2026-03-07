//! Visible signature appearance builder.
//!
//! Builds a PDF Form XObject (appearance stream) containing an image,
//! suitable for use as the `/AP /N` entry of a signature widget annotation.
//!
//! Supports PNG and JPEG images. Handles alpha transparency via SMask.

use anyhow::{Context, Result};
use lopdf::{Dictionary, Document, Object, ObjectId, Stream};

/// Parameters for a visible signature appearance.
#[derive(Debug, Clone)]
pub struct VisibleSignatureParams {
    /// Image file bytes (PNG or JPEG)
    pub image_bytes: Vec<u8>,
    /// Rectangle on the page: [x1, y1, x2, y2] in PDF user-space points
    pub rect: [f32; 4],
    /// Page number (1-based)
    pub page: u32,
    /// Signer name (shown as text below image if text_below is true)
    pub signer_name: String,
}

/// Decoded image data ready for PDF embedding.
struct DecodedImage {
    /// Raw RGB pixel data (no alpha)
    rgb_data: Vec<u8>,
    /// Optional alpha channel data
    alpha_data: Option<Vec<u8>>,
    /// Image width in pixels
    width: u32,
    /// Image height in pixels
    height: u32,
}

/// Decode an image from bytes (supports PNG and JPEG).
fn decode_image(image_bytes: &[u8]) -> Result<DecodedImage> {
    let img = image::load_from_memory(image_bytes)
        .context("Failed to decode image (supported: PNG, JPEG)")?;

    let rgba = img.to_rgba8();
    let width = rgba.width();
    let height = rgba.height();

    let mut rgb_data = Vec::with_capacity((width * height * 3) as usize);
    let mut alpha_data = Vec::with_capacity((width * height) as usize);
    let mut has_alpha = false;

    for pixel in rgba.pixels() {
        rgb_data.push(pixel[0]); // R
        rgb_data.push(pixel[1]); // G
        rgb_data.push(pixel[2]); // B
        alpha_data.push(pixel[3]); // A
        if pixel[3] != 255 {
            has_alpha = true;
        }
    }

    Ok(DecodedImage {
        rgb_data,
        alpha_data: if has_alpha { Some(alpha_data) } else { None },
        width,
        height,
    })
}

/// Add the image as a PDF Image XObject, returning its ObjectId.
///
/// If the image has transparency, a separate SMask image is also created.
fn add_image_xobject(
    doc: &mut Document,
    decoded: &DecodedImage,
) -> Result<ObjectId> {
    // If alpha channel exists, create SMask first
    let smask_id = if let Some(ref alpha) = decoded.alpha_data {
        let smask_dict = Dictionary::from_iter(vec![
            ("Type", Object::Name(b"XObject".to_vec())),
            ("Subtype", Object::Name(b"Image".to_vec())),
            ("Width", Object::Integer(decoded.width as i64)),
            ("Height", Object::Integer(decoded.height as i64)),
            ("ColorSpace", Object::Name(b"DeviceGray".to_vec())),
            ("BitsPerComponent", Object::Integer(8)),
        ]);
        let smask_stream = Stream::new(smask_dict, alpha.clone());
        Some(doc.add_object(smask_stream))
    } else {
        None
    };

    // Create the main image XObject
    let mut img_dict = Dictionary::from_iter(vec![
        ("Type", Object::Name(b"XObject".to_vec())),
        ("Subtype", Object::Name(b"Image".to_vec())),
        ("Width", Object::Integer(decoded.width as i64)),
        ("Height", Object::Integer(decoded.height as i64)),
        ("ColorSpace", Object::Name(b"DeviceRGB".to_vec())),
        ("BitsPerComponent", Object::Integer(8)),
    ]);

    if let Some(smask_ref) = smask_id {
        img_dict.set("SMask", Object::Reference(smask_ref));
    }

    let img_stream = Stream::new(img_dict, decoded.rgb_data.clone());
    let img_id = doc.add_object(img_stream);

    Ok(img_id)
}

/// Build a Form XObject appearance stream that draws the signature image
/// scaled to fit the given rectangle.
///
/// The appearance stream content is:
///   q <w> 0 0 <h> 0 0 cm /Img Do Q
///
/// Returns the ObjectId of the Form XObject.
fn build_appearance_form_xobject(
    doc: &mut Document,
    image_id: ObjectId,
    rect: [f32; 4],
) -> Result<ObjectId> {
    let width = rect[2] - rect[0];
    let height = rect[3] - rect[1];

    // Appearance stream content: scale image to fill the rect
    let content = format!(
        "q {:.2} 0 0 {:.2} 0 0 cm /Img Do Q",
        width, height
    );

    // Resources dictionary referencing the image as /Img
    let mut xobject_dict = Dictionary::new();
    xobject_dict.set("Img", Object::Reference(image_id));

    let mut resources = Dictionary::new();
    resources.set("XObject", Object::Dictionary(xobject_dict));

    // Form XObject dictionary
    let mut form_dict = Dictionary::from_iter(vec![
        ("Type", Object::Name(b"XObject".to_vec())),
        ("Subtype", Object::Name(b"Form".to_vec())),
        (
            "BBox",
            Object::Array(vec![
                Object::Real(0.0),
                Object::Real(0.0),
                Object::Real(width),
                Object::Real(height),
            ]),
        ),
        ("Resources", Object::Dictionary(resources)),
    ]);

    // The matrix positions the form at the origin; the widget Rect handles placement
    form_dict.set(
        "Matrix",
        Object::Array(vec![
            Object::Real(1.0),
            Object::Real(0.0),
            Object::Real(0.0),
            Object::Real(1.0),
            Object::Real(0.0),
            Object::Real(0.0),
        ]),
    );

    let form_stream = Stream::new(form_dict, content.into_bytes());
    let form_id = doc.add_object(form_stream);

    Ok(form_id)
}

/// Result of building a visible signature appearance.
pub struct SignatureAppearance {
    /// ObjectId of the appearance Form XObject (`/AP /N` value)
    pub appearance_id: ObjectId,
    /// The rectangle [x1, y1, x2, y2] in PDF points
    pub rect: [f32; 4],
}

/// Build a visible signature appearance and add it to the document.
///
/// This creates:
/// 1. An Image XObject from the decoded image bytes
/// 2. An optional SMask for alpha transparency
/// 3. A Form XObject appearance stream that renders the image
///
/// The returned `SignatureAppearance` contains the appearance ObjectId
/// to be set as `/AP << /N <ref> >>` on the signature widget annotation,
/// and the rect to be set as the widget's `/Rect`.
pub fn build_visible_signature(
    doc: &mut Document,
    params: &VisibleSignatureParams,
) -> Result<SignatureAppearance> {
    log::info!(
        "Building visible signature: image={} bytes, rect={:?}, page={}",
        params.image_bytes.len(),
        params.rect,
        params.page,
    );

    // Decode image
    let decoded = decode_image(&params.image_bytes)?;
    log::info!(
        "Decoded image: {}x{} pixels, alpha={}",
        decoded.width,
        decoded.height,
        decoded.alpha_data.is_some()
    );

    // Add image XObject to document
    let image_id = add_image_xobject(doc, &decoded)?;

    // Build appearance Form XObject
    let appearance_id = build_appearance_form_xobject(doc, image_id, params.rect)?;

    Ok(SignatureAppearance {
        appearance_id,
        rect: params.rect,
    })
}
