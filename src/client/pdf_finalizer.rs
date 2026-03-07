//! PDF finalization — embed the CMS signature into the prepared PDF.

use anyhow::{Context, Result};
use std::io::Write;
use std::path::Path;

/// Embed a CMS/PKCS#7 signature into the prepared PDF's Contents placeholder.
///
/// The `prepared_pdf_bytes` must already have the correct ByteRange set.
/// The `cms_signature` is the DER-encoded CMS blob from the server.
/// `signature_size` is the total hex character capacity of the Contents field.
///
/// The replacement is done as a fixed-width, in-place write so the file
/// size does not change and ByteRange values remain valid.
pub fn embed_signature(
    prepared_pdf_bytes: &[u8],
    cms_signature: &[u8],
    signature_size: usize,
) -> Result<Vec<u8>> {
    let mut pdf_bytes = prepared_pdf_bytes.to_vec();

    // The Contents field in the PDF looks like: /Contents<0000...0000>
    // We need to find the placeholder and write the hex-encoded CMS signature.

    // Build the pattern to find the start of Contents hex placeholder.
    let pattern_prefix = b"/Contents<";
    let pattern_content = vec![b'0'; signature_size.min(51)];
    let mut pattern = pattern_prefix.to_vec();
    pattern.extend_from_slice(&pattern_content);

    let found_at = find_pattern(&pdf_bytes, &pattern)
        .context("Contents placeholder pattern not found in PDF")?;

    // The hex content starts right after "/Contents<"
    let hex_start = found_at + pattern_prefix.len();

    // Build the hex-encoded signature, zero-padded to fill the full placeholder.
    let hex_signature: String = cms_signature
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    if hex_signature.len() > signature_size {
        anyhow::bail!(
            "CMS signature is too large: {} hex chars, but only {} available in Contents",
            hex_signature.len(),
            signature_size
        );
    }

    // Pad with trailing zeros to fill the entire Contents placeholder.
    let padded_hex = format!("{:0<width$}", hex_signature, width = signature_size);

    // In-place byte copy — no splice, no size change.
    pdf_bytes[hex_start..hex_start + signature_size]
        .copy_from_slice(padded_hex.as_bytes());

    log::info!(
        "Embedded CMS signature ({} bytes / {} hex chars, padded to {}) into PDF",
        cms_signature.len(),
        hex_signature.len(),
        signature_size
    );

    Ok(pdf_bytes)
}

/// Save the signed PDF to a file.
pub fn save_signed_pdf(pdf_bytes: &[u8], output_path: &Path) -> Result<()> {
    let mut file = std::fs::File::create(output_path)
        .context(format!("Failed to create output file {:?}", output_path))?;
    file.write_all(pdf_bytes)
        .context("Failed to write signed PDF")?;
    log::info!("Signed PDF saved to {:?}", output_path);
    Ok(())
}

/// Simple binary pattern search.
fn find_pattern(bytes: &[u8], pattern: &[u8]) -> Option<usize> {
    if bytes.is_empty() || pattern.is_empty() {
        return None;
    }
    bytes.windows(pattern.len()).position(|w| w == pattern)
}

