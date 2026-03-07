//! Multipart form-data helper utilities.
//!
//! Provides `extract_multipart_fields()` which reads all fields from an
//! `actix_multipart::Multipart` stream into a `HashMap<String, FieldData>`.
//!
//! Each field is either raw bytes (file upload) or a UTF-8 text value.

use actix_multipart::Multipart;
use futures_util::StreamExt;
use std::collections::HashMap;

/// A single field extracted from a multipart form.
#[derive(Debug)]
pub struct FieldData {
    /// Raw bytes of the field content
    pub bytes: Vec<u8>,
    /// Original filename (if it was a file upload)
    pub filename: Option<String>,
    /// Content-Type of the field (e.g. "application/pdf", "image/png")
    pub content_type: Option<String>,
}

impl FieldData {
    /// Interpret field as UTF-8 text (for non-file form fields).
    pub fn as_text(&self) -> Option<&str> {
        std::str::from_utf8(&self.bytes).ok()
    }

    /// Parse as f32 (for numeric form fields like rect components).
    pub fn as_f32(&self) -> Option<f32> {
        self.as_text()?.trim().parse().ok()
    }

    /// Parse as u32.
    pub fn as_u32(&self) -> Option<u32> {
        self.as_text()?.trim().parse().ok()
    }

    /// Parse as bool ("true"/"1"/"yes" → true, else false).
    pub fn as_bool(&self) -> bool {
        match self.as_text() {
            Some(s) => matches!(s.trim().to_lowercase().as_str(), "true" | "1" | "yes"),
            None => false,
        }
    }
}

/// Extract all fields from a multipart stream into a HashMap.
///
/// Field names are used as keys. If the same field name appears multiple
/// times, only the last value is kept (except in practice each field is unique).
///
/// # Limits
/// - Maximum field size: 50 MB (for large PDF files)
pub async fn extract_multipart_fields(
    mut payload: Multipart,
) -> Result<HashMap<String, FieldData>, String> {
    const MAX_FIELD_SIZE: usize = 50 * 1024 * 1024; // 50 MB

    let mut fields = HashMap::new();

    while let Some(item) = payload.next().await {
        let mut field = item.map_err(|e| format!("Multipart error: {}", e))?;

        let name = field
            .name()
            .map(|n| n.to_string())
            .unwrap_or_default();

        let filename = field
            .content_disposition()
            .and_then(|cd| cd.get_filename().map(|f| f.to_string()));

        let content_type = field
            .content_type()
            .map(|ct| ct.to_string());

        let mut bytes = Vec::new();
        while let Some(chunk) = field.next().await {
            let chunk = chunk.map_err(|e| format!("Error reading field '{}': {}", name, e))?;
            if bytes.len() + chunk.len() > MAX_FIELD_SIZE {
                return Err(format!(
                    "Field '{}' exceeds maximum size of {} bytes",
                    name, MAX_FIELD_SIZE
                ));
            }
            bytes.extend_from_slice(&chunk);
        }

        fields.insert(
            name,
            FieldData {
                bytes,
                filename,
                content_type,
            },
        );
    }

    Ok(fields)
}

