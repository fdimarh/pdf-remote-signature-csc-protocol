//! `/csc/v2/info` endpoint — returns service metadata.

use actix_web::{web, HttpResponse};

use crate::common::csc_types::InfoResponse;

/// `POST /csc/v2/info`
pub async fn info_handler() -> HttpResponse {
    let response = InfoResponse {
        specs: "2.0.0.0".to_string(),
        name: "Remote Signature PDF Prototype".to_string(),
        logo: String::new(),
        region: "ID".to_string(),
        lang: "en".to_string(),
        description: "CSC v2 prototype signing service with static PKI backend. Supports PKCS7 and PAdES (B-B, B-T, B-LT, B-LTA) signature formats, PDF validation, visible/invisible signatures, and multipart/form-data uploads.".to_string(),
        auth_type: vec!["basic".to_string()],
        methods: vec![
            "auth/login".to_string(),
            "credentials/list".to_string(),
            "credentials/info".to_string(),
            "signatures/signHash".to_string(),
            "signatures/signDoc".to_string(),
            "signatures/signDoc/form".to_string(),
            "signPdf".to_string(),
            "signPdf/form".to_string(),
            "validate".to_string(),
            "validate/form".to_string(),
        ],
        signature_formats: vec!["pkcs7".to_string(), "pades".to_string()],
        pades_levels: vec![
            "B-B".to_string(),
            "B-T".to_string(),
            "B-LT".to_string(),
            "B-LTA".to_string(),
        ],
    };
    HttpResponse::Ok().json(response)
}

/// Configure the info route
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/csc/v2/info", web::post().to(info_handler));
}
