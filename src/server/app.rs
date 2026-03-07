//! Actix-web application setup and shared state.

use crate::server::pki::PkiState;
use actix_web::{web, App, HttpServer, middleware::Logger};
use std::path::Path;

/// Shared application state injected into all handlers.
pub struct AppState {
    pub pki: PkiState,
}

/// Start the CSC signing server.
pub async fn run_server(cert_dir: &Path, host: &str, port: u16) -> std::io::Result<()> {
    // Load PKI material
    let pki = PkiState::load_from_dir(cert_dir).expect("Failed to load PKI certificates");

    let state = web::Data::new(AppState { pki });

    log::info!("Starting CSC signing server on {}:{}", host, port);

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(state.clone())
            // Increase JSON payload limit to 50 MB for large PDFs + images
            .app_data(web::JsonConfig::default().limit(50 * 1024 * 1024))
            .configure(crate::server::info::configure)
            .configure(crate::server::auth::configure)
            .configure(crate::server::credentials::configure)
            .configure(crate::server::signing::configure)
            .configure(crate::server::validation::configure)
            .configure(crate::server::sign_pdf::configure)
    })
    .bind((host, port))?
    .run()
    .await
}

