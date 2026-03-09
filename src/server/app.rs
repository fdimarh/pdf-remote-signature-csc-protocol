//! Actix-web application setup and shared state.

use crate::server::pki::PkiState;
use crate::server::pki_backend::PkiBackend;
use actix_multipart::form::MultipartFormConfig;
use actix_web::{web, App, HttpServer, middleware::Logger};
use std::path::Path;
use std::sync::Arc;

/// Shared application state injected into all handlers.
pub struct AppState {
    /// PKI backend (PEM in-memory or HSM PKCS#11)
    pub backend: Arc<dyn PkiBackend>,
    /// Legacy field — provides backward compatibility for code using `state.pki`
    pub pki: PkiState,
}

/// Start the CSC signing server.
pub async fn run_server(cert_dir: &Path, host: &str, port: u16) -> std::io::Result<()> {
    run_server_with_backend(cert_dir, host, port, None).await
}

/// Start the server with an explicit PKI backend.
///
/// If `backend` is `None`, falls back to PEM-based backend loaded from `cert_dir`.
pub async fn run_server_with_backend(
    cert_dir: &Path,
    host: &str,
    port: u16,
    backend: Option<Arc<dyn PkiBackend>>,
) -> std::io::Result<()> {
    // Load PKI material (always needed for cert metadata, credential responses, etc.)
    let pki = PkiState::load_from_dir(cert_dir).expect("Failed to load PKI certificates");

    // Use provided backend or create PEM backend
    let backend: Arc<dyn PkiBackend> = match backend {
        Some(b) => {
            log::info!("Using PKI backend: {}", b.backend_name());
            b
        }
        None => {
            let pem_backend = crate::server::pki_backend::PemBackend::new(pki.clone());
            log::info!("Using PKI backend: {}", pem_backend.backend_name());
            Arc::new(pem_backend)
        }
    };

    let state = web::Data::new(AppState { backend, pki });

    log::info!("Starting CSC signing server on {}:{}", host, port);

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(state.clone())
            // Increase JSON payload limit to 50 MB for large PDFs + images
            .app_data(web::JsonConfig::default().limit(50 * 1024 * 1024))
            // Increase multipart payload limit to 50 MB for form-data uploads
            .app_data(MultipartFormConfig::default().total_limit(50 * 1024 * 1024))
            .app_data(web::PayloadConfig::default().limit(50 * 1024 * 1024))
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
