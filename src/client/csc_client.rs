//! HTTP client for CSC API v2 endpoints.

use anyhow::{Context, Result};
use base64::Engine;
use reqwest::Client;

use crate::common::csc_types::{
    AuthLoginRequest, AuthLoginResponse, CredentialsInfoRequest, CredentialsInfoResponse,
    CredentialsListRequest, CredentialsListResponse, CscErrorResponse, InfoResponse,
    SignDocRequest, SignDocResponse, SignPdfRequest, SignPdfResponse, OID_RSA_SHA256, OID_SHA256,
};

/// Client for interacting with a CSC v2 signing server.
pub struct CscClient {
    http: Client,
    base_url: String,
    access_token: Option<String>,
}

impl CscClient {
    /// Create a new CSC client pointing at the given server URL.
    pub fn new(base_url: &str) -> Self {
        CscClient {
            http: Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            access_token: None,
        }
    }

    /// Get service information.
    pub async fn info(&self) -> Result<InfoResponse> {
        let url = format!("{}/csc/v2/info", self.base_url);
        let resp = self
            .http
            .post(&url)
            .json(&serde_json::json!({}))
            .send()
            .await
            .context("Failed to connect to CSC server")?;

        if !resp.status().is_success() {
            let err: CscErrorResponse = resp.json().await.unwrap_or(CscErrorResponse {
                error: "unknown".into(),
                error_description: "Server returned an error".into(),
            });
            anyhow::bail!("info failed: {} — {}", err.error, err.error_description);
        }

        resp.json().await.context("Failed to parse info response")
    }

    /// Authenticate with Basic Auth and obtain a Bearer token.
    pub async fn login(&mut self, username: &str, password: &str) -> Result<String> {
        let url = format!("{}/csc/v2/auth/login", self.base_url);

        let basic_auth = {
            let engine = base64::engine::general_purpose::STANDARD;
            engine.encode(format!("{}:{}", username, password))
        };

        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("Basic {}", basic_auth))
            .json(&AuthLoginRequest { remember_me: true })
            .send()
            .await
            .context("Failed to connect for login")?;

        if !resp.status().is_success() {
            let err: CscErrorResponse = resp.json().await.unwrap_or(CscErrorResponse {
                error: "unknown".into(),
                error_description: "Login failed".into(),
            });
            anyhow::bail!("login failed: {} — {}", err.error, err.error_description);
        }

        let login_resp: AuthLoginResponse = resp.json().await.context("Failed to parse login response")?;
        self.access_token = Some(login_resp.access_token.clone());

        log::info!("Logged in successfully (token expires in {}s)", login_resp.expires_in);
        Ok(login_resp.access_token)
    }

    /// List available signing credentials.
    pub async fn list_credentials(&self) -> Result<CredentialsListResponse> {
        let token = self.get_token()?;
        let url = format!("{}/csc/v2/credentials/list", self.base_url);

        let resp = self
            .http
            .post(&url)
            .bearer_auth(token)
            .json(&CredentialsListRequest::default())
            .send()
            .await
            .context("Failed to list credentials")?;

        if !resp.status().is_success() {
            let err: CscErrorResponse = resp.json().await.unwrap_or(CscErrorResponse {
                error: "unknown".into(),
                error_description: "List credentials failed".into(),
            });
            anyhow::bail!(
                "credentials/list failed: {} — {}",
                err.error,
                err.error_description
            );
        }

        resp.json().await.context("Failed to parse credentials list")
    }

    /// Get certificate chain and key info for a credential.
    pub async fn get_credential_info(
        &self,
        credential_id: &str,
    ) -> Result<CredentialsInfoResponse> {
        let token = self.get_token()?;
        let url = format!("{}/csc/v2/credentials/info", self.base_url);

        let resp = self
            .http
            .post(&url)
            .bearer_auth(token)
            .json(&CredentialsInfoRequest {
                credential_id: credential_id.to_string(),
                certificates: "chain".to_string(),
            })
            .send()
            .await
            .context("Failed to get credential info")?;

        if !resp.status().is_success() {
            let err: CscErrorResponse = resp.json().await.unwrap_or(CscErrorResponse {
                error: "unknown".into(),
                error_description: "Get credential info failed".into(),
            });
            anyhow::bail!(
                "credentials/info failed: {} — {}",
                err.error,
                err.error_description
            );
        }

        resp.json()
            .await
            .context("Failed to parse credential info")
    }

    /// Sign document content using the server's PKI via the signDoc endpoint.
    ///
    /// `content_bytes` is the raw byte range content from the PDF
    /// (everything except the Contents hex placeholder). The server
    /// will build a complete CMS SignedData from this.
    ///
    /// Options:
    /// - `signature_format`: "pkcs7" or "pades"
    /// - `pades_level`: "B-B", "B-T", "B-LT", "B-LTA"
    /// - `timestamp_url`: Optional TSA URL
    pub async fn sign_doc(
        &self,
        credential_id: &str,
        content_bytes: &[u8],
        signature_format: &str,
        pades_level: &str,
        timestamp_url: Option<&str>,
        include_crl: bool,
        include_ocsp: bool,
    ) -> Result<SignDocResponse> {
        let token = self.get_token()?;
        let url = format!("{}/csc/v2/signatures/signDoc", self.base_url);
        let engine = base64::engine::general_purpose::STANDARD;

        let request = SignDocRequest {
            credential_id: credential_id.to_string(),
            document_content: engine.encode(content_bytes),
            hash_algo: OID_SHA256.to_string(),
            sign_algo: OID_RSA_SHA256.to_string(),
            signature_format: signature_format.to_string(),
            pades_level: pades_level.to_string(),
            timestamp_url: timestamp_url.map(|s| s.to_string()),
            include_crl,
            include_ocsp,
        };

        let resp = self
            .http
            .post(&url)
            .bearer_auth(token)
            .json(&request)
            .send()
            .await
            .context("Failed to call signDoc")?;

        if !resp.status().is_success() {
            let err: CscErrorResponse = resp.json().await.unwrap_or(CscErrorResponse {
                error: "unknown".into(),
                error_description: "Sign doc failed".into(),
            });
            anyhow::bail!(
                "signatures/signDoc failed: {} — {}",
                err.error,
                err.error_description
            );
        }

        resp.json().await.context("Failed to parse signDoc response")
    }

    /// Full server-side PDF signing — upload PDF + optional image,
    /// get back a fully signed PDF in one round-trip.
    ///
    /// The server handles: preparation, visible image embedding,
    /// hash computation, CMS signing, and signature embedding.
    pub async fn sign_pdf_remote(
        &self,
        credential_id: &str,
        pdf_bytes: &[u8],
        image_bytes: Option<&[u8]>,
        sig_rect: Option<[f32; 4]>,
        sig_page: u32,
        signer_name: &str,
        signature_format: &str,
        pades_level: &str,
        timestamp_url: Option<&str>,
    ) -> Result<SignPdfResponse> {
        let token = self.get_token()?;
        let url = format!("{}/api/v1/signPdf", self.base_url);
        let engine = base64::engine::general_purpose::STANDARD;

        let request = SignPdfRequest {
            credential_id: credential_id.to_string(),
            pdf_content: engine.encode(pdf_bytes),
            image_content: image_bytes.map(|b| engine.encode(b)),
            sig_rect,
            sig_page,
            signer_name: signer_name.to_string(),
            signature_format: signature_format.to_string(),
            pades_level: pades_level.to_string(),
            timestamp_url: timestamp_url.map(|s| s.to_string()),
            include_crl: false,
            include_ocsp: false,
        };

        let resp = self
            .http
            .post(&url)
            .bearer_auth(token)
            .json(&request)
            .send()
            .await
            .context("Failed to call signPdf")?;

        if !resp.status().is_success() {
            let err: CscErrorResponse = resp.json().await.unwrap_or(CscErrorResponse {
                error: "unknown".into(),
                error_description: "Server-side sign PDF failed".into(),
            });
            anyhow::bail!(
                "signPdf failed: {} — {}",
                err.error,
                err.error_description
            );
        }

        resp.json().await.context("Failed to parse signPdf response")
    }

    /// Validate a signed PDF via the server's validation endpoint.
    pub async fn validate_pdf(
        &self,
        pdf_bytes: &[u8],
        password: Option<&str>,
    ) -> Result<crate::common::csc_types::ValidateResponse> {
        let url = format!("{}/api/v1/validate", self.base_url);
        let engine = base64::engine::general_purpose::STANDARD;

        let request = crate::common::csc_types::ValidateRequest {
            pdf_content: engine.encode(pdf_bytes),
            password: password.map(|s| s.to_string()),
        };

        let resp = self
            .http
            .post(&url)
            .json(&request)
            .send()
            .await
            .context("Failed to call validate")?;

        if !resp.status().is_success() {
            let err: CscErrorResponse = resp.json().await.unwrap_or(CscErrorResponse {
                error: "unknown".into(),
                error_description: "Validation failed".into(),
            });
            anyhow::bail!(
                "validate failed: {} — {}",
                err.error,
                err.error_description
            );
        }

        resp.json().await.context("Failed to parse validate response")
    }

    /// Get the current access token or return an error.
    fn get_token(&self) -> Result<&str> {
        self.access_token
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("Not authenticated. Call login() first."))
    }
}

