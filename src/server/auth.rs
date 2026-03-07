//! `/csc/v2/auth/login` — simple token-based authentication.
//!
//! For this prototype, we use a static user database and issue JWT tokens.

use actix_web::{web, HttpRequest, HttpResponse};
use chrono::Utc;
use jsonwebtoken::{encode, decode, EncodingKey, DecodingKey, Header, Validation, Algorithm};
use serde::{Deserialize, Serialize};

use crate::common::csc_types::{AuthLoginRequest, AuthLoginResponse, CscErrorResponse};
use crate::server::app::AppState;

/// JWT secret (in production, use env var or vault)
pub const JWT_SECRET: &[u8] = b"csc-prototype-jwt-secret-2024";

/// JWT claims
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,        // username
    pub exp: usize,         // expiration timestamp
    pub iat: usize,         // issued at
}

/// Static user database for the prototype
pub struct StaticUser {
    pub username: &'static str,
    pub password: &'static str,
    pub credential_id: &'static str,
}

/// Prototype users
pub const USERS: &[StaticUser] = &[
    StaticUser {
        username: "testuser",
        password: "testpass",
        credential_id: "credential-001",
    },
    StaticUser {
        username: "signer",
        password: "signer123",
        credential_id: "credential-001",
    },
];

/// Extract Basic Auth credentials from the Authorization header
fn extract_basic_auth(req: &HttpRequest) -> Option<(String, String)> {
    let auth_header = req.headers().get("Authorization")?.to_str().ok()?;
    if !auth_header.starts_with("Basic ") {
        return None;
    }
    let encoded = &auth_header[6..];
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decoded_str = String::from_utf8(decoded).ok()?;
    let parts: Vec<&str> = decoded_str.splitn(2, ':').collect();
    if parts.len() == 2 {
        Some((parts[0].to_string(), parts[1].to_string()))
    } else {
        None
    }
}

/// `POST /csc/v2/auth/login`
pub async fn login_handler(
    req: HttpRequest,
    _body: web::Json<AuthLoginRequest>,
    _state: web::Data<AppState>,
) -> HttpResponse {
    // Extract Basic Auth
    let (username, password) = match extract_basic_auth(&req) {
        Some(creds) => creds,
        None => {
            return HttpResponse::Unauthorized().json(CscErrorResponse {
                error: "invalid_client".to_string(),
                error_description: "Missing or invalid Basic Auth header".to_string(),
            });
        }
    };

    // Validate credentials against static user database
    let user = USERS.iter().find(|u| u.username == username && u.password == password);
    let user = match user {
        Some(u) => u,
        None => {
            return HttpResponse::Unauthorized().json(CscErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: "Invalid username or password".to_string(),
            });
        }
    };

    // Generate JWT
    let now = Utc::now().timestamp() as usize;
    let expires_in = 3600u64; // 1 hour
    let claims = Claims {
        sub: user.username.to_string(),
        exp: now + expires_in as usize,
        iat: now,
    };

    let token = match encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET),
    ) {
        Ok(t) => t,
        Err(e) => {
            log::error!("Failed to create JWT: {}", e);
            return HttpResponse::InternalServerError().json(CscErrorResponse {
                error: "server_error".to_string(),
                error_description: "Failed to generate access token".to_string(),
            });
        }
    };

    log::info!("User '{}' logged in successfully", username);

    HttpResponse::Ok().json(AuthLoginResponse {
        access_token: token,
        token_type: "Bearer".to_string(),
        expires_in,
    })
}

/// Validate a Bearer token and return the claims.
pub fn validate_bearer_token(req: &HttpRequest) -> Result<Claims, HttpResponse> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !auth_header.starts_with("Bearer ") {
        return Err(HttpResponse::Unauthorized().json(CscErrorResponse {
            error: "invalid_token".to_string(),
            error_description: "Missing or invalid Bearer token".to_string(),
        }));
    }

    let token = &auth_header[7..];
    let validation = Validation::new(Algorithm::HS256);

    match decode::<Claims>(token, &DecodingKey::from_secret(JWT_SECRET), &validation) {
        Ok(data) => Ok(data.claims),
        Err(e) => {
            log::warn!("Invalid token: {}", e);
            Err(HttpResponse::Unauthorized().json(CscErrorResponse {
                error: "invalid_token".to_string(),
                error_description: format!("Token validation failed: {}", e),
            }))
        }
    }
}

/// Configure auth routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/csc/v2/auth/login", web::post().to(login_handler));
}

