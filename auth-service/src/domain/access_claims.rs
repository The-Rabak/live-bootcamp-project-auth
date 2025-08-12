use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessClaims {
    pub sub: String, // Subject (user ID)
    pub iss: String, // Issuer
    pub aud: String, // Audience
    pub exp: usize,  // Expiration time
    pub iat: usize,  // Issued at time
    pub jti: String, // JWT ID
    pub sid: String, // Session ID
}
