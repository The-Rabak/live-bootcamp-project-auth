use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::app_state::BannedTokenStoreType;
use crate::domain::email::Email;

use super::Config;

// Create cookie with a new JWT auth token
pub fn generate_auth_cookie(
    email: &Email,
    config: &Config,
) -> Result<Cookie<'static>, GenerateTokenError> {
    let token = generate_auth_token(email, config)?;
    Ok(create_auth_cookie(token, config))
}

// Create cookie and set the value to the passed-in token string
fn create_auth_cookie(token: String, config: &Config) -> Cookie<'static> {
    let cookie = Cookie::build((config.jwt_cookie_name().to_owned(), token))
        .path("/") // apply cookie to all URLs on the server
        .http_only(true) // prevent JavaScript from accessing the cookie
        .same_site(SameSite::Lax) // send cookie with "same-site" requests, and with "cross-site" top-level navigation.
        .build();

    cookie
}

#[derive(Debug)]
pub enum GenerateTokenError {
    TokenError(jsonwebtoken::errors::Error),
    BannedToken,
    UnexpectedError,
}

// Create JWT auth token
pub fn generate_auth_token(email: &Email, config: &Config) -> Result<String, GenerateTokenError> {
    let delta = chrono::Duration::try_seconds(config.token_ttl_seconds())
        .ok_or(GenerateTokenError::UnexpectedError)?;

    // Create JWT expiration time
    let exp = Utc::now()
        .checked_add_signed(delta)
        .ok_or(GenerateTokenError::UnexpectedError)?
        .timestamp();

    // Cast exp to a usize, which is what Claims expects
    let exp: usize = exp
        .try_into()
        .map_err(|_| GenerateTokenError::UnexpectedError)?;

    let sub = email.as_ref().to_owned();

    let claims = Claims { sub, exp };

    create_token(&claims, config).map_err(GenerateTokenError::TokenError)
}

pub fn generate_refresh_token(token: String, config: &Config) -> Result<String, GenerateTokenError> {
    let delta = chrono::Duration::try_seconds(config.refresh_token_ttl_seconds())
        .ok_or(GenerateTokenError::UnexpectedError)?;
    
    // Create JWT expiration time
    let exp = Utc::now()
        .checked_add_signed(delta)
        .ok_or(GenerateTokenError::UnexpectedError)?
        .timestamp();

}

// Check if JWT auth token is valid by decoding it using the JWT secret
pub async fn validate_token(
    banned_token_store: BannedTokenStoreType,
    token: &str,
    config: &Config,
) -> Result<Claims, GenerateTokenError> {
    // First check if token is banned (in separate scope to release read lock)
    let is_banned = {
        banned_token_store
            .read()
            .await
            .token_exists(&token.to_owned())
            .await
    };

    if is_banned {
        return Err(GenerateTokenError::BannedToken);
    }

    // Token is not banned, so validate it first
    let claims = decode_token(token, config).await.map_err(|_e| {
        GenerateTokenError::TokenError(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidToken,
        ))
    })?;

    // If token is valid, then ban it (in separate scope)
    {
        banned_token_store
            .write()
            .await
            .store_token(token.to_owned())
            .await
            .map_err(|_e| GenerateTokenError::UnexpectedError)?;
    }

    Ok(claims)
}

pub async fn decode_token(
    token: &str,
    config: &Config,
) -> Result<Claims, jsonwebtoken::errors::Error> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(config.jwt_secret().as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
}

// Create JWT auth token by encoding claims using the JWT secret
fn create_token(claims: &Claims, config: &Config) -> Result<String, jsonwebtoken::errors::Error> {
    encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret().as_bytes()),
    )
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_generate_auth_cookie() {
        let email = Email::parse("test@example.com".to_owned()).unwrap();
        let config = Config::default();
        let cookie = generate_auth_cookie(&email, &config).unwrap();
        assert_eq!(cookie.name(), config.jwt_cookie_name());
        assert_eq!(cookie.value().split('.').count(), 3);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_create_auth_cookie() {
        let token = "test_token".to_owned();
        let config = Config::default();
        let cookie = create_auth_cookie(token.clone(), &config);
        assert_eq!(cookie.name(), config.jwt_cookie_name());
        assert_eq!(cookie.value(), token);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_generate_auth_token() {
        let email = Email::parse("test@example.com".to_owned()).unwrap();
        let config = Config::default();
        let token = generate_auth_token(&email, &config).unwrap();
        assert!(token.len() > 0);
    }

    #[tokio::test]
    async fn test_validate_token_with_valid_token() {
        let email = Email::parse("test@example.com".to_owned()).unwrap();
        let config = Config::default();
        let token = generate_auth_token(&email, &config).unwrap();
        let result = decode_token(&token, &config).await.unwrap();
        assert_eq!(result.sub, "test@example.com");

        let exp = Utc::now()
            .checked_add_signed(chrono::Duration::try_minutes(9).expect("valid duration"))
            .expect("valid timestamp")
            .timestamp();

        assert!(result.exp > exp as usize);
    }

    #[tokio::test]
    async fn test_validate_token_with_invalid_token() {
        let token = "invalid_token".to_owned();
        let config = Config::default();
        let result = decode_token(&token, &config).await;
        assert!(result.is_err());
    }
}
