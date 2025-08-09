use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

use crate::{
    app_state::AppState, domain::VerifyTokenRequestBody, errors::VerifyTokenError,
    utils::auth::decode_token,
};

pub async fn verify_token(
    State(state): State<AppState>,
    Json(request): Json<VerifyTokenRequestBody>,
) -> Result<impl IntoResponse, VerifyTokenError> {
    // Get config
    let config = state.config.read().await;

    // First check if token is banned
    let is_banned = {
        state
            .banned_token_store
            .read()
            .await
            .token_exists(&request.token)
            .await
    };

    if is_banned {
        return Err(VerifyTokenError::InvalidToken);
    }

    // Decode and validate token structure
    let claims = decode_token(&request.token, &config)
        .await
        .map_err(|_| VerifyTokenError::MalformedToken)?;

    // Check if token is expired
    if claims.exp < chrono::Utc::now().timestamp() as usize {
        return Err(VerifyTokenError::InvalidToken);
    }

    // Token is valid, so ban it for future use
    state
        .banned_token_store
        .write()
        .await
        .store_token(request.token)
        .await
        .map_err(|_| VerifyTokenError::InternalServerError)?;

    Ok(StatusCode::OK)
}
