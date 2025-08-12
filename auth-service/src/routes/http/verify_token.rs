use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;

use crate::{app_state::AppState, errors::VerifyTokenError};

pub async fn verify_token(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, VerifyTokenError> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(VerifyTokenError::InvalidToken)?;

    let token = auth
        .strip_prefix("Bearer ")
        .ok_or(VerifyTokenError::InvalidToken)?;

    let token_service = state.token_service.write().await;

    let _ = token_service.validate_access(token).await.map_err(|_| {
        // Whether invalid or revoked, treat as unauthorized to avoid leaking info.
        VerifyTokenError::InvalidToken
    })?;

    Ok(StatusCode::OK)
}
