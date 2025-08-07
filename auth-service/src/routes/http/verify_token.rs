use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

use crate::{
    domain::VerifyTokenRequestBody,
    errors::VerifyTokenError,
    utils::{auth::validate_token, Claims},
};

pub async fn verify_token(
    Json(request): Json<VerifyTokenRequestBody>,
) -> Result<impl IntoResponse, VerifyTokenError> {
    let claims = validate_token(&request.token)
        .await
        .map_err(|e| VerifyTokenError::MalformedToken)?;

    if claims.exp < chrono::Utc::now().timestamp() as usize {
        return Err(VerifyTokenError::InvalidToken);
    }
    Ok(StatusCode::OK)
}
