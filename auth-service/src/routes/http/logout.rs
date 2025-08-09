use axum::extract::State;
use axum::{http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;

use crate::{
    app_state::AppState, domain::LogoutResponse, errors::LogoutError, utils::auth::decode_token,
};

pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, impl IntoResponse), LogoutError> {
    // Get config
    let config = state.config.read().await;
    let cookie = jar
        .get(config.jwt_cookie_name())
        .ok_or(LogoutError::MissingToken)?;

    let cookie_value = cookie.value().to_owned();
    let cookie_name = cookie.name().to_owned();

    // Check if token is already banned
    let is_banned = {
        state
            .banned_token_store
            .read()
            .await
            .token_exists(&cookie_value)
            .await
    };

    if is_banned {
        return Err(LogoutError::InvalidToken);
    }

    // Validate token structure and expiration
    let claims = decode_token(&cookie_value, &config)
        .await
        .map_err(|_| LogoutError::InvalidToken)?;

    if claims.exp < chrono::Utc::now().timestamp() as usize {
        return Err(LogoutError::InvalidToken);
    }

    // Token is valid, so ban it
    state
        .banned_token_store
        .write()
        .await
        .store_token(cookie_value)
        .await
        .map_err(|_| LogoutError::InternalServerError)?;

    Ok((
        jar.remove(cookie_name),
        (
            StatusCode::OK,
            Json(LogoutResponse {
                message: "Logged out successfully".to_string(),
            }),
        ),
    ))
}
