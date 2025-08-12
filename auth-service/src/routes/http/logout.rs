use axum::extract::State;
use axum::http::HeaderMap;
use axum::{http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use uuid::Uuid;

use crate::{
    app_state::AppState, domain::LogoutResponse, errors::LogoutError,
    utils::cookie_helpers::clear_cookie,
};

pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<(CookieJar, impl IntoResponse), LogoutError> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(LogoutError::InvalidToken)?;

    let token = auth
        .strip_prefix("Bearer ")
        .ok_or(LogoutError::InvalidToken)?;

    {
        let token_service = state.token_service.write().await;

        let claims = token_service.validate_access(token).await.map_err(|_| {
            // Whether invalid or revoked, treat as unauthorized to avoid leaking info.
            LogoutError::InvalidToken
        })?;

        let sid = Uuid::parse_str(&claims.sid).map_err(|_| LogoutError::InvalidToken)?;
        token_service.logout_session(sid).await;
    }

    let jar = {
        let config = state.config.read().await;
        jar.add(clear_cookie(config.access_cookie_name(), "/"))
            .add(clear_cookie(config.refresh_cookie_name(), "/refresh-token"))
    };

    Ok((
        jar,
        (
            StatusCode::OK,
            Json(LogoutResponse {
                message: "Logged out successfully".to_string(),
            }),
        ),
    ))
}
