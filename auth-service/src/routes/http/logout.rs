use axum::{http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;

use crate::{
    domain::LogoutResponse,
    errors::LogoutError,
    utils::{auth::validate_token, consts::JWT_COOKIE_NAME},
};

pub async fn logout(jar: CookieJar) -> Result<(CookieJar, impl IntoResponse), LogoutError> {
    let cookie = jar.get(JWT_COOKIE_NAME).ok_or(LogoutError::MissingToken)?;

    let cookie_value = cookie.value().to_owned();
    let cookie_name = cookie.name().to_owned();
    validate_token(&cookie_value)
        .await
        .map_err(|e| LogoutError::InvalidToken)?;

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
