use crate::app_state::AppState;
use crate::domain::{Email, LoginRequestBody, LoginResponse, Password};
use crate::errors::LoginError;
use crate::services::AuthService;
use crate::utils::cookie_helpers::{access_cookie, refresh_cookie};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use axum_extra::extract::CookieJar;

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequestBody>,
) -> Result<(CookieJar, impl IntoResponse), LoginError> {
    let email = Email::parse(request.email).or(Err(LoginError::InvalidEmail))?;
    let password = Password::parse(request.password).or(Err(LoginError::InvalidPassword))?;
    AuthService::login(state.clone(), email.clone(), password).await?;

    let issued = state
        .token_service
        .write()
        .await
        .issue_initial_session(email.as_ref())
        .await
        .map_err(|_| LoginError::InternalServerError)?;

    let jar = {
        let config = state.config.read().await;
        jar.add(access_cookie(
            config.access_cookie_name(),
            &issued.access_token,
            config.token_ttl_seconds(),
        ))
        .add(refresh_cookie(
            config.refresh_cookie_name(),
            &issued.refresh_token,
            config.refresh_token_ttl_seconds(),
        ))
    };

    Ok((
        jar,
        (
            StatusCode::OK,
            Json(LoginResponse {
                message: "Logged in successfully".to_string(),
            }),
        ),
    ))
}
