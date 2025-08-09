use crate::app_state::AppState;
use crate::domain::{Email, LoginRequestBody, LoginResponse, Password};
use crate::errors::LoginError;
use crate::services::AuthService;
use crate::utils::auth::generate_auth_cookie;
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

    let config = state.config.read().await;
    let jwt_cookie =
        generate_auth_cookie(&email, &config).map_err(|_| LoginError::InternalServerError)?;

    Ok((
        jar.add(jwt_cookie),
        (
            StatusCode::OK,
            Json(LoginResponse {
                message: "Logged in successfully".to_string(),
            }),
        ),
    ))
}
