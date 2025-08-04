use crate::app_state::AppState;
use crate::domain::{Email, Password, SignupRequestBody, SignupResponse};
use crate::errors::SignupError;
use crate::services::AuthService;
use axum::extract::State;
use axum::{http::StatusCode, response::IntoResponse, Json};

pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequestBody>,
) -> Result<impl IntoResponse, SignupError> {
    let email = Email::parse(request.email).or(Err(SignupError::InvalidEmail))?;
    let password = Password::parse(request.password).or(Err(SignupError::InvalidPassword))?;

    AuthService::signup(state, email, password, request.requires_mfa).await?;

    Ok((
        StatusCode::CREATED,
        Json(SignupResponse {
            message: "User created successfully!".to_string(),
        }),
    ))
}
