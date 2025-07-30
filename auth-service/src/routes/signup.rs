use axum::{http::StatusCode, response::IntoResponse, Json};
use crate::domain::{SignupRequestBody};
use crate::errors::SignupError;
use crate::validation::is_valid_email;

pub async fn signup(Json(request): Json<SignupRequestBody>) -> Result<StatusCode, SignupError> {

    if !is_valid_email(&request.email) {
        return Err(SignupError::InvalidEmail);
    }

    // validate password length
    let min_len = 8;
    if request.password.len() < min_len {
        return Err(SignupError::PasswordTooShort(min_len));
    }

    Ok(StatusCode::CREATED)
}