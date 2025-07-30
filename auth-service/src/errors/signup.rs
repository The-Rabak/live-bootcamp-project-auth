use thiserror::Error;
use axum::{response::IntoResponse, http::StatusCode};

#[derive(Error, Debug)]
pub enum SignupError {
    #[error("malformed json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid email address")]
    InvalidEmail,

    #[error("password must be at least {0} characters long")]
    PasswordTooShort(usize),

    #[error("Something went wrong, please try again later.")]
    InternalServerError,

    #[error("User with email {0} already exists.")]
    UserAlreadyExists(String),
}

impl IntoResponse for SignupError {
    fn into_response(self) -> axum::response::Response {
        let status = match self {
            SignupError::Json(_) => StatusCode::BAD_REQUEST,
            SignupError::InvalidEmail => StatusCode::BAD_REQUEST,
            SignupError::PasswordTooShort(_) => StatusCode::BAD_REQUEST,
            SignupError::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
            SignupError::UserAlreadyExists(_) => StatusCode::CONFLICT,
        };

        (status, self.to_string()).into_response()
    }
}