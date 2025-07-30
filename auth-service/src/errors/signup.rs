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
}

impl IntoResponse for SignupError {
    fn into_response(self) -> axum::response::Response {
        let status = match self {
            SignupError::Json(_) => StatusCode::BAD_REQUEST,
            SignupError::InvalidEmail => StatusCode::BAD_REQUEST,
            SignupError::PasswordTooShort(_) => StatusCode::BAD_REQUEST,
        };

        (status, self.to_string()).into_response()
    }
}