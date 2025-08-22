use axum::{http::StatusCode, response::IntoResponse};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VerifyMfaError {
    #[error("malformed json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid email address")]
    InvalidEmail,

    #[error("invalid login request id")]
    InvalidLoginRequestId,

    #[error("invalid 2fa code")]
    InvalidMFACode,

    #[error("code has been used before")]
    OldCode,

    #[error("Something went wrong, please try again later.")]
    InternalServerError,
}

impl IntoResponse for VerifyMfaError {
    fn into_response(self) -> axum::response::Response {
        let status = match self {
            VerifyMfaError::Json(_) => StatusCode::BAD_REQUEST,
            VerifyMfaError::InvalidEmail => StatusCode::UNAUTHORIZED,
            VerifyMfaError::InvalidLoginRequestId => StatusCode::UNAUTHORIZED,
            VerifyMfaError::InvalidMFACode => StatusCode::UNAUTHORIZED,
            VerifyMfaError::OldCode => StatusCode::UNAUTHORIZED,
            VerifyMfaError::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (status, self.to_string()).into_response()
    }
}
