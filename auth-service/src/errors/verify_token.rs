use axum::{http::StatusCode, response::IntoResponse};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VerifyTokenError {
    #[error("Something went wrong, please try again later.")]
    InternalServerError,

    #[error("Invalid token provided")]
    InvalidToken,

    #[error("Token not provided")]
    MalformedToken,
}

impl IntoResponse for VerifyTokenError {
    fn into_response(self) -> axum::response::Response {
        let status = match self {
            VerifyTokenError::InvalidToken => StatusCode::UNAUTHORIZED,
            VerifyTokenError::MalformedToken => StatusCode::UNPROCESSABLE_ENTITY,
            VerifyTokenError::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (status, self.to_string()).into_response()
    }
}
