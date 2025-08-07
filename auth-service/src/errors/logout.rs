use axum::{http::StatusCode, response::IntoResponse};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LogoutError {
    #[error("Something went wrong, please try again later.")]
    InternalServerError,

    #[error("Invalid token provided")]
    InvalidToken,

    #[error("Token not provided")]
    MissingToken,
}

impl IntoResponse for LogoutError {
    fn into_response(self) -> axum::response::Response {
        let status = match self {
            LogoutError::InvalidToken => StatusCode::UNAUTHORIZED,
            LogoutError::MissingToken => StatusCode::BAD_REQUEST,
            LogoutError::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (status, self.to_string()).into_response()
    }
}
