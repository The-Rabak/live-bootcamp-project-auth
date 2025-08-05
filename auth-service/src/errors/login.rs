use axum::{http::StatusCode, response::IntoResponse};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LoginError {
    #[error("malformed json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid email address")]
    InvalidEmail,

    #[error("password must be at least 8 characters long, contain at least one uppercase letter and one special character.")]
    InvalidPassword,

    #[error("Something went wrong, please try again later.")]
    InternalServerError,

    #[error("User with email {0} not found.")]
    UserNotFound(String),
}

impl IntoResponse for LoginError {
    fn into_response(self) -> axum::response::Response {
        let status = match self {
            LoginError::Json(_) => StatusCode::BAD_REQUEST,
            LoginError::InvalidEmail => StatusCode::UNPROCESSABLE_ENTITY,
            LoginError::InvalidPassword => StatusCode::UNPROCESSABLE_ENTITY,
            LoginError::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
            LoginError::UserNotFound(_) => StatusCode::UNAUTHORIZED,
        };

        (status, self.to_string()).into_response()
    }
}
