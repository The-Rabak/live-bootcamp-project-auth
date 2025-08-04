use axum::http::StatusCode;
use axum::response::IntoResponse;

pub async fn verify_mfa() -> impl IntoResponse {
    StatusCode::OK.into_response()
}
