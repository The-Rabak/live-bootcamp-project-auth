use axum::http::StatusCode;
use axum::response::IntoResponse;

pub async fn delete_account() -> impl IntoResponse {
    StatusCode::OK.into_response()
}
