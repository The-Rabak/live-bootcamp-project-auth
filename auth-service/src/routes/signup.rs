use axum::{http::StatusCode, response::IntoResponse, Json};
use crate::dtos::SignupRequestBody;

pub async fn signup(Json(request): Json<SignupRequestBody>) -> impl IntoResponse {
    StatusCode::CREATED.into_response()
}