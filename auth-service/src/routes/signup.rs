use axum::{http::StatusCode, response::IntoResponse, Json};
use axum::extract::State;
use crate::app_state::AppState;
use crate::domain::{SignupRequestBody, SignupResponse, User};
use crate::errors::SignupError;
use crate::validation::is_valid_email;
use crate::domain::data_stores::UserStoreError;

pub async fn signup(State(state): State<AppState>, Json(request): Json<SignupRequestBody>)
                    -> Result<impl IntoResponse, SignupError> {

    if !is_valid_email(&request.email) {
        return Err(SignupError::InvalidEmail);
    }

    // validate password length
    let min_len = 8;
    if request.password.len() < min_len {
        return Err(SignupError::PasswordTooShort(min_len));
    }

    let mut user_store = state.user_store.write().await;

    let _user = user_store.add_user(
        User::new(request.email.clone(), request.password.clone(), request.requires_mfa)
    ).await.map_err(|e| {
        match e {
            UserStoreError::UserAlreadyExists => SignupError::UserAlreadyExists(request.email.clone()),
            _ => SignupError::InternalServerError,
        }
    })?;

     let response = Json(SignupResponse {
        message: "User created successfully!".to_string(),
    });

    Ok((StatusCode::CREATED, response))
}