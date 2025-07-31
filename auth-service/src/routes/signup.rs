use axum::{http::StatusCode, response::IntoResponse, Json};
use axum::extract::State;
use crate::app_state::AppState;
use crate::domain::email::Email;
use crate::domain::{Password, SignupRequestBody, SignupResponse, User};
use crate::errors::SignupError;
use crate::validation::is_valid_email;
use crate::domain::data_stores::UserStoreError;

pub async fn signup(State(state): State<AppState>, Json(request): Json<SignupRequestBody>)
                    -> Result<impl IntoResponse, SignupError> {

    if !is_valid_email(&request.email) {
        return Err(SignupError::InvalidEmail);
    }

    let email = Email::parse(request.email).or(Err(SignupError::InvalidEmail))?;
    let password = Password::parse(request.password).or(Err(SignupError::InvalidPassword))?;

    let mut user_store = state.user_store.write().await;


    let _user = user_store.add_user(User::new(email.clone(), password, request.requires_mfa)).await.map_err(|e| {
        match e {
            UserStoreError::UserAlreadyExists => SignupError::UserAlreadyExists(email.as_ref().to_string()),
            _ => SignupError::InternalServerError,
        }
    })?;

     let response = Json(SignupResponse {
        message: "User created successfully!".to_string(),
    });

    Ok((StatusCode::CREATED, response))
}