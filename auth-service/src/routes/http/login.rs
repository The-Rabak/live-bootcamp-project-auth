use crate::app_state::AppState;
use crate::domain::{Email, LoginAttemptId, LoginRequestBody, LoginResponse, Password, TwoFACode};
use crate::errors::LoginError;
use crate::services::AuthService;
use crate::utils::cookie_helpers::{access_cookie, refresh_cookie};
use axum::extract::State;
use axum::http::StatusCode;

use axum::Json;
use axum_extra::extract::CookieJar;

use serde::{Deserialize, Serialize};

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequestBody>,
) -> Result<(CookieJar, (StatusCode, Json<LoginTypes>)), LoginError> {
    let email = Email::parse(request.email).or(Err(LoginError::InvalidEmail))?;
    let password = Password::parse(request.password).or(Err(LoginError::InvalidPassword))?;
    let user = AuthService::login(state.clone(), email.clone(), password).await?;

    match user.requires_mfa {
        // We are now passing `&user.email` and `&state` to `handle_2fa`
        true => handle_2fa_login(&user.email, &state, jar).await,
        false => handle_no_2fa_login(&user.email, &state, jar).await,
    }
}

async fn handle_2fa_login(
    email: &Email,
    state: &AppState,
    jar: CookieJar,
) -> Result<(CookieJar, (StatusCode, Json<LoginTypes>)), LoginError> {
    let login_attempt_id = LoginAttemptId::default();
    let two_fa_code = TwoFACode::default();

    state
        .twofa_token_store
        .write()
        .await
        .add_code(email.clone(), login_attempt_id.clone(), two_fa_code.clone())
        .await
        .map_err(|_| LoginError::InternalServerError)?;

    state
        .email_client
        .read()
        .await
        .send_email(email, "your 2fa code", two_fa_code.as_ref())
        .await
        .map_err(|_| LoginError::InternalServerError)?;

    // Finally, we need to return the login attempt ID to the client
    let response = Json(LoginTypes::TwoFactorAuth(TwoFactorAuthResponse {
        message: "2FA required".to_owned(),
        login_attempt_id: login_attempt_id.as_ref().to_owned(), // Add the generated login attempt ID
    }));

    Ok((jar, (StatusCode::PARTIAL_CONTENT, response)))
}

async fn handle_no_2fa_login(
    email: &Email,
    state: &AppState,
    jar: CookieJar,
) -> Result<(CookieJar, (StatusCode, Json<LoginTypes>)), LoginError> {
    let issued = state
        .token_service
        .write()
        .await
        .issue_initial_session(email.as_ref())
        .await
        .map_err(|_| LoginError::InternalServerError)?;

    let jar = {
        let config = state.config.read().await;
        jar.add(access_cookie(
            config.access_cookie_name(),
            &issued.access_token,
            config.token_ttl_seconds(),
        ))
        .add(refresh_cookie(
            config.refresh_cookie_name(),
            &issued.refresh_token,
            config.refresh_token_ttl_seconds(),
        ))
    };

    Ok((
        jar,
        (
            StatusCode::OK,
            Json(LoginTypes::RegularAuth(LoginResponse {
                message: "Logged in successfully".to_string(),
            })),
        ),
    ))
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LoginTypes {
    RegularAuth(LoginResponse),
    TwoFactorAuth(TwoFactorAuthResponse),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
}
