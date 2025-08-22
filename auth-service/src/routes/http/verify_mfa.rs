use axum::extract::State;
use axum::{http::StatusCode, Json};
use axum_extra::extract::CookieJar;

use crate::domain::{Email, LoginAttemptId, LoginResponse, TwoFACode, VerifyMFARequestBody};
use crate::errors::VerifyMfaError;
use crate::utils::cookie_helpers::{access_cookie, refresh_cookie};
use crate::AppState;

pub async fn verify_mfa(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<VerifyMFARequestBody>,
) -> Result<(CookieJar, (StatusCode, Json<LoginResponse>)), VerifyMfaError> {
    let email = Email::parse(request.email).or(Err(VerifyMfaError::InvalidEmail))?;

    let login_attempt_id = LoginAttemptId::parse(request.login_attempt_id)
        .or(Err(VerifyMfaError::InvalidLoginRequestId))?;

    let two_fa_code = TwoFACode::parse(request.mfa_code).or(Err(VerifyMfaError::InvalidMFACode))?;

    let mut twofa_token_store = state.twofa_token_store.write().await;
    let get_code = twofa_token_store.get_code(&email);

    match get_code.await {
        Ok(v) => {
            if v.0 == login_attempt_id && v.1 == two_fa_code {
                let issued = state
                    .token_service
                    .write()
                    .await
                    .issue_initial_session(email.as_ref())
                    .await
                    .map_err(|_| VerifyMfaError::InternalServerError)?;

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

                twofa_token_store
                    .remove_code(&email)
                    .await
                    .map_err(|_| VerifyMfaError::InternalServerError)?;
                Ok((
                    jar,
                    (
                        StatusCode::OK,
                        Json(LoginResponse {
                            message: "MFA verification successful".to_string(),
                        }),
                    ),
                ))
            } else {
                Err(VerifyMfaError::OldCode)
            }
        }
        Err(_) => Err(VerifyMfaError::OldCode),
    }
}
