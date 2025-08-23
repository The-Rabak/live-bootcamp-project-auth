use crate::helpers::{get_random_email, TestApp, TestContext};
use auth_service::domain::LoginResponse;
use auth_service::routes::TwoFactorAuthResponse;
use test_context::test_context;

#[test_context(TestContext)]
#[tokio::test]
async fn should_return_401_if_old_code(ctx: &mut TestContext) {
    // Call login twice. Then, attempt to call verify-fa with the 2FA code from the first login requet. This should fail.
    let app = &ctx.test_app;
    let email = get_random_email();
    let password = "Password123!".to_string();
    let requires_mfa = true;

    // First, sign up a user with 2FA enabled
    let response = app
        .signup(email.clone(), password.clone(), requires_mfa)
        .await;
    assert_eq!(response.status().as_u16(), 201);

    // First login - this will generate a 2FA code
    let login_response_1 = app.login(email.clone(), password.clone()).await;
    assert_eq!(login_response_1.status().as_u16(), 206, "first assert");

    let first_login_response = login_response_1
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    let first_login_attempt_id = first_login_response.login_attempt_id;

    // Get the first 2FA code from the store
    let first_2fa_code = {
        let email_parsed = auth_service::domain::Email::parse(email.clone()).unwrap();
        let store = app.twofa_code_store.read().await;
        let (_, code) = store.get_code(&email_parsed).await.unwrap();
        code.as_ref().to_string()
    };

    // Second login - this will generate a new 2FA code and overwrite the first one
    let login_response_2 = app.login(email.clone(), password.clone()).await;
    let login_response_2_status = login_response_2.status().as_u16();
    let login_response_2_body = login_response_2.text().await.unwrap();
    assert_eq!(login_response_2_status, 206, "second assert");

    // Now try to verify 2FA with the old code from the first login
    let verify_response = app
        .verify_mfa(email.clone(), first_login_attempt_id, first_2fa_code)
        .await;

    assert_eq!(verify_response.status().as_u16(), 401);
}

#[test_context(TestContext)]
#[tokio::test]
async fn should_return_401_if_incorrect_credentials(ctx: &mut TestContext) {
    let app = &ctx.test_app;
    let email = get_random_email();
    let login_attempt_id = String::from("lads1");
    let mfa_code = String::from("mfa");
    let response = app.verify_mfa(email, login_attempt_id, mfa_code).await;

    assert_eq!(response.status().as_u16(), 401);
}

#[test_context(TestContext)]
#[tokio::test]
async fn should_return_200_if_correct_code(ctx: &mut TestContext) {
    // Make sure to assert the auth cookie gets set
    let app = &ctx.test_app;
    let email = get_random_email();
    let password = "Password123!".to_string();
    let requires_mfa = true;

    // First, sign up a user with 2FA enabled
    let response = app
        .signup(email.clone(), password.clone(), requires_mfa)
        .await;
    assert_eq!(response.status().as_u16(), 201);

    // Login to get the 2FA challenge
    let login_response = app.login(email.clone(), password.clone()).await;
    assert_eq!(login_response.status().as_u16(), 206);

    let two_factor_response = login_response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    let login_attempt_id = two_factor_response.login_attempt_id;

    // Get the 2FA code from the store
    let mfa_code = {
        let email_parsed = auth_service::domain::Email::parse(email.clone()).unwrap();
        let store = app.twofa_code_store.read().await;
        let (_, code) = store.get_code(&email_parsed).await.unwrap();
        code.as_ref().to_string()
    };

    // Verify 2FA with the correct code
    let verify_response = app
        .verify_mfa(email.clone(), login_attempt_id, mfa_code)
        .await;

    assert_eq!(verify_response.status().as_u16(), 200);

    // Assert that the auth cookies are set
    let access_cookie = verify_response
        .cookies()
        .find(|cookie| cookie.name() == "access_token")
        .expect("No access token cookie found");
    assert!(!access_cookie.value().is_empty());

    let refresh_cookie = verify_response
        .cookies()
        .find(|cookie| cookie.name() == "refresh_token")
        .expect("No refresh token cookie found");
    assert!(!refresh_cookie.value().is_empty());

    // Verify the response body
    let login_response_body = verify_response
        .json::<LoginResponse>()
        .await
        .expect("Could not deserialize response body to LoginResponse");

    assert_eq!(login_response_body.message, "MFA verification successful");
}
