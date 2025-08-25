use crate::helpers::{get_random_email, TestContext};
use auth_service::routes::TwoFactorAuthResponse;
use test_context::test_context;

#[test_context(TestContext)]
#[tokio::test]
async fn should_return_422_if_malformed_email(ctx: &mut TestContext) {
    let app = &ctx.test_app;
    let email = "".to_string(); // Empty email
    let password = String::from("Lads123!");

    let response = app.login(email, password).await;

    assert_eq!(response.status().as_u16(), 422);
}

#[test_context(TestContext)]
#[tokio::test]
async fn should_return_422_if_malformed_password(ctx: &mut TestContext) {
    let app = &ctx.test_app;
    let email = get_random_email();
    // Empty password
    let password = String::from("");

    let response = app.login(email, password).await;

    assert_eq!(response.status().as_u16(), 422);
}

#[test_context(TestContext)]
#[tokio::test]
async fn should_return_401_if_user_not_found(ctx: &mut TestContext) {
    let app = &ctx.test_app;
    let email = get_random_email();
    let password = String::from("Lads123!");
    let response = app.login(email, password).await;
    assert_eq!(response.status().as_u16(), 401);
}

#[test_context(TestContext)]
#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled(ctx: &mut TestContext) {
    let app = &ctx.test_app;

    let random_email = get_random_email();
    let password = "Password123!".to_string();
    let requires_mfa = false;

    let response = app
        .signup(random_email.clone(), password.clone(), requires_mfa)
        .await;

    assert_eq!(response.status().as_u16(), 201);

    let response = app.login(random_email.clone(), password.clone()).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == "access_token")
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());
}

#[test_context(TestContext)]
#[tokio::test]
async fn should_return_206_if_valid_credentials_and_2fa_enabled(ctx: &mut TestContext) {
    let app = &ctx.test_app;

    let random_email = get_random_email();
    let password = "Password123!".to_string();
    let requires_mfa = true;

    let response = app
        .signup(random_email.clone(), password.clone(), requires_mfa)
        .await;

    assert_eq!(response.status().as_u16(), 201);

    let response = app.login(random_email.clone(), password.clone()).await;
    assert_eq!(response.status().as_u16(), 206);
    assert_eq!(
        response
            .json::<TwoFactorAuthResponse>()
            .await
            .expect("Could not deserialize response body to TwoFactorAuthResponse")
            .message,
        "2FA required".to_owned()
    );
}
