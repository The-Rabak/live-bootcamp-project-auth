use crate::helpers::{get_random_email, TestApp};
use auth_service::utils::consts::JWT_COOKIE_NAME;

#[tokio::test]
async fn should_return_422_if_malformed_email() {
    let app = TestApp::new().await;
    let email = "".to_string(); // Empty email
    let password = String::from("Lads123!");

    let response = app.login(email, password).await;

    assert_eq!(response.status().as_u16(), 422);
}

#[tokio::test]
async fn should_return_422_if_malformed_password() {
    let app = TestApp::new().await;
    let email = get_random_email();
    // Empty password
    let password = String::from("");

    let response = app.login(email, password).await;

    assert_eq!(response.status().as_u16(), 422);
}

#[tokio::test]
async fn should_return_401_if_user_not_found() {
    let app = TestApp::new().await;
    let email = get_random_email();
    let password = String::from("Lads123!");
    let response = app.login(email, password).await;
    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let app = TestApp::new().await;

    let random_email = get_random_email();
    let password = "Password123!".to_string();
    let requires_mfa = false;

    let response = app.signup(random_email.clone(), password.clone(), requires_mfa).await;

    assert_eq!(response.status().as_u16(), 201);

    let response = app.login(random_email.clone(), password.clone()).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());
}