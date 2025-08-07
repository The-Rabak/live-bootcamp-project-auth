use crate::helpers::TestApp;
use serial_test::serial;

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;
    let jwt = String::from("malformed_jwt");
    let response = app.verify_token(jwt).await;

    assert_eq!(response.status().as_u16(), 422);
}

#[tokio::test]
async fn should_return_200_valid_token() {
    todo!()
}

#[tokio::test]
#[serial]
async fn should_return_401_if_invalid_token() {
    use std::env;

    // Save the current environment variable state
    let original_ttl = env::var("TOKEN_TTL_SECONDS").ok();

    // Set a very short TTL for this test (1 second)
    env::set_var("TOKEN_TTL_SECONDS", "1");

    let app = TestApp::new().await;
    let email = auth_service::domain::email::Email::parse("test@example.com".to_owned()).unwrap();

    // Generate a token that will expire in 1 second
    let token = auth_service::utils::auth::generate_auth_token(&email).unwrap();

    // Wait for the token to expire
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let response = app.verify_token(token).await;
    assert_eq!(response.status().as_u16(), 401);

    // Restore original environment variable
    match original_ttl {
        Some(val) => env::set_var("TOKEN_TTL_SECONDS", val),
        None => env::remove_var("TOKEN_TTL_SECONDS"),
    }
}
