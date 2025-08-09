use crate::helpers::{get_random_email, TestApp};
use auth_service::{domain::email::Email, utils::auth::generate_auth_token};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;
    let jwt = String::from("malformed_jwt");
    let response = app.verify_token(jwt).await;

    assert_eq!(response.status().as_u16(), 422);
}

#[tokio::test]
async fn should_return_200_valid_token() {
    let app = TestApp::new().await;
    let email = Email::parse(get_random_email()).unwrap();

    let config = app.config.read().await;
    let token = generate_auth_token(&email, &config).unwrap();

    //first validation should work
    let response = app.verify_token(token.clone()).await;
    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;
    let email = Email::parse(get_random_email()).unwrap();

    // Generate a token that will expire in 1 second
    // We need to modify the config for this test to have a short TTL
    {
        let mut config = app.config.write().await;
        config.set_token_ttl_seconds(1);
    }

    let config = app.config.read().await;
    let token = generate_auth_token(&email, &config).unwrap();

    // Wait for the token to expire
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let response = app.verify_token(token).await;
    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_401_if_banned_token() {
    let app = TestApp::new().await;
    let email = Email::parse(get_random_email()).unwrap();

    let config = app.config.read().await;
    let token = generate_auth_token(&email, &config).unwrap();

    //first validation should work
    let response = app.verify_token(token.clone()).await;
    assert_eq!(response.status().as_u16(), 200);

    //token is now in banned token store and thus the second verification should fail
    let response = app.verify_token(token).await;
    assert_eq!(response.status().as_u16(), 401);
}
