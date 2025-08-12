use crate::helpers::{get_random_email, TestApp};
use auth_service::domain::signup_response::SignupResponse;

#[tokio::test]
async fn should_return_422_if_malformed_email() {
    let app = TestApp::new().await;

    let empty_email = String::new();
    let password = String::from("lads123!");
    let requires_mfa = true;

    let response = app.signup(empty_email, password, requires_mfa).await;
    assert_eq!(response.status().as_u16(), 422, "Invalid email");
}

#[tokio::test]
async fn should_return_422_if_malformed_password() {
    let app = TestApp::new().await;

    let empty_email = get_random_email();
    let password = String::new();
    let requires_mfa = true;

    let response = app.signup(empty_email, password, requires_mfa).await;
    assert_eq!(response.status().as_u16(), 422, "Password is too short");
}
#[tokio::test]
async fn should_return_201_if_fields_are_sent() {
    let app = TestApp::new().await;

    let random_email = get_random_email();
    let password = String::from("Ilads123!");
    let requires_mfa = true;

    let response = app.signup(random_email, password, requires_mfa).await;
    assert_eq!(response.status().as_u16(), 201);

    let expected_response = SignupResponse {
        message: "User created successfully!".to_owned(),
    };

    // Assert that we are getting the correct response body!
    assert_eq!(
        response
            .json::<SignupResponse>()
            .await
            .expect("Could not deserialize response body to UserBody"),
        expected_response
    );
}

#[tokio::test]
async fn should_return_409_if_email_already_exists() {
    // Call the signup route twice. The second request should fail with a 409 HTTP status code
    let app = TestApp::new().await;
    let random_email = get_random_email();
    let password = String::from("Ilads123!");

    // First signup attempt
    let response = app
        .signup(random_email.clone(), password.clone(), true)
        .await;
    assert_eq!(response.status().as_u16(), 201);

    // Second signup attempt with the same email
    let response = app.signup(random_email.clone(), password, true).await;

    let expected_response = format!("User with email {} already exists.", random_email);
    assert_eq!(response.status().as_u16(), 409);
    assert_eq!(response.text().await.unwrap(), expected_response);
}
