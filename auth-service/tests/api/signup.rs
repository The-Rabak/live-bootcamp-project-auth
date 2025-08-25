use crate::helpers::{get_random_email, TestContext};
use auth_service::domain::signup_response::SignupResponse;
use test_context::test_context;

#[test_context(TestContext)]
#[tokio::test]
async fn should_return_422_if_malformed_email(ctx: &mut TestContext) {
    let app = &ctx.test_app;

    let empty_email = String::new();
    let password = String::from("lads123!");
    let requires_mfa = true;

    let response = app.signup(empty_email, password, requires_mfa).await;
    assert_eq!(response.status().as_u16(), 422, "Invalid email");
}

#[test_context(TestContext)]
#[tokio::test]
async fn should_return_422_if_malformed_password(ctx: &mut TestContext) {
    let app = &ctx.test_app;

    let empty_email = get_random_email();
    let password = String::new();
    let requires_mfa = true;

    let response = app.signup(empty_email, password, requires_mfa).await;
    assert_eq!(response.status().as_u16(), 422, "Password is too short");
}
#[test_context(TestContext)]
#[tokio::test]
async fn should_return_201_if_fields_are_sent(ctx: &mut TestContext) {
    let app = &ctx.test_app;

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

#[test_context(TestContext)]
#[tokio::test]
async fn should_return_409_if_email_already_exists(ctx: &mut TestContext) {
    // Call the signup route twice. The second request should fail with a 409 HTTP status code
    let app = &ctx.test_app;
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
