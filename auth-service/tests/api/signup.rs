use crate::helpers::{TestApp, get_random_email};

#[tokio::test]
async fn should_return_400_if_email_empty() {
    let app = TestApp::new().await;

    let empty_email = String::new();
    let password = String::from("lads123!");
    let requires_mfa = true;

    let response = app.signup(empty_email, password, requires_mfa).await;
    assert_eq!(
        response.status().as_u16(),
        400,
        "Invalid email"
    );
}

#[tokio::test]
async fn should_return_400_if_password_empty() {
    let app = TestApp::new().await;

    let empty_email = get_random_email();
    let password = String::new();
    let requires_mfa = true;

    let response = app.signup(empty_email, password, requires_mfa).await;
    assert_eq!(
        response.status().as_u16(),
        400,
        "Password is too short"
    );
}
#[tokio::test]
async fn should_return_201_if_fields_are_sent() {
    let app = TestApp::new().await;

    let random_email = get_random_email();
    let password = String::from("ilads123!");
    let requires_mfa = true;

    let response = app.signup(random_email, password, requires_mfa).await;
    assert_eq!(
        response.status().as_u16(),
        201
    );
}