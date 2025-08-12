use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;
    let jwt = String::from("malformed_jwt");

    let response = app
        .http_client
        .post(&format!("{}/verify-token", &app.address))
        .header("Authorization", format!("Bearer {}", jwt))
        .send()
        .await
        .expect("Failed to execute verify token request.");

    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_200_valid_token() {
    let app = TestApp::new().await;
    let email = get_random_email();

    let issued = app
        .token_service
        .write()
        .await
        .issue_initial_session(&email)
        .await
        .expect("Failed to issue session");

    let response = app
        .http_client
        .post(&format!("{}/verify-token", &app.address))
        .header("Authorization", format!("Bearer {}", issued.access_token))
        .send()
        .await
        .expect("Failed to execute verify token request.");

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;
    let invalid_token = "invalid.token.here";

    let response = app
        .http_client
        .post(&format!("{}/verify-token", &app.address))
        .header("Authorization", format!("Bearer {}", invalid_token))
        .send()
        .await
        .expect("Failed to execute verify token request.");

    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_401_if_revoked_session() {
    let app = TestApp::new().await;
    let email = get_random_email();

    let issued = app
        .token_service
        .write()
        .await
        .issue_initial_session(&email)
        .await
        .expect("Failed to issue session");

    // First validation should work
    let response = app
        .http_client
        .post(&format!("{}/verify-token", &app.address))
        .header("Authorization", format!("Bearer {}", issued.access_token))
        .send()
        .await
        .expect("Failed to execute verify token request.");

    assert_eq!(response.status().as_u16(), 200);

    // Logout the session to revoke it
    let session_id = issued.session_id;
    app.token_service
        .write()
        .await
        .logout_session(session_id)
        .await;

    // Second validation should fail because session is revoked
    let response = app
        .http_client
        .post(&format!("{}/verify-token", &app.address))
        .header("Authorization", format!("Bearer {}", issued.access_token))
        .send()
        .await
        .expect("Failed to execute verify token request.");

    assert_eq!(response.status().as_u16(), 401);
}
