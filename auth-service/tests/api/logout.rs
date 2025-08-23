use crate::helpers::{get_random_email, TestApp, TestContext};
use test_context::test_context;

#[test_context(TestContext)]
#[tokio::test]
async fn should_return_401_if_authorization_header_missing(ctx: &mut TestContext) {
    let app = &ctx.test_app;

    let response = app
        .http_client
        .post(&format!("{}/logout", &app.address))
        .send()
        .await
        .expect("Failed to execute logout request.");

    assert_eq!(response.status(), 401);
}

#[test_context(TestContext)]
#[tokio::test]
async fn should_return_401_if_invalid_token(ctx: &mut TestContext) {
    let app = &ctx.test_app;

    let response = app
        .http_client
        .post(&format!("{}/logout", &app.address))
        .header("Authorization", "Bearer invalid_token")
        .send()
        .await
        .expect("Failed to execute logout request.");

    assert_eq!(response.status(), 401);
}

#[test_context(TestContext)]
#[tokio::test]
async fn should_return_200_if_valid_token(ctx: &mut TestContext) {
    let app = &ctx.test_app;
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
        .post(&format!("{}/logout", &app.address))
        .header("Authorization", format!("Bearer {}", issued.access_token))
        .send()
        .await
        .expect("Failed to execute logout request.");

    assert_eq!(response.status(), 200);

    // Verify that the session has been logged out by trying to use the token again
    let second_response = app
        .http_client
        .post(&format!("{}/logout", &app.address))
        .header("Authorization", format!("Bearer {}", issued.access_token))
        .send()
        .await
        .expect("Failed to execute second logout request.");

    assert_eq!(second_response.status(), 401);
}

// #[tokio::test]
// async fn should_return_400_if_logout_called_twice_in_a_row() {
//     let app = TestApp::new().await;
//     let random_email = get_random_email();
//     // add invalid cookie
//     app.cookie_jar.add_cookie_str(
//         &format!(
//             "{}, sameSite=Lax; httpOnly; path=/",
//             generate_auth_cookie(&Email::parse(random_email).unwrap(), &config).unwrap()
//         ),
//         &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
//     );

//     let response = app.logout().await;
//     assert_eq!(response.status(), 200);

//     let second_logout_response = app.logout().await;
//     // by now the cookie should be deleted and therefore cannot be validated again
//     assert_eq!(second_logout_response.status(), 400);
// }
