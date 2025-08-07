use auth_service::{
    domain::Email, errors::LogoutError, utils::consts::JWT_COOKIE_NAME, utils::generate_auth_cookie,
};

use reqwest::{cookie::CookieStore, Url};

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_400_if_jwt_cookie_missing() {
    let app = TestApp::new().await;

    let response = app.logout().await;
    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;

    // add invalid cookie
    app.cookie_jar.add_cookie_str(
        &format!(
            "{}=invalid; HttpOnly; SameSite=Lax; Secure; Path=/",
            JWT_COOKIE_NAME
        ),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.logout().await;
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn should_return_200_if_valid_jwt_cookie() {
    let app = TestApp::new().await;
    let random_email = get_random_email();
    // add invalid cookie
    app.cookie_jar.add_cookie_str(
        &format!(
            "{}, sameSite=Lax; httpOnly; path=/",
            generate_auth_cookie(&Email::parse(random_email).unwrap()).unwrap()
        ),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.logout().await;
    assert_eq!(response.status(), 200);
}

// #[tokio::test]
// async fn should_return_400_if_logout_called_twice_in_a_row() {
//     let app = TestApp::new().await;
//     let random_email = get_random_email();
//     // add invalid cookie
//     app.cookie_jar.add_cookie_str(
//         &format!(
//             "{}, sameSite=Lax; httpOnly; path=/",
//             generate_auth_cookie(&Email::parse(random_email).unwrap()).unwrap()
//         ),
//         &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
//     );

//     let response = app.logout().await;
//     assert_eq!(response.status(), 200);

//     let second_logout_response = app.logout().await;
//     // by now the cookie should be deleted and therefore cannot be validated again
//     assert_eq!(second_logout_response.status(), 400);
// }
