use crate::helpers::TestApp;

#[tokio::test]
async fn logout_user_success() {
    let app = TestApp::new().await;
    let jwt = String::from("jwt");
    let response = app.logout(jwt).await;

    assert_eq!(response.status().as_u16(), 200);
}
