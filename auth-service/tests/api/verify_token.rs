use crate::helpers::TestApp;

#[tokio::test]
async fn verify_token_success() {
    let app = TestApp::new().await;
    let jwt = String::from("jwt");
    let response = app.verify_token(jwt).await;

    assert_eq!(response.status().as_u16(), 200);
}
