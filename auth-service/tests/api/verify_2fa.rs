use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn verify_mfa_success() {
    let app = TestApp::new().await;
    let email = get_random_email();
    let login_attempt_id = String::from("lads1");
    let mfa_code = String::from("mfa");
    let response = app.verify_mfa(email, login_attempt_id, mfa_code).await;

    assert_eq!(response.status().as_u16(), 200);
}
