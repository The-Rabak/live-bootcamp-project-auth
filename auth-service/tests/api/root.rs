use crate::helpers::{TestApp, TestContext};
use test_context::test_context;

#[test_context(TestContext)]
#[tokio::test]
async fn root_returns_auth_ui(ctx: &mut TestContext) {
    let app = &ctx.test_app;

    let response = app.get_root().await;

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
}
