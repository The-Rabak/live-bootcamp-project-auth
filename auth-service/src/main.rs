use auth_service::app_state::AppState;
use auth_service::migrations;
use auth_service::services::hashmap_user_store::HashmapUserStore;
use auth_service::services::{
    HashmapTwoFACodeStore, HashsetRefreshStore, MockEmailClient, SqlUserStore, TokenService,
};
use auth_service::utils::Config;
use auth_service::{get_db_pool, Application};
use std::sync::Arc;
use tokio::sync::RwLock;
use welds::connections::any::AnyClient;

#[tokio::main]
async fn main() {
    env_logger::init();
    let config = Arc::new(RwLock::new(
        Config::default().expect("Failed to load config"),
    ));
    let token_service = Arc::new(RwLock::new(
        TokenService::new(config.clone(), Box::new(HashsetRefreshStore::default())).await,
    ));
    let twofa_code_store = Arc::new(RwLock::new(HashmapTwoFACodeStore::default()));
    let email_client = Arc::new(RwLock::new(MockEmailClient::default()));
    let db_client = get_configured_db_connection(config.read().await.db_url()).await;
    let user_store = SqlUserStore::new(db_client.clone());
    let app_state = AppState::new(
        Arc::new(RwLock::new(user_store)),
        token_service,
        config.clone(),
        twofa_code_store,
        email_client,
        db_client,
    );
    let app = Application::build(app_state, "0.0.0.0:3000", "0.0.0.0:50051")
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}

async fn get_configured_db_connection(db_url: &str) -> AnyClient {
    let db_client = get_db_pool(db_url).await.unwrap();
    //log the migration error to tracing layer
    let _ = migrations::up(&db_client).await;
    db_client
}
