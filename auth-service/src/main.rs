use auth_service::app_state::AppState;
use auth_service::services::hashmap_user_store::HashmapUserStore;
use auth_service::services::{HashmapTwoFACodeStore, HashsetRefreshStore, TokenService};
use auth_service::utils::Config;
use auth_service::Application;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    env_logger::init();
    let user_store = HashmapUserStore::new();
    let config = Arc::new(RwLock::new(
        Config::default().expect("Failed to load config"),
    ));
    let token_service = Arc::new(RwLock::new(
        TokenService::new(config.clone(), Box::new(HashsetRefreshStore::default())).await,
    ));
    let twofa_code_store = Arc::new(RwLock::new(HashmapTwoFACodeStore::default()));
    let app_state = AppState::new(
        Arc::new(RwLock::new(user_store)),
        token_service,
        config.clone(),
        twofa_code_store,
    );
    let app = Application::build(app_state, "0.0.0.0:3000", "0.0.0.0:50051")
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
