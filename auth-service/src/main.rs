use auth_service::app_state::AppState;
use auth_service::services::{
    hashmap_user_store::HashmapUserStore, hashset_banned_token_store::HashsetBannedTokenStore,
};
use auth_service::utils::Config;
use auth_service::Application;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    env_logger::init();
    let user_store = HashmapUserStore::new();
    let banned_token_store = HashsetBannedTokenStore::new();
    let config = Config::default();
    let app_state = AppState::new(
        Arc::new(RwLock::new(user_store)),
        Arc::new(RwLock::new(banned_token_store)),
        Arc::new(RwLock::new(config)),
    );
    let app = Application::build(app_state, "0.0.0.0:3000", "0.0.0.0:50051")
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
