use std::sync::Arc;
use tokio::sync::RwLock;

use crate::domain::UserStore;
use crate::services::TokenService;
use crate::utils::Config;

// Using a type alias to improve readability!
pub type UserStoreType = Arc<RwLock<dyn UserStore>>;
pub type TokenServiceType = Arc<RwLock<TokenService>>;
pub type ConfigType = Arc<RwLock<Config>>;

#[derive(Clone)]
pub struct AppState {
    pub user_store: UserStoreType,
    pub token_service: TokenServiceType,
    pub config: ConfigType,
}

impl AppState {
    pub fn new(
        user_store: UserStoreType,
        token_service: TokenServiceType,
        config: ConfigType,
    ) -> Self {
        Self {
            user_store,
            token_service,
            config,
        }
    }
}
