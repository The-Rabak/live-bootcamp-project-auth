use std::sync::Arc;
use tokio::sync::RwLock;

use crate::domain::{TwoFACodeStore, UserStore};
use crate::services::TokenService;
use crate::utils::Config;

// Using type aliases to improve readability!
pub type TwoFACodeStoreType = Arc<RwLock<dyn TwoFACodeStore>>;
pub type UserStoreType = Arc<RwLock<dyn UserStore>>;
pub type TokenServiceType = Arc<RwLock<TokenService>>;
pub type ConfigType = Arc<RwLock<Config>>;

#[derive(Clone)]
pub struct AppState {
    pub user_store: UserStoreType,
    pub token_service: TokenServiceType,
    pub config: ConfigType,
    pub twofa_token_store: TwoFACodeStoreType,
}

impl AppState {
    pub fn new(
        user_store: UserStoreType,
        token_service: TokenServiceType,
        config: ConfigType,
        twofa_token_store: TwoFACodeStoreType,
    ) -> Self {
        Self {
            user_store,
            token_service,
            config,
            twofa_token_store,
        }
    }
}
