use std::sync::Arc;
use tokio::sync::RwLock;
use welds::connections::any::AnyClient;

use crate::domain::{EmailClient, TwoFACodeStore, UserStore};
use crate::services::TokenService;
use crate::utils::Config;

// Using type aliases to improve readability!
pub type TwoFACodeStoreType = Arc<RwLock<dyn TwoFACodeStore>>;
pub type UserStoreType = Arc<RwLock<dyn UserStore>>;
pub type TokenServiceType = Arc<RwLock<TokenService>>;
pub type ConfigType = Arc<RwLock<Config>>;
pub type EmailClientType = Arc<RwLock<dyn EmailClient>>;

#[derive(Clone)]
pub struct AppState {
    pub user_store: UserStoreType,
    pub token_service: TokenServiceType,
    pub config: ConfigType,
    pub twofa_token_store: TwoFACodeStoreType,
    pub email_client: EmailClientType,
    pub db_client: AnyClient,
}

impl AppState {
    pub fn new(
        user_store: UserStoreType,
        token_service: TokenServiceType,
        config: ConfigType,
        twofa_token_store: TwoFACodeStoreType,
        email_client: EmailClientType,
        db_client: AnyClient,
    ) -> Self {
        Self {
            user_store,
            token_service,
            config,
            twofa_token_store,
            email_client,
            db_client,
        }
    }
}
