use super::BannedTokenStoreErr;

#[async_trait::async_trait]
pub trait BannedTokenStore: Send + Sync {
    async fn store_token(&mut self, token: String) -> Result<(), BannedTokenStoreErr>;
    async fn token_exists(&self, token: &String) -> bool;
}
