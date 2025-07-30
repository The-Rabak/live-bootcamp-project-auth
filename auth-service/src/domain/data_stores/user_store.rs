use crate::domain::User;
use super::UserStoreError;

#[async_trait::async_trait]
pub trait UserStore: Send + Sync {

    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, username: &str) -> Result<&User, UserStoreError>;
    async fn validate_user(&self, username: &str, password: &str) -> Result<bool, UserStoreError>;
}