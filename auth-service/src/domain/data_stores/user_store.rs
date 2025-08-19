use super::UserStoreError;
use crate::domain::{Email, Password, User};

#[async_trait::async_trait]
pub trait UserStore: Send + Sync {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, username: Email) -> Result<&User, UserStoreError>;
    async fn delete_user(&mut self, username: Email) -> Result<User, UserStoreError>;
    async fn validate_user(
        &self,
        username: Email,
        password: Password,
    ) -> Result<User, UserStoreError>;
}
