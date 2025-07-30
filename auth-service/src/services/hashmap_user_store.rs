use std::collections::HashMap;
use std::hash::Hash;

use crate::domain::User;
use crate::domain::data_stores::UserStoreError;
use crate::domain::data_stores::UserStore;

pub struct HashmapUserStore {
    users: HashMap<String, User>,
}

impl HashmapUserStore {

    pub fn new() -> Self {
        HashmapUserStore {
            users: HashMap::new()
        }
    }

    pub fn get_user_count(&self) -> usize {
        self.users.len()
    }

}

#[async_trait::async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if let Some(user) = self.users.get(&user.email) {
            return Err(UserStoreError::UserAlreadyExists);
        }
        self.users.insert(user.email.clone(), user);
        Ok(())
    }

    async fn get_user(&self, email: &str) -> Result<&User, UserStoreError> {
        self.users.get(email).ok_or(UserStoreError::UserNotFound)
    }

    async fn validate_user(&self, email: &str, password: &str) -> Result<bool, UserStoreError> {
        if let Some(user) = self.get_user(email).await.ok() {
            if user.email == email && user.password == password {
                return Ok(true);
            }
            return Err(UserStoreError::InvalidCredentials);
        }
        Err(UserStoreError::UserNotFound)
    }

}

// TODO: Add unit tests for your `HashmapUserStore` implementation
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_add_user() {
        let mut hashmap_user_store = HashmapUserStore::new();
        let user = User::new("lads@tst.com".to_string(), "lads123!".to_string(), false);
        let result = hashmap_user_store.add_user(user).await;
        assert_eq!(Ok(()), result);
        assert_eq!(1 as usize, hashmap_user_store.get_user_count());
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut hashmap_user_store = HashmapUserStore::new();
        let user = User::new("lads@tst.com".to_string(), "lads123!".to_string(), false);
        let user_validation = User::new("lads@tst.com".to_string(), "lads123!".to_string(), false);
        let _ = hashmap_user_store.add_user(user).await;
        let retrieved_user = hashmap_user_store.get_user("lads@tst.com").await;
        assert_eq!(Ok(&user_validation), retrieved_user);
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut hashmap_user_store = HashmapUserStore::new();
        let user = User::new("lads@tst.com".to_string(), "lads123!".to_string(), false);
        let _ = hashmap_user_store.add_user(user).await;
        assert_eq!(Ok(true), hashmap_user_store.validate_user("lads@tst.com", "lads123!").await);
    }
}