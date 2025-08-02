use std::collections::HashMap;
use std::hash::Hash;

use crate::domain::email::Email;
use crate::domain::Password;
use crate::domain::User;
use crate::domain::data_stores::UserStoreError;
use crate::domain::data_stores::UserStore;

pub struct HashmapUserStore {
    users: HashMap<Email, User>,
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

    async fn get_user(&self, email: Email) -> Result<&User, UserStoreError> {
        self.users.get(&email).ok_or(UserStoreError::UserNotFound)
    }

    async fn delete_user(&mut self, email: Email) -> Result<User, UserStoreError> {
        self.users.remove(&email).ok_or(UserStoreError::UserNotFound)
    }

    async fn validate_user(&self, email: Email, password: Password) -> Result<bool, UserStoreError> {
        if let Some(user) = self.get_user(email.clone()).await.ok() {
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
        let user = User::new(Email::parse("lads@tst.com".to_string()).unwrap(), Password::parse("Lads123!".to_string()).unwrap(), false);
        let result = hashmap_user_store.add_user(user).await;
        assert_eq!(Ok(()), result);
        assert_eq!(1 as usize, hashmap_user_store.get_user_count());
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut hashmap_user_store = HashmapUserStore::new();
        let user = User::new(Email::parse("lads@tst.com".to_string()).unwrap(), Password::parse("Lads123!".to_string()).unwrap(), false);
        let user_validation = User::new(Email::parse("lads@tst.com".to_string()).unwrap(), Password::parse("Lads123!".to_string()).unwrap(), false);
        let _ = hashmap_user_store.add_user(user).await;
        let retrieved_user = hashmap_user_store.get_user(Email::parse("lads@tst.com".to_string()).unwrap()).await;
        assert_eq!(Ok(&user_validation), retrieved_user);
    }

    #[tokio::test]
    async fn test_delete_user() {
        let mut hashmap_user_store = HashmapUserStore::new();
        let user = User::new(Email::parse("lads@tst.com".to_string()).unwrap(), Password::parse("Lads123!".to_string()).unwrap(), false);
        let user_validation = User::new(Email::parse("lads@tst.com".to_string()).unwrap(), Password::parse("Lads123!".to_string()).unwrap(), false);
        let _ = hashmap_user_store.add_user(user).await;
        let retrieved_user = hashmap_user_store.delete_user(Email::parse("lads@tst.com".to_string()).unwrap()).await;
        assert_eq!(Ok(user_validation), retrieved_user);
        assert_eq!(0 as usize, hashmap_user_store.get_user_count());
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut hashmap_user_store = HashmapUserStore::new();
        let user = User::new(Email::parse("lads@tst.com".to_string()).unwrap(), Password::parse("Lads123!".to_string()).unwrap(), false);
        let _ = hashmap_user_store.add_user(user).await;
        assert_eq!(Ok(true), hashmap_user_store.validate_user(Email::parse("lads@tst.com".to_string()).unwrap(), Password::parse("Lads123!".to_string()).unwrap()).await);
    }
}