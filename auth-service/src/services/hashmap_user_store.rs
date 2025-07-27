use std::collections::HashMap;

use crate::domain::User;

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}

pub struct HashmapUserStore {
    users: HashMap<String, User>,
}

impl HashmapUserStore {

    pub fn new() -> Self {
        HashmapUserStore {
            users: HashMap::new()
        }
    }
    pub fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if let Some(user) = self.users.get(&user.email) {
            return Err(UserStoreError::UserAlreadyExists);
        }
        self.users.insert(user.email.clone(), user);
        Ok(())
    }

    pub fn get_user(&self, email: &str) -> Option<&User> {
        self.users.get(email)
    }

    pub fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
        if let Some(user) = self.get_user(email) {
            if user.email == email && user.password == password {
                return Ok(());
            }
            return Err(UserStoreError::InvalidCredentials);
        }
        Err(UserStoreError::UserNotFound)
    }

    pub fn get_user_count(&self) -> usize {
        self.users.len()
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
        let result = hashmap_user_store.add_user(user);
        assert_eq!(Ok(()), result);
        assert_eq!(1 as usize, hashmap_user_store.get_user_count());
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut hashmap_user_store = HashmapUserStore::new();
        let user = User::new("lads@tst.com".to_string(), "lads123!".to_string(), false);
        let user_validation = User::new("lads@tst.com".to_string(), "lads123!".to_string(), false);
        let _ = hashmap_user_store.add_user(user);
        let retrieved_user = hashmap_user_store.get_user("lads@tst.com");
        assert_eq!(Some(&user_validation), retrieved_user);
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut hashmap_user_store = HashmapUserStore::new();
        let user = User::new("lads@tst.com".to_string(), "lads123!".to_string(), false);
        let _ = hashmap_user_store.add_user(user);
        assert_eq!(Ok(()), hashmap_user_store.validate_user("lads@tst.com", "lads123!"));
    }
}