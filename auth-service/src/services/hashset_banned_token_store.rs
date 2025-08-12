use std::collections::HashSet;

use crate::domain::data_stores::{BannedTokenStore, BannedTokenStoreErr};

pub struct HashsetBannedTokenStore {
    store: HashSet<String>,
}

impl HashsetBannedTokenStore {
    pub fn new() -> Self {
        Self {
            store: HashSet::new(),
        }
    }
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn store_token(&mut self, token: String) -> Result<(), BannedTokenStoreErr> {
        if self.store.contains(&token) {
            Err(BannedTokenStoreErr::TokenExists)
        } else {
            self.store.insert(token);
            Ok(())
        }
    }

    async fn token_exists(&self, token: &String) -> bool {
        self.store.contains(token)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_store_token() {
        let mut hashset_token_store = HashsetBannedTokenStore::new();
        let token = String::from("lads");
        let result = hashset_token_store.store_token(token.clone()).await;
        assert_eq!(Ok(()), result);
        assert_eq!(true, hashset_token_store.token_exists(&token).await);
    }

    #[tokio::test]
    async fn test_not_storing_existing_tokens() {
        let mut hashset_token_store = HashsetBannedTokenStore::new();
        let token = String::from("lads");
        let result = hashset_token_store.store_token(token.clone()).await;
        assert_eq!(Ok(()), result);

        //trying to store the token again
        let result = hashset_token_store.store_token(token).await;
        assert_eq!(Err(BannedTokenStoreErr::TokenExists), result);
    }
}
