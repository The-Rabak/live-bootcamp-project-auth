use redis::{aio::MultiplexedConnection, Client};
use redis::{AsyncCommands, ExistenceCheck, SetExpiry, SetOptions};
use std::error::Error;
use std::fmt;

// Common seconds type for Redis expirations
type Seconds = i64;

// Small helper to shorten CRUD error mapping
fn crud<E: ToString>(e: E) -> RedisServiceErr {
    RedisServiceErr::CRUDErr(e.to_string())
}

#[derive(Debug)]
pub enum RedisServiceErr {
    ConnectionErr(String),
    CRUDErr(String),
    UnexpectedErr,
}

impl fmt::Display for RedisServiceErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RedisServiceErr::ConnectionErr(str) => {
                write!(f, "error while connection to instance: {str}")
            }
            RedisServiceErr::CRUDErr(str) => write!(f, "error while performing CRUD action: {str}"),
            RedisServiceErr::UnexpectedErr => {
                write!(f, "unexpected error occured, please try again later")
            }
        }
    }
}

impl Error for RedisServiceErr {}

pub struct RedisService {
    client: Client,
}

impl RedisService {
    pub fn new(host_url: &str) -> Self {
        let formatted_url = format!("redis://{}/", host_url);
        let client = Client::open(formatted_url).expect("failed to connect to redis instance");
        Self { client }
    }

    async fn get_connection(&self) -> Result<MultiplexedConnection, RedisServiceErr> {
        self.client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| RedisServiceErr::ConnectionErr(e.to_string()))
    }

    pub async fn set_key_value(
        &self,
        key: &str,
        value: &str,
        ttl: usize,
    ) -> Result<Vec<usize>, RedisServiceErr> {
        // Clamp TTL to at least 1 second to avoid immediate expiration
        let ttl = if ttl == 0 { 1 } else { ttl };
        let mut conn = self.get_connection().await?;
        let opts = SetOptions::default()
            .conditional_set(ExistenceCheck::NX)
            .get(true)
            .with_expiration(SetExpiry::EX(ttl));
        conn.set_options(key, value, opts).await.map_err(crud)
    }

    pub async fn exists(&self, key: &str) -> Result<bool, RedisServiceErr> {
        let mut conn = self.get_connection().await?;
        conn.exists(key)
            .await
            .map_err(|_| RedisServiceErr::UnexpectedErr)
    }

    pub async fn get(&self, key: &str) -> Result<Option<String>, RedisServiceErr> {
        let mut conn = self.get_connection().await?;
        conn.get(key).await.map_err(crud)
    }

    pub async fn set_hash_multiple(
        &self,
        key: &str,
        fields: &[(String, String)],
        ttl: Option<usize>,
    ) -> Result<(), RedisServiceErr> {
        let mut conn = self.get_connection().await?;

        conn.hset_multiple::<_, _, _, ()>(key, fields)
            .await
            .map_err(crud)?;

        if let Some(ttl_seconds) = ttl {
            let ttl_seconds: Seconds = if ttl_seconds == 0 {
                1
            } else {
                ttl_seconds as Seconds
            };
            conn.expire::<_, ()>(key, ttl_seconds).await.map_err(crud)?;
        }

        Ok(())
    }

    pub async fn get_hash_all(&self, key: &str) -> Result<Vec<(String, String)>, RedisServiceErr> {
        let mut conn = self.get_connection().await?;
        conn.hgetall(key).await.map_err(crud)
    }

    // hash_exists removed; use exists() for key presence checks.

    pub async fn delete_key(&self, key: &str) -> Result<bool, RedisServiceErr> {
        let mut conn = self.get_connection().await?;
        let deleted: i32 = conn.del(key).await.map_err(crud)?;
        Ok(deleted > 0)
    }
}
