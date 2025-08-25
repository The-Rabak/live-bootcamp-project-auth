use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::domain::AsRedisHashArgs;

/// Strongly typed wrapper for a 32-byte token hash.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct TokenHash(pub [u8; 32]);

impl TokenHash {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        TokenHash(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
    pub fn from_hex(s: &str) -> Result<Self, String> {
        let raw = hex::decode(s).map_err(|e| format!("invalid token hash hex: {e}"))?;
        if raw.len() != 32 {
            return Err("token hash must be 32 bytes".into());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw);
        Ok(TokenHash(arr))
    }
    pub fn redis_key(&self) -> String {
        format!("refresh_token:{}", self.to_hex())
    }
}

#[derive(Clone, Debug)]
pub struct RefreshRecord {
    pub token_hash: [u8; 32],
    pub user_id: String,
    pub session_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub parent_hash: Option<[u8; 32]>,
    pub replaced_by_hash: Option<[u8; 32]>,
    pub used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl AsRedisHashArgs for RefreshRecord {
    fn as_redis_hash_args(&self) -> Vec<(String, String)> {
        // Pre-calculate capacity: 5 required + each optional if present
        let mut fields = Vec::with_capacity(
            5 + (self.parent_hash.is_some() as usize)
                + (self.replaced_by_hash.is_some() as usize)
                + (self.used_at.is_some() as usize)
                + (self.revoked_at.is_some() as usize),
        );

        // Required fields (use static field names to avoid reallocating the name)
        fields.push(("token_hash".into(), hex::encode(self.token_hash)));
        fields.push(("user_id".into(), self.user_id.clone()));
        fields.push(("session_id".into(), self.session_id.to_string()));
        fields.push(("created_at".into(), self.created_at.timestamp().to_string()));
        fields.push(("expires_at".into(), self.expires_at.timestamp().to_string()));

        // Optional fields
        if let Some(parent_hash) = self.parent_hash {
            fields.push(("parent_hash".into(), hex::encode(parent_hash)));
        }
        if let Some(replaced_by_hash) = self.replaced_by_hash {
            fields.push(("replaced_by_hash".into(), hex::encode(replaced_by_hash)));
        }
        if let Some(used_at) = self.used_at {
            fields.push(("used_at".into(), used_at.timestamp().to_string()));
        }
        if let Some(revoked_at) = self.revoked_at {
            fields.push(("revoked_at".into(), revoked_at.timestamp().to_string()));
        }

        fields
    }
}

impl RefreshRecord {
    /// Reconstruct a RefreshRecord from Redis hash fields
    pub fn from_redis_hash(fields: Vec<(String, String)>) -> Result<Self, String> {
        let mut token_hash: Option<[u8; 32]> = None;
        let mut user_id: Option<String> = None;
        let mut session_id: Option<Uuid> = None;
        let mut created_at: Option<DateTime<Utc>> = None;
        let mut expires_at: Option<DateTime<Utc>> = None;
        let mut parent_hash: Option<[u8; 32]> = None;
        let mut replaced_by_hash: Option<[u8; 32]> = None;
        let mut used_at: Option<DateTime<Utc>> = None;
        let mut revoked_at: Option<DateTime<Utc>> = None;

        for (key, value) in fields {
            match key.as_str() {
                "token_hash" => {
                    let th = TokenHash::from_hex(&value)
                        .map_err(|e| format!("Invalid token_hash hex: {}", e))?;
                    token_hash = Some(th.0);
                }
                "user_id" => user_id = Some(value),
                "session_id" => {
                    session_id = Some(
                        Uuid::parse_str(&value)
                            .map_err(|e| format!("Invalid session_id UUID: {}", e))?,
                    );
                }
                "created_at" => {
                    let timestamp: i64 = value
                        .parse()
                        .map_err(|e| format!("Invalid created_at timestamp: {}", e))?;
                    created_at = Some(
                        DateTime::from_timestamp(timestamp, 0)
                            .ok_or("Invalid created_at timestamp")?,
                    );
                }
                "expires_at" => {
                    let timestamp: i64 = value
                        .parse()
                        .map_err(|e| format!("Invalid expires_at timestamp: {}", e))?;
                    expires_at = Some(
                        DateTime::from_timestamp(timestamp, 0)
                            .ok_or("Invalid expires_at timestamp")?,
                    );
                }
                "parent_hash" => {
                    let th = TokenHash::from_hex(&value)
                        .map_err(|e| format!("Invalid parent_hash hex: {}", e))?;
                    parent_hash = Some(th.0);
                }
                "replaced_by_hash" => {
                    let th = TokenHash::from_hex(&value)
                        .map_err(|e| format!("Invalid replaced_by_hash hex: {}", e))?;
                    replaced_by_hash = Some(th.0);
                }
                "used_at" => {
                    let timestamp: i64 = value
                        .parse()
                        .map_err(|e| format!("Invalid used_at timestamp: {}", e))?;
                    used_at = Some(
                        DateTime::from_timestamp(timestamp, 0)
                            .ok_or("Invalid used_at timestamp")?,
                    );
                }
                "revoked_at" => {
                    let timestamp: i64 = value
                        .parse()
                        .map_err(|e| format!("Invalid revoked_at timestamp: {}", e))?;
                    revoked_at = Some(
                        DateTime::from_timestamp(timestamp, 0)
                            .ok_or("Invalid revoked_at timestamp")?,
                    );
                }
                _ => { /* ignore unknown */ }
            }
        }

        // Ensure required fields are present
        let token_hash = token_hash.ok_or("Missing required field: token_hash")?;
        let user_id = user_id.ok_or("Missing required field: user_id")?;
        let session_id = session_id.ok_or("Missing required field: session_id")?;
        let created_at = created_at.ok_or("Missing required field: created_at")?;
        let expires_at = expires_at.ok_or("Missing required field: expires_at")?;

        Ok(RefreshRecord {
            token_hash,
            user_id,
            session_id,
            created_at,
            expires_at,
            parent_hash,
            replaced_by_hash,
            used_at,
            revoked_at,
        })
    }

    /// Generate the Redis key for this record
    pub fn get_redis_key(&self) -> String {
        TokenHash(self.token_hash).redis_key()
    }

    /// Generate a Redis key from a token hash
    pub fn redis_key_from_hash(token_hash: &[u8; 32]) -> String {
        TokenHash(*token_hash).redis_key()
    }
}
