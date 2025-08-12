use chrono::{DateTime, Utc};
use uuid::Uuid;

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
