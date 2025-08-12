use blake3;
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use super::{RefreshError, RefreshRecord};

pub trait RefreshStore {
    fn insert_initial(&mut self, record: RefreshRecord) -> Result<(), RefreshError>;
    fn rotate(
        &mut self,
        presented_plain: &str,
        new_plain: &str,
        now: DateTime<Utc>,
        ttl: Duration,
        hash_key: &[u8; 32],
    ) -> Result<(RefreshRecord, RefreshRecord), RefreshError>;

    fn revoke_session(&mut self, session_id: Uuid, now: DateTime<Utc>);

    fn revoke_session_internal(&mut self, session_id: Uuid, now: DateTime<Utc>);

    fn is_session_revoked(&self, session_id: Uuid) -> bool;
}

pub fn hash_refresh(key32: &[u8; 32], token: &str) -> [u8; 32] {
    let out = blake3::keyed_hash(key32, token.as_bytes());
    *out.as_bytes()
}
