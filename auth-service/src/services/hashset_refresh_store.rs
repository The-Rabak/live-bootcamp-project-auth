use chrono::{DateTime, Duration, Utc};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use crate::domain::{hash_refresh, RefreshError, RefreshRecord, RefreshStore};

#[derive(Default)]
pub struct HashsetRefreshStore {
    // hash -> record
    by_hash: HashMap<[u8; 32], RefreshRecord>,
    // quick check for revoked sessions
    revoked_sessions: HashSet<Uuid>,
}

impl RefreshStore for HashsetRefreshStore {
    fn insert_initial(&mut self, record: RefreshRecord) -> Result<(), RefreshError> {
        if self.by_hash.contains_key(&record.token_hash) {
            return Err(RefreshError::Internal);
        }
        self.by_hash.insert(record.token_hash, record);
        Ok(())
    }

    fn rotate(
        &mut self,
        presented_plain: &str,
        new_plain: &str,
        now: DateTime<Utc>,
        ttl: Duration,
        hash_key: &[u8; 32],
    ) -> Result<(RefreshRecord, RefreshRecord), RefreshError> {
        let old_hash = hash_refresh(hash_key, presented_plain);
        let new_hash = hash_refresh(hash_key, new_plain);

        let mut old = match self.by_hash.get(&old_hash) {
            Some(r) => r.clone(),
            None => return Err(RefreshError::NotFoundOrExpired),
        };

        if old.expires_at <= now {
            return Err(RefreshError::NotFoundOrExpired);
        }
        if old.revoked_at.is_some() || self.revoked_sessions.contains(&old.session_id) {
            return Err(RefreshError::Revoked);
        }
        if old.replaced_by_hash.is_some() || old.used_at.is_some() {
            // Reuse: someone presented an already-used refresh token.
            self.revoke_session_internal(old.session_id, now);
            return Err(RefreshError::ReuseDetected);
        }

        // Mark the old as used and replaced-by.
        old.used_at = Some(now);
        old.replaced_by_hash = Some(new_hash);

        let new_record = RefreshRecord {
            token_hash: new_hash,
            user_id: old.user_id.clone(),
            session_id: old.session_id,
            created_at: now,
            expires_at: now + ttl,
            parent_hash: Some(old_hash),
            replaced_by_hash: None,
            used_at: None,
            revoked_at: None,
        };

        self.by_hash.insert(new_hash, new_record.clone());
        Ok((old, new_record))
    }

    fn revoke_session(&mut self, session_id: Uuid, now: DateTime<Utc>) {
        self.revoke_session_internal(session_id, now);
    }

    fn revoke_session_internal(&mut self, session_id: Uuid, now: DateTime<Utc>) {
        self.revoked_sessions.insert(session_id);
        for r in self.by_hash.values_mut() {
            if r.session_id == session_id && r.revoked_at.is_none() {
                r.revoked_at = Some(now);
            }
        }
    }

    fn is_session_revoked(&self, session_id: Uuid) -> bool {
        self.revoked_sessions.contains(&session_id)
    }
}
