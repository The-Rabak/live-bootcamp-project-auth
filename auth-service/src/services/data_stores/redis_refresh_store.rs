use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    domain::{hash_refresh, AsRedisHashArgs, RefreshError, RefreshRecord, RefreshStore},
    services::RedisService,
};

pub struct RedisRefreshStore {
    redis_service: Arc<RedisService>,
}

impl RedisRefreshStore {
    pub fn new(redis_service: Arc<RedisService>) -> Self {
        Self { redis_service }
    }

    /// Get a RefreshRecord by its token hash using Redis hash operations
    async fn get_record_by_hash(
        &self,
        token_hash: &[u8; 32],
    ) -> Result<Option<RefreshRecord>, RefreshError> {
        let key = RefreshRecord::redis_key_from_hash(token_hash);

        // Check if the key exists first
        let exists = self
            .redis_service
            .exists(&key)
            .await
            .map_err(|_| RefreshError::Internal)?;

        if !exists {
            return Ok(None);
        }

        // Get all hash fields
        let fields = self
            .redis_service
            .get_hash_all(&key)
            .await
            .map_err(|_| RefreshError::Internal)?;

        if fields.is_empty() {
            return Ok(None);
        }

        // Reconstruct the record from hash fields
        let record = RefreshRecord::from_redis_hash(fields).map_err(|_| RefreshError::Internal)?;

        Ok(Some(record))
    }

    /// Store a RefreshRecord using Redis hash operations
    async fn store_record(
        &self,
        record: &RefreshRecord,
        ttl_seconds: Option<usize>,
    ) -> Result<(), RefreshError> {
        let key = record.get_redis_key();
        let fields = record.as_redis_hash_args();

        self.redis_service
            .set_hash_multiple(&key, &fields, ttl_seconds)
            .await
            .map_err(|_| RefreshError::Internal)
    }

    /// Delete a RefreshRecord by its token hash
    async fn delete_record(&self, token_hash: &[u8; 32]) -> Result<bool, RefreshError> {
        let key = RefreshRecord::redis_key_from_hash(token_hash);
        self.redis_service
            .delete_key(&key)
            .await
            .map_err(|_| RefreshError::Internal)
    }

    /// Check if a session is revoked by looking up in Redis
    async fn is_session_revoked_internal(&self, session_id: Uuid) -> Result<bool, RefreshError> {
        let revoked_key = format!("revoked_session:{}", session_id);
        self.redis_service
            .exists(&revoked_key)
            .await
            .map_err(|_| RefreshError::Internal)
    }

    /// Mark a session as revoked in Redis
    async fn mark_session_revoked(&self, session_id: Uuid) -> Result<(), RefreshError> {
        let revoked_key = format!("revoked_session:{}", session_id);
        // Store with 30 days TTL
        self.redis_service
            .set_key_value(&revoked_key, "1", 86400 * 30)
            .await
            .map_err(|_| RefreshError::Internal)?;
        Ok(())
    }
}

#[async_trait]
impl RefreshStore for RedisRefreshStore {
    async fn insert_initial(&mut self, record: RefreshRecord) -> Result<(), RefreshError> {
        let key = record.get_redis_key();

        // Check if the record already exists
        if self
            .redis_service
            .exists(&key)
            .await
            .map_err(|_| RefreshError::Internal)?
        {
            return Err(RefreshError::Internal);
        }

        // Calculate TTL from the record's expires_at
        let now = chrono::Utc::now();
        let ttl_seconds = (record.expires_at - now).num_seconds() as usize;

        // Store the record as a Redis hash
        self.store_record(&record, Some(ttl_seconds)).await
    }

    async fn rotate(
        &mut self,
        presented_plain: &str,
        new_plain: &str,
        now: DateTime<Utc>,
        ttl: Duration,
        hash_key: &[u8; 32],
    ) -> Result<(RefreshRecord, RefreshRecord), RefreshError> {
        let old_hash = hash_refresh(hash_key, presented_plain).await;
        let new_hash = hash_refresh(hash_key, new_plain).await;

        // Get the old record using hash operations
        let mut old = match self.get_record_by_hash(&old_hash).await? {
            Some(r) => r,
            None => return Err(RefreshError::NotFoundOrExpired),
        };

        // Validate the old record
        if old.expires_at <= now {
            return Err(RefreshError::NotFoundOrExpired);
        }

        if old.revoked_at.is_some() || self.is_session_revoked(old.session_id).await {
            return Err(RefreshError::Revoked);
        }

        if old.replaced_by_hash.is_some() || old.used_at.is_some() {
            // Reuse detected: mark session as revoked
            self.revoke_session_internal(old.session_id, now).await;
            return Err(RefreshError::ReuseDetected);
        }

        // Update the old record
        old.used_at = Some(now);
        old.replaced_by_hash = Some(new_hash);

        // Persist the updated old record immediately so any concurrent / rapid
        // reuse attempts observe the used/replaced flags before the new token
        // is fully stored.
        let remaining_seconds = (old.expires_at - now).num_seconds();
        if remaining_seconds <= 0 {
            return Err(RefreshError::NotFoundOrExpired);
        }
        self.store_record(&old, Some(remaining_seconds as usize))
            .await?;

        // Create the new record
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

        // Store the new record with its full TTL
        let new_ttl_seconds = ttl.num_seconds() as usize;
        self.store_record(&new_record, Some(new_ttl_seconds))
            .await?;

        Ok((old, new_record))
    }

    async fn revoke_session(&mut self, session_id: Uuid, now: DateTime<Utc>) {
        let _ = self.revoke_session_internal(session_id, now).await;
    }

    async fn revoke_session_internal(&mut self, session_id: Uuid, _now: DateTime<Utc>) {
        // Mark the session as revoked in Redis
        let _ = self.mark_session_revoked(session_id).await;
    }

    async fn is_session_revoked(&self, session_id: Uuid) -> bool {
        self.is_session_revoked_internal(session_id)
            .await
            .unwrap_or(false)
    }
}
