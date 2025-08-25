#![cfg(feature = "redis-tests")]
use std::sync::Arc;

use auth_service::domain::{hash_refresh, RefreshError, RefreshRecord, RefreshStore};
use auth_service::services::data_stores::redis_refresh_store::RedisRefreshStore;
use auth_service::services::data_stores::redis_service::RedisService;
use base64::Engine;
use chrono::{Duration, Utc};
use rand::RngCore;
use tokio::test;
use uuid::Uuid;

/// Obtain redis host for tests (default local instance).
fn redis_host() -> String {
    std::env::var("TEST_REDIS_HOST")
        .or_else(|_| std::env::var("REDIS_HOST"))
        .unwrap_or_else(|_| "127.0.0.1:6379".to_string())
}

/// Fixed hash key for deterministic hashing in tests.
const HASH_KEY: [u8; 32] = [7u8; 32];

/// Generate a random (URL-safe-ish) plain refresh token for test purposes.
fn random_plain() -> String {
    // 24 raw bytes -> base64 ~32 chars; good enough uniqueness for test isolation
    let mut buf = [0u8; 24];
    rand::rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

/// Build a fresh RedisRefreshStore backed by a shared RedisService.
fn new_store() -> RedisRefreshStore {
    let svc = Arc::new(RedisService::new(&redis_host()));
    RedisRefreshStore::new(svc)
}

/// Helper to make a fresh RefreshRecord (uninserted) given a plain token & ttl.
async fn make_record(plain: &str, ttl_secs: i64) -> RefreshRecord {
    let now = Utc::now();
    let token_hash = hash_refresh(&HASH_KEY, plain).await;
    RefreshRecord {
        token_hash,
        user_id: "user-test".into(),
        session_id: Uuid::new_v4(),
        created_at: now,
        expires_at: now + Duration::seconds(ttl_secs),
        parent_hash: None,
        replaced_by_hash: None,
        used_at: None,
        revoked_at: None,
    }
}

#[test]
async fn insert_initial_and_duplicate_detected() {
    let mut store = new_store();
    let plain = random_plain();
    let record = make_record(&plain, 300).await;

    store
        .insert_initial(record.clone())
        .await
        .expect("first insert should succeed");

    // Duplicate insert should error (Internal used as duplicate sentinel here)
    let dup_res = store.insert_initial(record).await;
    assert!(
        matches!(dup_res, Err(RefreshError::Internal)),
        "expected duplicate insert to return Internal, got {:?}",
        dup_res
    );
}

#[test]
async fn rotate_success_and_reuse_detection() {
    let mut store = new_store();
    let old_plain = random_plain();
    let new_plain = random_plain();
    let ttl = Duration::seconds(600);

    let record = make_record(&old_plain, ttl.num_seconds()).await;
    store
        .insert_initial(record)
        .await
        .expect("insert initial should succeed");

    // First rotation should succeed
    let (old_rec, new_rec) = store
        .rotate(&old_plain, &new_plain, Utc::now(), ttl, &HASH_KEY)
        .await
        .expect("rotate should succeed");

    assert!(old_rec.used_at.is_some(), "old token should be marked used");
    assert!(
        old_rec.replaced_by_hash.is_some(),
        "old token should have replaced_by_hash"
    );
    assert_eq!(
        old_rec.replaced_by_hash.unwrap(),
        new_rec.token_hash,
        "link integrity between old and new"
    );
    assert_eq!(
        new_rec.parent_hash,
        Some(old_rec.token_hash),
        "new record should point back to parent"
    );
    assert!(new_rec.used_at.is_none(), "new token should be unused");

    // Reuse the original old_plain again — should trigger reuse detection / revoke
    let reuse = store
        .rotate(&old_plain, &random_plain(), Utc::now(), ttl, &HASH_KEY)
        .await;

    assert!(
        matches!(reuse, Err(RefreshError::ReuseDetected)),
        "expected reuse detection, got {:?}",
        reuse
    );
}

#[test]
async fn rotate_fails_for_unknown_token() {
    let mut store = new_store();
    let unknown_plain = random_plain();
    let res = store
        .rotate(
            &unknown_plain,
            &random_plain(),
            Utc::now(),
            Duration::seconds(120),
            &HASH_KEY,
        )
        .await;
    assert!(
        matches!(res, Err(RefreshError::NotFoundOrExpired)),
        "expected NotFoundOrExpired for unknown token, got {:?}",
        res
    );
}

#[test]
async fn rotate_fails_for_expired_token() {
    let mut store = new_store();
    let old_plain = random_plain();
    // Create a record already expired (expires_at <= now)
    let mut rec = make_record(&old_plain, -10).await;
    // Manually adjust expires_at to ensure it is in the past (avoid negative TTL complications)
    rec.expires_at = Utc::now() - Duration::seconds(5);
    store
        .insert_initial(rec)
        .await
        .expect("insert of expired record still allowed; TTL calc may set large expiry");

    let res = store
        .rotate(
            &old_plain,
            &random_plain(),
            Utc::now(),
            Duration::seconds(120),
            &HASH_KEY,
        )
        .await;

    assert!(
        matches!(res, Err(RefreshError::NotFoundOrExpired)),
        "expected NotFoundOrExpired for expired token, got {:?}",
        res
    );
}

#[test]
async fn revoke_session_blocks_rotation_and_access() {
    let mut store = new_store();
    let old_plain = random_plain();
    let rec = make_record(&old_plain, 300).await;
    let session_id = rec.session_id;

    store
        .insert_initial(rec)
        .await
        .expect("initial insert should succeed");

    // Revoke session
    store.revoke_session(session_id, Utc::now()).await; // no error return

    // Attempt rotation should now be revoked
    let res = store
        .rotate(
            &old_plain,
            &random_plain(),
            Utc::now(),
            Duration::seconds(300),
            &HASH_KEY,
        )
        .await;

    assert!(
        matches!(res, Err(RefreshError::Revoked)),
        "expected Revoked after session revoke, got {:?}",
        res
    );

    // is_session_revoked should reflect revocation
    assert!(
        store.is_session_revoked(session_id).await,
        "session should be marked revoked"
    );
}

#[test]
async fn double_revoke_is_idempotent() {
    let mut store = new_store();
    let plain = random_plain();
    let rec = make_record(&plain, 120).await;
    let session_id = rec.session_id;
    store
        .insert_initial(rec)
        .await
        .expect("insert initial should succeed");

    store.revoke_session(session_id, Utc::now()).await;
    store.revoke_session(session_id, Utc::now()).await;

    assert!(
        store.is_session_revoked(session_id).await,
        "session should remain revoked"
    );
}
