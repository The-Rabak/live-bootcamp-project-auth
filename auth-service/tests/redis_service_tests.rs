use std::time::Duration;

use tokio::time::sleep;
use uuid::Uuid;

use auth_service::services::data_stores::redis_service::RedisService;

/// Integration tests for RedisService.
/// These tests assume a running Redis instance (default 127.0.0.1:6379).
/// Override host via environment:
///   TEST_REDIS_HOST or REDIS_HOST  (format: host:port)
///
/// Run:
///   cargo test --test redis_service_tests -- --nocapture
///
/// If Redis is not available the tests will panic early (simple approach).

fn redis_host() -> String {
    std::env::var("TEST_REDIS_HOST")
        .or_else(|_| std::env::var("REDIS_HOST"))
        .unwrap_or_else(|_| "127.0.0.1:6379".to_string())
}

fn unique_prefix() -> String {
    format!("itest:{}:", Uuid::new_v4())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_set_key_value_and_exists_and_delete() {
    let svc = RedisService::new(&redis_host());
    let prefix = unique_prefix();
    let key = format!("{prefix}plain");
    let val = "hello-world";

    assert!(
        !svc.exists(&key).await.unwrap(),
        "Key should not exist before set"
    );

    let _ = svc
        .set_key_value(&key, val, 5)
        .await
        .expect("set_key_value should succeed");

    assert!(
        svc.exists(&key).await.unwrap(),
        "Key should exist after set"
    );

    let fetched = svc.get(&key).await.unwrap();
    assert_eq!(fetched.as_deref(), Some(val));

    let deleted = svc.delete_key(&key).await.unwrap();
    assert!(deleted, "delete_key should report deletion");
    assert!(
        !svc.exists(&key).await.unwrap(),
        "Key should not exist after delete"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_set_hash_multiple_and_get_hash_all() {
    let svc = RedisService::new(&redis_host());
    let prefix = unique_prefix();
    let key = format!("{prefix}hash");
    let fields = vec![
        ("field1".to_string(), "v1".to_string()),
        ("field2".to_string(), "v2".to_string()),
        ("field3".to_string(), "v3".to_string()),
    ];

    svc.set_hash_multiple(&key, &fields, Some(10))
        .await
        .expect("hash set should succeed");

    assert!(
        svc.exists(&key).await.unwrap(),
        "Hash key should exist after set"
    );

    let mut got = svc.get_hash_all(&key).await.expect("get_hash_all succeeds");

    got.sort_by(|a, b| a.0.cmp(&b.0));
    let mut expected = fields.clone();
    expected.sort_by(|a, b| a.0.cmp(&b.0));

    assert_eq!(got, expected, "Stored hash fields should round-trip");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_hash_ttl_expiration() {
    let svc = RedisService::new(&redis_host());
    let prefix = unique_prefix();
    let key = format!("{prefix}hash_ttl");
    let fields = vec![("only".to_string(), "once".to_string())];

    svc.set_hash_multiple(&key, &fields, Some(2))
        .await
        .expect("hash set should succeed");

    assert!(
        svc.exists(&key).await.unwrap(),
        "Key should exist immediately after set"
    );

    sleep(Duration::from_secs(3)).await;

    assert!(
        !svc.exists(&key).await.unwrap(),
        "Key should have expired (TTL 2s, waited 3s)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_hash_ttl_zero_is_clamped_to_one_second() {
    let svc = RedisService::new(&redis_host());
    let prefix = unique_prefix();
    let key = format!("{prefix}hash_zero_ttl");
    let fields = vec![("f".to_string(), "v".to_string())];

    // Pass ttl = 0; implementation clamps to 1s
    svc.set_hash_multiple(&key, &fields, Some(0))
        .await
        .expect("hash set should succeed");

    assert!(
        svc.exists(&key).await.unwrap(),
        "Key should exist immediately after set"
    );

    sleep(Duration::from_millis(500)).await;
    assert!(
        svc.exists(&key).await.unwrap(),
        "Key should still exist before 1 second passes"
    );

    sleep(Duration::from_millis(800)).await; // total ~1.3s
    assert!(
        !svc.exists(&key).await.unwrap(),
        "Key should have expired after clamped 1s TTL"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_set_key_value_clamps_zero_ttl() {
    let svc = RedisService::new(&redis_host());
    let prefix = unique_prefix();
    let key = format!("{prefix}kv_zero_ttl");

    let _ = svc
        .set_key_value(&key, "zv", 0) // 0 -> clamped to 1 in impl
        .await
        .expect("set_key_value should succeed");

    assert!(
        svc.exists(&key).await.unwrap(),
        "Key should exist immediately after zero-ttl set"
    );

    sleep(Duration::from_millis(1200)).await;
    assert!(
        !svc.exists(&key).await.unwrap(),
        "Key should have expired after clamped 1s TTL"
    );
}
