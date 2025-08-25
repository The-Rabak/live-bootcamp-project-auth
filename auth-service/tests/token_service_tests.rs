use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;
use tokio::sync::RwLock;

use auth_service::domain::RefreshError;
use auth_service::services::data_stores::hashset_refresh_store::HashsetRefreshStore;
use auth_service::services::token_service::AccessError;
use auth_service::services::TokenService;
use auth_service::utils::config::Config;

/// Prepare environment variables required by Config::default()
fn set_env_config() {
    // These tests set vars each time; overwrite is fine.
    std::env::set_var("JWT_ISSUER", "test-issuer");
    std::env::set_var("JWT_AUDIENCE", "test-aud");
    std::env::set_var("DATABASE_URL", "sqlite::memory:");
    std::env::set_var("REDIS_HOST", "127.0.0.1:6379");
    std::env::set_var("ACCESS_TTL_SECONDS", "60");
    std::env::set_var("REFRESH_TTL_SECONDS", "300");

    // 32 zero bytes base64
    let thirty_two_zero_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    std::env::set_var("REFRESH_HASH_KEY_B64", thirty_two_zero_b64);

    // Single HS256 key JSON
    let keys_json = format!(
        r#"[{{"kid":"k1","secret_b64":"{secret}"}}]"#,
        secret = thirty_two_zero_b64
    );
    std::env::set_var("JWT_HS256_KEYS_JSON", keys_json);
    std::env::set_var("JWT_ACTIVE_KID", "k1");

    // Optional cookie names
    std::env::set_var("ACCESS_COOKIE_NAME", "access");
    std::env::set_var("REFRESH_COOKIE_NAME", "refresh");
}

async fn build_token_service() -> TokenService {
    set_env_config();
    let cfg = Arc::new(RwLock::new(
        Config::default().expect("failed to build test config"),
    ));
    let store: Box<dyn auth_service::domain::RefreshStore + Send + Sync> =
        Box::new(HashsetRefreshStore::default());
    TokenService::new(cfg, store).await
}

fn decode_refresh_plain(b64_token: &str) -> Vec<u8> {
    B64.decode(b64_token)
        .expect("refresh token base64 decode failed")
}

#[tokio::test]
async fn issue_initial_session_produces_valid_tokens() {
    let svc = build_token_service().await;
    let result = svc.issue_initial_session("user-123").await;
    assert!(result.is_ok(), "expected successful issuance");
    let issued = result.unwrap();

    assert_eq!(issued.user_id, "user-123");
    assert!(!issued.access_token.is_empty(), "access token empty");
    assert!(!issued.refresh_token.is_empty(), "refresh token empty");

    // Refresh token should base64 decode to 32 bytes
    let raw = decode_refresh_plain(&issued.refresh_token);
    assert_eq!(raw.len(), 32, "expected 32 random bytes in refresh token");

    // Validate access token
    let claims = svc
        .validate_access(&issued.access_token)
        .await
        .expect("access token should validate");
    assert_eq!(claims.sub, "user-123");
    assert_eq!(claims.sid, issued.session_id.to_string());
}

#[tokio::test]
async fn refresh_flow_issues_new_tokens_and_invalidates_old_refresh() {
    let svc = build_token_service().await;
    let first = svc
        .issue_initial_session("alice")
        .await
        .expect("initial issue");

    // Refresh
    let second = svc
        .refresh(&first.refresh_token)
        .await
        .expect("refresh should succeed");
    assert_eq!(second.user_id, "alice");
    assert_ne!(
        first.refresh_token, second.refresh_token,
        "new refresh token should differ"
    );
    assert_ne!(
        first.access_token, second.access_token,
        "access tokens should differ"
    );

    // Old refresh should now cause reuse / invalid error
    let reuse = svc.refresh(&first.refresh_token).await;
    match reuse {
        Err(RefreshError::ReuseDetected)
        | Err(RefreshError::Revoked)
        | Err(RefreshError::NotFoundOrExpired) => {
            // acceptable outcomes depending on store logic (Hashset store returns ReuseDetected)
        }
        other => panic!("expected reuse-related error, got {:?}", other),
    }

    // Because reuse triggered session revocation, the new access token should now be invalid.
    let post_reuse = svc.validate_access(&second.access_token).await;
    assert!(
        matches!(post_reuse, Err(AccessError::RevokedSession)),
        "expected RevokedSession after reuse, got {:?}",
        post_reuse
    );
}

#[tokio::test]
async fn validate_access_rejects_tampered_token() {
    let svc = build_token_service().await;
    let issued = svc
        .issue_initial_session("userX")
        .await
        .expect("issue initial");
    let mut tampered = issued.access_token.clone();
    // Flip one character safely (JWT are base64url segments; just alter a middle char)
    if tampered.len() > 11 {
        // can't directly mutate substring; simpler: rebuild string
        let bytes = tampered.as_bytes();
        let mut vec = bytes.to_vec();
        vec[10] = if vec[10] == b'a' { b'b' } else { b'a' };
        tampered = String::from_utf8(vec).unwrap();
    }

    let res = svc.validate_access(&tampered).await;
    assert!(
        matches!(res, Err(AccessError::InvalidToken)),
        "expected invalid token error, got {:?}",
        res
    );
}

#[tokio::test]
async fn logout_session_revokes_access_and_future_refresh() {
    let svc = build_token_service().await;
    let issued = svc
        .issue_initial_session("revoker")
        .await
        .expect("issue initial");
    let sid = issued.session_id;

    // Logout
    svc.logout_session(sid).await;

    // Access token now should be considered revoked
    let res = svc.validate_access(&issued.access_token).await;
    assert!(
        matches!(res, Err(AccessError::RevokedSession)),
        "expected RevokedSession error, got {:?}",
        res
    );

    // Attempt refresh after logout
    let ref_res = svc.refresh(&issued.refresh_token).await;
    assert!(
        matches!(
            ref_res,
            Err(RefreshError::Revoked) | Err(RefreshError::NotFoundOrExpired)
        ),
        "expected revoked or not-found after logout, got {:?}",
        ref_res
    );
}

#[tokio::test]
async fn multiple_sequential_refreshes_work() {
    let svc = build_token_service().await;
    let mut current = svc
        .issue_initial_session("chain-user")
        .await
        .expect("initial issue");

    for i in 0..5 {
        let next = svc
            .refresh(&current.refresh_token)
            .await
            .unwrap_or_else(|e| panic!("refresh #{i} failed: {e:?}"));
        // Each step: new session id stays same, tokens change
        assert_eq!(next.user_id, "chain-user");
        assert_eq!(next.session_id, current.session_id);
        assert_ne!(next.refresh_token, current.refresh_token);
        assert_ne!(next.access_token, current.access_token);

        // Do not attempt reuse here; reuse would revoke the session under current security policy.

        current = next;
    }

    // Final access token validates
    let claims = svc
        .validate_access(&current.access_token)
        .await
        .expect("final access token validates");
    assert_eq!(claims.sub, "chain-user");
}

#[tokio::test]
async fn access_claims_have_reasonable_fields() {
    let svc = build_token_service().await;
    let issued = svc
        .issue_initial_session("inspect")
        .await
        .expect("issue initial");
    let claims = svc
        .validate_access(&issued.access_token)
        .await
        .expect("validate");

    // Basic structural expectations
    fn non_empty(s: &str) -> bool {
        !s.trim().is_empty()
    }
    assert!(non_empty(&claims.sub));
    assert!(non_empty(&claims.sid));
    assert!(non_empty(&claims.jti));
    assert!(claims.exp > claims.iat, "exp should be > iat");
    assert!(claims.exp - claims.iat <= 3600, "unexpected large TTL span");
}

#[tokio::test]
async fn refresh_with_unknown_token_fails() {
    let svc = build_token_service().await;
    // Random base64 32 bytes (not issued)
    let random = {
        let mut b = [0u8; 32];
        rand::rng().fill_bytes(&mut b);
        B64.encode(b)
    };
    let res = svc.refresh(&random).await;
    assert!(
        matches!(res, Err(RefreshError::NotFoundOrExpired)),
        "expected NotFoundOrExpired, got {:?}",
        res
    );
}
