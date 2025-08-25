/// Token issuance and validation service.
///
/// This module provides the `TokenService`, which coordinates:
/// - Creation of access (JWT) tokens
/// - Creation and rotation of refresh tokens
/// - Detection of refresh token reuse (and session revocation on reuse)
/// - Validation (signature + claims + revocation) of access tokens
/// - Explicit session revocation (logout)
///
/// Security model:
/// 1. Each refresh token rotation produces a new refresh token and marks the
///    previous one as used/replaced.
/// 2. Presenting an already-used / replaced refresh token is treated as a
///    reuse attempt and the entire session is revoked (defensive posture).
/// 3. Access tokens are short‑lived (configured TTL) and are invalidated early
///    if their session is revoked (revoked session check).
///
/// Errors:
/// - Refresh workflows map internal inconsistencies to `RefreshError`.
/// - Access token validation distinguishes invalid/malformed tokens,
///   key mismatches, and revoked sessions via `AccessError`.
///
/// Concurrency:
/// - Internal mutable state is hidden behind an async `RwLock<dyn RefreshStore>`.
/// - Rotation and revocation operations take a write lock only for the
///   minimal critical section.
///
/// Extensibility:
/// - Swapping the underlying `RefreshStore` (e.g., in‑memory, Redis-backed) is
///   done by providing a different boxed implementation at construction.
/// - Key material / issuer / audience / TTLs come from the dynamic `Config`.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, decode_header, encode, Algorithm, Header, Validation};
use rand::RngCore;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::domain::data_stores::jwt_key_store::JwtKeyStore;
use crate::domain::{
    hash_refresh, AccessClaims, IssuedTokens, RefreshError, RefreshRecord, RefreshStore,
};

use crate::utils::config::Config;

#[derive(Clone)]
/// Main façade for issuing / rotating refresh tokens and validating access tokens.
///
/// Typical lifecycle:
/// 1. `issue_initial_session` -> returns `(access, refresh)`
/// 2. Client uses refresh token with `refresh` to rotate & obtain a new pair
/// 3. On logout or suspected compromise -> `logout_session`
/// 4. Every protected request -> `validate_access`
///
/// Reuse policy: any attempt to reuse an already rotated refresh token
/// revokes the entire session chain.
pub struct TokenService {
    cfg: Arc<RwLock<Config>>,
    keys: Arc<JwtKeyStore>,
    // State that changes: refresh records and revoked sessions
    state: Arc<RwLock<Box<dyn RefreshStore + Send + Sync>>>,
}

#[derive(Debug)]
pub enum AccessError {
    InvalidToken,
    BadKey,
    RevokedSession,
}

impl TokenService {
    /// Construct a new `TokenService`.
    ///
    /// Parameters:
    /// - `cfg`: shared configuration (issuer, audience, TTLs, keys)
    /// - `store`: refresh store implementation (in‑memory, Redis, etc.)
    ///
    /// Panics: none (errors during key setup should already have been surfaced
    /// when building `Config` / key store).
    pub async fn new(cfg: Arc<RwLock<Config>>, store: Box<dyn RefreshStore + Send + Sync>) -> Self {
        let keys = {
            let config = cfg.read().await;
            Arc::new(JwtKeyStore::from_config(
                config.jwt_keys(),
                config.jwt_active_kid(),
            ))
        };

        let state = Arc::new(RwLock::new(store));
        Self { cfg, keys, state }
    }

    // Create a short-lived access JWT for a given user and session.
    /// Internal helper: build & sign a short‑lived access JWT.
    ///
    /// Not exposed publicly because callers should rely on the higher‑level
    /// flows (`issue_initial_session`, `refresh`) that also manage refresh state.
    async fn generate_access_token(
        &self,
        user_id: &str,
        session_id: Uuid,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let now = Utc::now();
        let (token_ttl_seconds, jwt_issuer, jwt_audience) = {
            let config = self.cfg.read().await;
            (
                config.token_ttl_seconds(),
                config.jwt_issuer().to_owned(),
                config.jwt_audience().to_owned(),
            )
        };
        let exp = now + Duration::seconds(token_ttl_seconds);

        let claims = AccessClaims {
            sub: user_id.to_string(),
            iss: jwt_issuer,
            aud: jwt_audience,
            exp: exp.timestamp() as usize,
            iat: now.timestamp() as usize,
            jti: Uuid::new_v4().to_string(),
            sid: session_id.to_string(),
        };

        let (enc_key, kid) = self.keys.encoding_key_and_kid();
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(kid.to_string());

        encode(&header, &claims, &enc_key)
    }

    fn new_refresh_token_plain(&self) -> String {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        B64.encode(bytes)
    }

    // Issue initial session: access + refresh.
    /// Issue the initial access + refresh token pair for a new session.
    ///
    /// On success returns:
    /// - `access_token`: JWT
    /// - `refresh_token`: opaque (base64) refresh token
    ///
    /// Errors:
    /// - `RefreshError::Internal` if the refresh store rejects insertion
    pub async fn issue_initial_session(&self, user_id: &str) -> Result<IssuedTokens, RefreshError> {
        let session_id = Uuid::new_v4();
        let access = self
            .generate_access_token(user_id, session_id)
            .await
            .map_err(|_| RefreshError::Internal)?;

        let now = Utc::now();
        let (refresh_token_ttl_seconds, refresh_hash_key) = {
            let config = self.cfg.read().await;
            (
                config.refresh_token_ttl_seconds(),
                config.refresh_hash_key().to_owned(),
            )
        };

        let ttl = Duration::seconds(refresh_token_ttl_seconds);

        let refresh_plain = self.new_refresh_token_plain();
        let record = RefreshRecord {
            token_hash: hash_refresh(&refresh_hash_key, &refresh_plain).await,
            user_id: user_id.to_string(),
            session_id,
            created_at: now,
            expires_at: now + ttl,
            parent_hash: None,
            replaced_by_hash: None,
            used_at: None,
            revoked_at: None,
        };

        {
            let mut st = self.state.write().await;
            st.insert_initial(record)
                .await
                .map_err(|_| RefreshError::Internal)?;
        }

        Ok(IssuedTokens {
            user_id: user_id.to_string(),
            session_id,
            access_token: access,
            refresh_token: refresh_plain,
        })
    }

    // Rotate refresh token and return new tokens.
    /// Rotate a refresh token, returning a fresh access + refresh pair.
    ///
    /// Security behavior:
    /// - Marks the presented refresh token as used/replaced.
    /// - If the token was already used/replaced, session is revoked and an error returned.
    ///
    /// Returns the new pair on success.
    ///
    /// Possible errors:
    /// - `NotFoundOrExpired`: token hash not present or expired
    /// - `ReuseDetected`: reuse attempt (session revoked)
    /// - `Revoked`: session already revoked
    /// - `Internal`: underlying store failure
    pub async fn refresh(&self, presented_refresh: &str) -> Result<IssuedTokens, RefreshError> {
        let now = Utc::now();

        let (refresh_token_ttl_seconds, refresh_hash_key) = {
            let config = self.cfg.read().await;
            (
                config.refresh_token_ttl_seconds(),
                config.refresh_hash_key().to_owned(),
            )
        };

        let ttl = Duration::seconds(refresh_token_ttl_seconds);
        let next_plain = self.new_refresh_token_plain();

        let (user_id, session_id) = {
            let mut st = self.state.write().await;
            let (_old, new_record) = st
                .rotate(presented_refresh, &next_plain, now, ttl, &refresh_hash_key)
                .await?;
            (new_record.user_id.clone(), new_record.session_id)
        };

        let access = self
            .generate_access_token(&user_id, session_id)
            .await
            .map_err(|_| RefreshError::Internal)?;

        Ok(IssuedTokens {
            user_id,
            session_id,
            access_token: access,
            refresh_token: next_plain,
        })
    }

    // Validate access token (signature + iss/aud/exp) and ensure session not
    // revoked. Returns the claims if valid.
    /// Validate an access (JWT) token:
    /// - Decodes header & selects the correct key by KID
    /// - Validates signature, issuer, audience, exp (with small leeway)
    /// - Checks that the session (sid) has not been revoked
    ///
    /// Errors:
    /// - `AccessError::InvalidToken`: malformed or signature/claim failure
    /// - `AccessError::BadKey`: unknown / missing key id
    /// - `AccessError::RevokedSession`: session has been revoked
    pub async fn validate_access(&self, token: &str) -> Result<AccessClaims, AccessError> {
        let header = decode_header(token).map_err(|_| AccessError::InvalidToken)?;

        let key = self
            .keys
            .decoding_key_for_kid(header.kid.as_deref())
            .ok_or(AccessError::BadKey)?;

        let mut validation = Validation::new(Algorithm::HS256);

        let (jwt_issuer, jwt_audience) = {
            let config = self.cfg.read().await;
            (
                config.jwt_issuer().to_owned(),
                config.jwt_audience().to_owned(),
            )
        };

        validation.set_issuer(&[jwt_issuer]);
        validation.set_audience(&[jwt_audience]);
        validation.leeway = 30;

        let data = decode::<AccessClaims>(token, &key, &validation)
            .map_err(|_| AccessError::InvalidToken)?;

        let sid = Uuid::parse_str(&data.claims.sid).map_err(|_| AccessError::InvalidToken)?;

        {
            let st = self.state.read().await;
            if st.is_session_revoked(sid).await {
                return Err(AccessError::RevokedSession);
            }
        }

        Ok(data.claims)
    }

    // Logout: revoke the entire session chain (refreshes) and mark session as
    // revoked so existing access tokens are denied.
    /// Revoke an entire session chain (all refresh lineage + future access).
    ///
    /// Safe to call multiple times (idempotent at the store layer).
    pub async fn logout_session(&self, session_id: Uuid) {
        let now = Utc::now();
        let mut st = self.state.write().await;
        st.revoke_session(session_id, now).await;
    }
}
