use auth_service::app_router;

use auth_service::services::TokenService;
use auth_service::services::{HashmapTwoFACodeStore, HashsetRefreshStore};
use reqwest::cookie::CookieStore;
use reqwest::cookie::Jar;

use reqwest::Client;
use reqwest::Response;
use reqwest::Url;
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use tokio::net::TcpListener;
use tokio::spawn;
use uuid::Uuid;

use auth_service::app_state::{AppState, TwoFACodeStoreType};
use auth_service::domain::SignupRequestBody;
use auth_service::services::hashmap_user_store::HashmapUserStore;
use auth_service::utils::Config;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Serialize)]
pub struct LoginBody {
    pub email: String,
    pub password: String,
}
pub struct Verify2FABody {
    pub email: String,
    pub login_attempt_id: String,
    pub mfa_code: String,
}

impl Serialize for Verify2FABody {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Verify2FABody", 3)?;
        state.serialize_field("email", &self.email)?;
        state.serialize_field("loginAttemptId", &self.login_attempt_id)?;
        state.serialize_field("2FACode", &self.mfa_code)?;
        state.end()
    }
}

#[derive(Serialize)]
pub struct VerifyJWTBody {
    pub token: String,
}

pub struct TestApp {
    pub address: String,
    pub http_client: Client,
    pub cookie_jar: Arc<Jar>,
    pub token_service: Arc<RwLock<TokenService>>,
    pub config: Arc<RwLock<Config>>,
    pub twofa_code_store: TwoFACodeStoreType,
}

impl TestApp {
    pub async fn new() -> Self {
        let user_store = HashmapUserStore::new();
        // Set up test environment variables
        std::env::set_var("JWT_ISSUER", "test_issuer");
        std::env::set_var("JWT_AUDIENCE", "test_audience");
        std::env::set_var("ACCESS_TTL_SECONDS", "3600");
        std::env::set_var("REFRESH_TTL_SECONDS", "86400");
        std::env::set_var(
            "REFRESH_HASH_KEY_B64",
            "dGVzdF9yZWZyZXNoX2hhc2hfa2V5XzMyX2J5dGVzISE",
        );
        std::env::set_var("JWT_ACTIVE_KID", "test_key_id");
        std::env::set_var(
            "JWT_HS256_KEYS_JSON",
            r#"[{"kid":"test_key_id","secret_b64":"dGVzdF9zZWNyZXRfa2V5X3RoYXRfaXNfbG9uZ19lbm91Z2hfZm9yX2hzMjU2X2FsZ29yaXRobQ"}]"#,
        );
        std::env::set_var("ACCESS_COOKIE_NAME", "access_token");
        std::env::set_var("REFRESH_COOKIE_NAME", "refresh_token");

        let config = Arc::new(RwLock::new(
            Config::default().expect("could not start config for tests"),
        ));
        let token_service = Arc::new(RwLock::new(
            TokenService::new(config.clone(), Box::new(HashsetRefreshStore::default())).await,
        ));
        let twofa_code_store = Arc::new(RwLock::new(HashmapTwoFACodeStore::default()));

        let app_state = AppState::new(
            Arc::new(RwLock::new(user_store)),
            token_service.clone(),
            Arc::clone(&config),
            twofa_code_store.clone(),
        );
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed binding to an ephemeral port");

        let port = listener.local_addr().unwrap().port();
        let address = format!("http://127.0.0.1:{}", port);

        let server = axum::serve(listener, app_router(app_state));

        spawn(async move {
            if let Err(e) = server.await {
                eprintln!("Test server error: {}", e);
            }
        });

        let cookie_jar = Arc::new(Jar::default());
        let client = Client::builder()
            .cookie_provider(Arc::clone(&cookie_jar))
            .build()
            .expect("failed to build http client");

        TestApp {
            address,
            http_client: client,
            cookie_jar,
            token_service,
            config,
            twofa_code_store,
        }
    }

    pub async fn get_root(&self) -> reqwest::Response {
        self.http_client
            .get(&format!("{}/", &self.address))
            .send()
            .await
            .expect("Failed to execute root request.")
    }

    pub async fn signup(&self, email: String, password: String, requires_mfa: bool) -> Response {
        let body = SignupRequestBody {
            email,
            password,
            requires_mfa,
        };

        self.http_client
            .post(&format!("{}/signup", &self.address))
            .json(&body)
            .header("Content-Type", "application/json")
            .send()
            .await
            .expect("Failed to execute signup request.")
    }

    pub async fn login(&self, email: String, password: String) -> Response {
        let body = LoginBody { email, password };

        self.http_client
            .post(&format!("{}/login", &self.address))
            .json(&body)
            .header("Content-Type", "application/json")
            .send()
            .await
            .expect("Failed to execute login request.")
    }
    pub async fn verify_mfa(
        &self,
        email: String,
        login_attempt_id: String,
        mfa_code: String,
    ) -> Response {
        let body = Verify2FABody {
            email,
            login_attempt_id,
            mfa_code,
        };

        self.http_client
            .post(&format!("{}/verify-2fa", &self.address))
            .json(&body)
            .header("Content-Type", "application/json")
            .send()
            .await
            .expect("Failed to execute verify 2fa request.")
    }

    pub async fn logout(&self) -> Response {
        let url = Url::parse(&self.address).unwrap();
        let response = self
            .http_client
            .post(&format!("{}/logout", &self.address))
            .send()
            .await
            .expect("Failed to execute logout request.");

        let mut cookies = response.headers().get_all("set-cookie").iter();
        self.cookie_jar.set_cookies(&mut cookies, &url);

        response
    }

    pub async fn verify_token(&self, jwt_token: String) -> Response {
        let body = VerifyJWTBody { token: jwt_token };

        self.http_client
            .post(&format!("{}/verify-token", &self.address))
            .json(&body)
            .header("Content-Type", "application/json")
            .send()
            .await
            .expect("Failed to execute verify token request.")
    }
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}
