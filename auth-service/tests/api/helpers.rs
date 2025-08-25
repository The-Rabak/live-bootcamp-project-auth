use auth_service::{app_router, get_db_pool};

use auth_service::services::{HashmapTwoFACodeStore, HashsetRefreshStore, MockEmailClient};
use auth_service::services::{SqlUserStore, TokenService};
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

use auth_service::app_state::{AppState, EmailClientType, TwoFACodeStoreType};
use auth_service::domain::SignupRequestBody;
use auth_service::migrations;
use auth_service::utils::Config;
use std::sync::Arc;
use test_context::AsyncTestContext;
use tokio::sync::RwLock;
use welds::connections::any::AnyClient;

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

pub struct TestContext {
    pub test_app: TestApp,
    db_file_path: String,
}

impl AsyncTestContext for TestContext {
    async fn setup() -> Self {
        // Create a unique database file for this test to avoid parallel test conflicts
        let unique_db_file = format!("data/test_{}.sqlite", Uuid::new_v4());
        let test_app = TestApp::new_with_db_file(&unique_db_file).await;

        // Run migrations in a blocking task to avoid trait bound issues
        let db_client = test_app.db_client.clone();
        tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(async {
                if let Err(e) = migrations::up(&db_client).await {
                    eprintln!("Failed to run migrations: {:?}", e);
                }
            })
        })
        .await
        .unwrap();

        Self {
            test_app,
            db_file_path: unique_db_file,
        }
    }

    async fn teardown(self) {
        // Clean up database in a blocking task
        let db_client = self.test_app.db_client.clone();
        tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(async {
                if let Err(e) = migrations::down(&db_client).await {
                    eprintln!("Failed to teardown migrations: {:?}", e);
                }
            })
        })
        .await
        .unwrap();

        // Clean up the unique database file
        let _ = std::fs::remove_file(&self.db_file_path);
    }
}

#[allow(dead_code)]
pub struct TestApp {
    pub address: String,
    pub http_client: Client,
    pub cookie_jar: Arc<Jar>,
    pub token_service: Arc<RwLock<TokenService>>,
    pub config: Arc<RwLock<Config>>,
    pub twofa_code_store: TwoFACodeStoreType,
    pub email_client: EmailClientType,
    pub db_client: AnyClient,
}

#[allow(dead_code)]
impl TestApp {
    pub async fn new() -> Self {
        // Create a unique database file for this test
        let unique_db_file = format!("data/test_{}.sqlite", Uuid::new_v4());
        Self::new_with_db_file(&unique_db_file).await
    }

    pub async fn new_with_db_file(db_file_path: &str) -> Self {
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
        // Required because Config::default() mandates REDIS_HOST even though
        // these API tests use the in-memory refresh store implementation.
        std::env::set_var("REDIS_HOST", "127.0.0.1:6379");

        // Create the database file if it doesn't exist
        if let Some(parent) = std::path::Path::new(db_file_path).parent() {
            std::fs::create_dir_all(parent).expect("Failed to create database directory");
        }
        std::fs::File::create(db_file_path).expect("Failed to create database file");

        // Create the database URL from the file path
        let db_url = format!("sqlite://{}", db_file_path);

        let config = Arc::new(RwLock::new(
            Config::default().expect("could not start config for tests"),
        ));
        let token_service = Arc::new(RwLock::new(
            TokenService::new(config.clone(), Box::new(HashsetRefreshStore::default())).await,
        ));
        let twofa_code_store = Arc::new(RwLock::new(HashmapTwoFACodeStore::default()));
        let email_client = Arc::new(RwLock::new(MockEmailClient::default()));
        let db_client = get_db_pool(&db_url).await.unwrap();
        let user_store = SqlUserStore::new(db_client.clone());

        let app_state = AppState::new(
            Arc::new(RwLock::new(user_store)),
            token_service.clone(),
            Arc::clone(&config),
            twofa_code_store.clone(),
            email_client.clone(),
            db_client.clone(),
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

        let test_app = TestApp {
            address,
            http_client: client,
            cookie_jar,
            token_service,
            config,
            twofa_code_store,
            email_client,
            db_client,
        };

        test_app
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

    #[allow(dead_code)]
    pub async fn verify_token(&self, jwt_token: String) -> Response {
        let body = VerifyJWTBody { token: jwt_token };
        self.http_client
            .post(&format!("{}/verify-token", &self.address))
            .json(&body)
            .send()
            .await
            .expect("Failed to execute verify token request.")
    }

    #[allow(dead_code)]
    pub async fn post_verify_2fa(
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
            .send()
            .await
            .expect("Failed to execute post verify 2FA request.")
    }
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}
