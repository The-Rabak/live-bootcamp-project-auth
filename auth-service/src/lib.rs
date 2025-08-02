use axum::{routing::{delete, post}, Router};
use tower_http::services::ServeDir;
use axum_server::bind;
use std::{error::Error, future::Future, pin::Pin};
use routes::{login, logout, signup, verify_mfa, verify_token, delete_account};
use app_state::AppState;

pub mod routes;
pub mod validation;
pub mod domain;
pub mod app_state;
pub mod services;
pub mod errors;

type ServerFuture = Pin<Box<dyn Future<Output = Result<(), std::io::Error>> + Send>>;

pub fn app_router(app_state: AppState) -> Router {
    Router::new()
        .nest_service("/", ServeDir::new("assets"))
        .route("/signup", post(signup::signup))
        .route("/login", post(login::login))
        .route("/verify-2fa", post(verify_mfa::verify_mfa))
        .route("/logout", post(logout::logout))
        .route("/verify-token", post(verify_token::verify_token))
        .route("/delete-account", delete(delete_account::delete_account))
        .with_state(app_state)
}

// This struct encapsulates our application-related logic.
pub struct Application {
    http_future: ServerFuture,
    // address is exposed as a public field,
    // so we have access to it in tests.
    pub address: String,
}

impl Application {

    pub async fn build(app_state: AppState, address: &str) -> Result<Self, Box<dyn Error>> {

        let router = app_router(app_state);

        let http_future = bind(address.parse()?)
            .serve(router.into_make_service());

        Ok(Self {
            http_future: Box::pin(http_future),
            address: format!("http://{}", address),
        })
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        println!("listening on {}", &self.address);
        self.http_future.await
    }

}