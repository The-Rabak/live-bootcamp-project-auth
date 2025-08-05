use crate::proto::auth_server::AuthServer;
use crate::routes::AuthGrpc;
use app_state::AppState;
use axum::{
    routing::{delete, post},
    Router,
};
use axum_server::bind;
use routes::{delete_account, login, logout, signup, verify_mfa, verify_token};
use std::{error::Error, future::Future, pin::Pin};
use tonic::transport::server::Router as GrpcRouter;
use tonic::transport::Error as GrpcError;
use tonic::transport::Server;
use tower_http::services::ServeDir;

pub mod app_state;
pub mod domain;
pub mod errors;
pub mod routes;
pub mod services;
pub mod validation;
pub mod utils;
pub mod proto {
    #[cfg(not(rust_analyzer))]
    tonic::include_proto!("auth");

    #[cfg(rust_analyzer)]
    include!("generated/auth.rs");

    pub const AUTH_DESCRIPTOR: &[u8] =
    tonic::include_file_descriptor_set!("auth_descriptor");
}

use tonic_reflection::server::Builder as ReflectionBuilder;
use proto::AUTH_DESCRIPTOR;



type ServerFuture = Pin<Box<dyn Future<Output = Result<(), std::io::Error>> + Send>>;
type GrpcServerFuture = Pin<Box<dyn Future<Output = Result<(), GrpcError>> + Send>>;

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

pub fn create_grpc_server(app_state: AppState) -> GrpcRouter {
    let auth_service = AuthGrpc { state: app_state };

    let reflection_svc = ReflectionBuilder::configure()
    .register_encoded_file_descriptor_set(AUTH_DESCRIPTOR)
    .build_v1()
    .unwrap();

    Server::builder()
    .add_service(reflection_svc)
    .add_service(AuthServer::new(auth_service))
}

// This struct encapsulates our application-related logic.
pub struct Application {
    http_future: ServerFuture,
    grpc_future: GrpcServerFuture,
    // address is exposed as a public field,
    // so we have access to it in tests.
    pub address: String,
    pub grpc_address: String,
}

impl Application {
    pub async fn build(
        app_state: AppState,
        address: &str,
        grpc_address: &str,
    ) -> Result<Self, Box<dyn Error>> {
        let http_router = app_router(app_state.clone());


        let grpc_future = create_grpc_server(app_state.clone()).serve(grpc_address.parse()?);

        let http_future = bind(address.parse()?).serve(http_router.into_make_service());

        Ok(Self {
            http_future: Box::pin(http_future),
            grpc_future: Box::pin(grpc_future),
            address: format!("http://{}", address),
            grpc_address: format!("http://{}", grpc_address),
        })
    }

    pub async fn run(self) -> Result<(), Box<dyn Error>> {
        // Run both servers concurrently using tokio::join!

        println!("http listening on {}", &self.address);
        println!("grpc listening on {}", &self.grpc_address);
        let (http_result, grpc_result) = tokio::join!(
            async {
                self.http_future
                    .await
                    .map_err(|e| Box::new(e) as Box<dyn Error>)
            },
            async {
                self.grpc_future
                    .await
                    .map_err(|e| Box::new(e) as Box<dyn Error>)
            }
        );

        // If either server fails, return the error
        http_result?;
        grpc_result?;

        Ok(())
    }
}
