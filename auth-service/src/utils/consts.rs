use dotenvy::dotenv;
use lazy_static::lazy_static;
use std::env as std_env;

// Define a lazily evaluated static. lazy_static is needed because std_env::var is not a const function.
lazy_static! {
    pub static ref JWT_SECRET: String = set_token();
    pub static ref TOKEN_TTL_SECONDS: i64 = set_token_ttl();
}

fn set_token() -> String {
    dotenv().ok(); // Load environment variables
    let secret = std_env::var(env::JWT_SECRET_ENV_VAR).expect("JWT_SECRET must be set.");
    if secret.is_empty() {
        panic!("JWT_SECRET must not be empty.");
    }
    secret
}

fn set_token_ttl() -> i64 {
    dotenv().ok(); // Load environment variables
    std_env::var(env::TOKEN_TTL_SECONDS_ENV_VAR)
        .ok()
        .and_then(|val| val.parse().ok())
        .unwrap_or(600) // Default to 600 seconds (10 minutes)
}

pub mod env {
    pub const JWT_SECRET_ENV_VAR: &str = "JWT_SECRET";
    pub const TOKEN_TTL_SECONDS_ENV_VAR: &str = "TOKEN_TTL_SECONDS";
}

pub const JWT_COOKIE_NAME: &str = "jwt";
