use axum_extra::extract::cookie::{Cookie, SameSite};
use time::Duration;

pub fn access_cookie(name: &str, token: &str, ttl_secs: i64) -> Cookie<'static> {
    Cookie::build((name.to_string(), token.to_string()))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(true)
        .max_age(Duration::seconds(ttl_secs))
        .build()
}

pub fn refresh_cookie(name: &str, token: &str, ttl_secs: i64) -> Cookie<'static> {
    Cookie::build((name.to_string(), token.to_string()))
        .path("/refresh-token")
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(true)
        .max_age(Duration::seconds(ttl_secs))
        .build()
}

pub fn clear_cookie(name: &str, path: &str) -> Cookie<'static> {
    Cookie::build((name.to_owned(), String::new()))
        .path(path.to_owned())
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(true)
        .max_age(Duration::seconds(0))
        .build()
}
