use once_cell::sync::Lazy;
use regex::Regex;

static EMAIL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?xi) ^[A-Z0-9._%+-]+@[A-Z0-9-]+(?:\.[A-Z0-9-]+)*\.[A-Z]{2,}$")
        .unwrap()
});

pub fn is_valid_email(email: &str) -> bool {
    EMAIL_RE.is_match(email)
}