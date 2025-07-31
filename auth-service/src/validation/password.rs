use once_cell::sync::Lazy;
use regex::Regex;

static UPPER_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[A-Z]").unwrap());
static SPECIAL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[^A-Za-z0-9]").unwrap());

/// True if pw is ≥8 chars, has at least one uppercase and one special char
pub fn is_valid_password(pw: &str) -> bool {
    pw.len() >= 8 && UPPER_RE.is_match(pw) && SPECIAL_RE.is_match(pw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_short_or_simple() {
        assert!(!is_valid_password("Short!"));        // too short
        assert!(!is_valid_password("alllowercase!")); // no uppercase
        assert!(!is_valid_password("NOUPPERCASE1"));  // no special
    }

    #[tokio::test]
    async fn accepts_good_passwords() {
        assert!(is_valid_password("Rustacean!"));
        assert!(is_valid_password("P@ssW0rd123"));
    }
}