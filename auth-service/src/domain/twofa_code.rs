use rand::Rng;

use crate::domain::TwoFAError;

#[derive(Clone, Debug, PartialEq)]
pub struct TwoFACode(String);

impl TwoFACode {
    pub fn parse(code: String) -> Result<Self, TwoFAError> {
        // Ensure `code` is a valid 6-digit code
        match code.chars().count() {
            6 => Ok(TwoFACode(code)),
            _ => Err(TwoFAError::InvalidToken),
        }
    }
}

impl Default for TwoFACode {
    fn default() -> Self {
        TwoFACode(rand::rng().random_range(100_000..=999_999).to_string())
    }
}

impl AsRef<str> for TwoFACode {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
