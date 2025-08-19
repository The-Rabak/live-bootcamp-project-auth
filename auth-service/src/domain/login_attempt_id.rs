use crate::domain::TwoFAError;
use uuid::*;

#[derive(Debug, Clone, PartialEq)]
pub struct LoginAttemptId(String);

impl LoginAttemptId {
    pub fn parse(id: String) -> Result<Self, TwoFAError> {
        let parsed_id = Uuid::parse_str(&id).map_err(|_| TwoFAError::LoginAttemptIdNotFound)?;
        Ok(LoginAttemptId(parsed_id.to_string()))
    }
}

impl Default for LoginAttemptId {
    fn default() -> Self {
        LoginAttemptId(Uuid::new_v4().to_string())
    }
}

impl AsRef<str> for LoginAttemptId {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}
