use crate::domain::{Email, LoginAttemptId, TwoFACode, TwoFAError};

// This trait represents the interface all concrete 2FA code stores should implement
#[async_trait::async_trait]
pub trait TwoFACodeStore: Send + Sync {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFAError>;
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFAError>;
    async fn get_code(&self, email: &Email) -> Result<&(LoginAttemptId, TwoFACode), TwoFAError>;
}
