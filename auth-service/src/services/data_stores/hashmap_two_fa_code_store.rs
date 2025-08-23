use std::collections::HashMap;

use crate::domain::{
    data_stores::{TwoFACodeStore, TwoFAError},
    Email, LoginAttemptId, TwoFACode,
};

#[derive(Default)]
pub struct HashmapTwoFACodeStore {
    codes: HashMap<Email, (LoginAttemptId, TwoFACode)>,
}

#[async_trait::async_trait]
impl TwoFACodeStore for HashmapTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFAError> {
        //if there's an old value for this email address it'll be returned, but we don't care about that
        let _ = self.codes.insert(email, (login_attempt_id, code));
        Ok(())
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFAError> {
        //returns the value matching that key, if exists, but we don't care about that
        let _ = self.codes.remove(email);
        Ok(())
    }

    async fn get_code(&self, email: &Email) -> Result<&(LoginAttemptId, TwoFACode), TwoFAError> {
        match self.codes.get(email) {
            Some(v) => Ok(v),
            None => Err(TwoFAError::LoginAttemptIdNotFound),
        }
    }
}
