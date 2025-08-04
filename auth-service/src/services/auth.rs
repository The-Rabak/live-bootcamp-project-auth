use crate::app_state::AppState;
use crate::domain::{Email, Password, User, UserStoreError};
use crate::errors::SignupError;

pub struct AuthService {}
impl AuthService {
    pub fn new() -> Self {
        AuthService {}
    }

    pub async fn signup(
        state: AppState,
        email: Email,
        password: Password,
        requires_mfa: bool,
    ) -> Result<(), SignupError> {
        let user = User::new(email.clone(), password, requires_mfa);
        let result = state.user_store.write().await.add_user(user).await;
        result.map_err(|e| match e {
            UserStoreError::UserAlreadyExists => {
                SignupError::UserAlreadyExists(email.as_ref().to_string())
            }
            _ => SignupError::InternalServerError,
        })?;
        Ok(())
    }
}
