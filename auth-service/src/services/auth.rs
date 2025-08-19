use crate::app_state::AppState;
use crate::domain::{Email, Password, User, UserStoreError};
use crate::errors::{LoginError, SignupError};

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

    pub async fn login(
        state: AppState,
        email: Email,
        password: Password,
    ) -> Result<User, LoginError> {
        match state
            .user_store
            .write()
            .await
            .validate_user(email.clone(), password)
            .await
        {
            Err(UserStoreError::UserNotFound) => {
                Err(LoginError::UserNotFound(email.as_ref().to_string()))
            }
            Err(_) => Err(LoginError::InternalServerError),
            Ok(user) => Ok(user),
        }
    }
}
