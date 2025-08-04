use crate::app_state::AppState;
use crate::domain::{Email, Password};
use crate::errors::SignupError;
use crate::proto::{SignupRequest, SignupResponse};
use crate::services::AuthService;
use tonic::{Request, Response, Status};

#[derive(Clone)]
pub struct AuthGrpc {
    pub state: AppState,
}

#[tonic::async_trait]
impl crate::proto::auth_server::Auth for AuthGrpc {
    async fn signup(
        &self,
        request: Request<SignupRequest>,
    ) -> Result<Response<SignupResponse>, Status> {
        let req = request.into_inner();
        let email = Email::parse(req.email).or(Err(Status::invalid_argument("invalid email")))?;
        let password =
            Password::parse(req.password).or(Err(Status::invalid_argument("invalid password")))?;
        AuthService::signup(self.state.clone(), email, password, req.requires_mfa)
            .await
            .map_err(|e| match e {
                SignupError::UserAlreadyExists(message) => Status::already_exists(message),
                SignupError::InternalServerError | _ => Status::internal("internal server error"),
            })?;

        Ok(Response::new(SignupResponse { success: true }))
    }
}
