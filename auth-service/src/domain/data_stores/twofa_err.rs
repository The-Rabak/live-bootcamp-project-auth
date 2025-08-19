#[derive(Debug, PartialEq)]
pub enum TwoFAError {
    LoginAttemptIdNotFound,
    InvalidToken,
    UnexpectedError,
}
