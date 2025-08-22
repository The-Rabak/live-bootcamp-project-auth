use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug)]
pub struct VerifyMFARequestBody {
    pub email: String,
    #[serde(
        rename(serialize = "loginAttemptId", deserialize = "login_attempt_id"),
        alias = "loginAttemptId"
    )]
    pub login_attempt_id: String,
    #[serde(
        rename(serialize = "2FACode", deserialize = "mfa_code"),
        alias = "2FACode"
    )]
    pub mfa_code: String,
}
