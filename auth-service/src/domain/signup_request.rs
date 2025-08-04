use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug)]
pub struct SignupRequestBody {
    pub email: String,
    pub password: String,
    #[serde(
        rename(serialize = "requires2fa", deserialize = "requires_mfa"),
        alias = "requires2fa"
    )]
    pub requires_mfa: bool,
}
