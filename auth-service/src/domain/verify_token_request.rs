use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug)]
pub struct VerifyTokenRequestBody {
    pub token: String,
}
