use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug)]
pub struct LoginRequestBody {
    pub email: String,
    pub password: String
}
