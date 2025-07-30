use serde::{Serialize, Deserialize};

#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct SignupResponse {
    pub message: String,
}