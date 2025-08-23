use welds::prelude::*;

#[derive(WeldsModel, Clone)]
#[welds(table = "users")]
pub struct UserModel {
    #[welds(primary_key)]
    pub id: i64,
    pub email: String,
    pub password_hash: String,
    #[welds(rename = "requires_2fa")]
    pub requires_mfa: bool,
    pub created_at: i64,
    pub updated_at: i64,
}
