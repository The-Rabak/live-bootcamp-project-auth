use welds::prelude::*;

#[derive(WeldsModel)]
#[welds(table = "users")]
pub struct UserModel {
    #[welds(primary_key)]
    pub id: i32,
    pub email: String,
    pub password_hash: String,
    pub created_at: i32,
    pub updated_at: i32,
}
