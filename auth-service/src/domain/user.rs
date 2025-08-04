use super::{email::Email, password::Password};

#[derive(PartialEq, Debug)]
pub struct User {
    pub email: Email,
    pub password: Password,
    pub requires_mfa: bool,
}

impl User {
    pub fn new(email: Email, password: Password, requires_mfa: bool) -> Self {
        User {
            email,
            password,
            requires_mfa,
        }
    }
}
