#[derive(PartialEq, Debug)]
pub struct User {
    pub email: String,
    pub password: String,
    pub requires_mfa: bool,
}

impl User {
    pub fn new(email: String, password: String, requires_mfa: bool) -> User {
        User{
            email,
            password,
            requires_mfa,
        }
    }
}