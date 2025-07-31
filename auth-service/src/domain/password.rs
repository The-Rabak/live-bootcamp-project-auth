use std::fmt::format;

use crate::validation::is_valid_password;

#[derive(PartialEq, Debug)]
pub struct Password(String);

impl Password {
    pub fn parse(password: String) -> Result<Password, String> {
        match is_valid_password(&password) {
            true => Ok(Password(password)),
            false => Err(format!("Password is not valid, must be at least 8 characters long, contain at least one uppercase letter and one special character.")),
        }
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}