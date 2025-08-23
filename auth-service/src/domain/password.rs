use crate::validation::is_valid_password;

#[derive(PartialEq, Debug, Clone)]
pub struct Password(String);

impl Password {
    pub fn parse(password: String) -> Result<Self, String> {
        match is_valid_password(&password) {
            true => Ok(Self(password)),
            false => Err(format!("Password is not valid, must be at least 8 characters long, contain at least one uppercase letter and one special character.")),
        }
    }
    pub fn from_hash(password_hash: String) -> Self {
        Self(password_hash)
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
