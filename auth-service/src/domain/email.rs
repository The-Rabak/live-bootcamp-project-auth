use crate::validation::is_valid_email;

#[derive(PartialEq, Debug, Clone, Eq, Hash)]
pub struct Email(String);

impl Email {
    pub fn parse(email: String) -> Result<Email, String> {
        match is_valid_email(&email) {
            true => Ok(Email(email)),
            false => Err(format!("Email {} is not valid", email)),
        }
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
