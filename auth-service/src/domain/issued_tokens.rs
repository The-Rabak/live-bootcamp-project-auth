use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct IssuedTokens {
    pub user_id: String,
    pub session_id: Uuid,
    pub access_token: String,
    pub refresh_token: String,
}
