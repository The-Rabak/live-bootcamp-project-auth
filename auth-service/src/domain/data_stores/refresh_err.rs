#[derive(Debug)]
pub enum RefreshError {
    NotFoundOrExpired,
    Revoked,
    ReuseDetected,
    Internal,
}
