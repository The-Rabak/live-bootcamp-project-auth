#[derive(Debug, PartialEq)]
pub enum BannedTokenStoreErr {
    TokenExists,
    UnexpectedError,
}
