use jsonwebtoken::{DecodingKey, EncodingKey};
use std::collections::HashMap;

#[derive(Clone)]
pub struct JwtKeyStore {
    // active key used for signing
    active_kid: String,
    // all accepted keys for verifying (kid -> secret)
    keys: HashMap<String, Vec<u8>>,
}

impl JwtKeyStore {
    pub fn from_config(jwt_keys: &[(String, Vec<u8>)], jwt_active_kid: &str) -> Self {
        let mut keys = HashMap::new();
        for (kid, key) in jwt_keys {
            keys.insert(kid.clone(), key.clone());
        }
        Self {
            active_kid: jwt_active_kid.to_string(),
            keys,
        }
    }

    pub fn encoding_key_and_kid(&self) -> (EncodingKey, &str) {
        let secret = self
            .keys
            .get(&self.active_kid)
            .expect("active kid must exist");
        (EncodingKey::from_secret(secret), &self.active_kid)
    }

    pub fn decoding_key_for_kid(&self, kid: Option<&str>) -> Option<DecodingKey> {
        let k = kid.unwrap_or(&self.active_kid);
        self.keys.get(k).map(|s| DecodingKey::from_secret(s))
    }
}
