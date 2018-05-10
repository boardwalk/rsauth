#[macro_use]
extern crate serde_derive;

extern crate base64;
extern crate regex;
extern crate serde;
extern crate sodiumoxide;

use regex::Regex;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use sodiumoxide::crypto::pwhash::HashedPassword;
use std::collections::HashMap;

pub struct PasswordHash(pub HashedPassword);

impl<'de> Deserialize<'de> for PasswordHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let b = base64::decode(&s).map_err(serde::de::Error::custom)?;
        let p = HashedPassword::from_slice(&b).ok_or(serde::de::Error::custom("Wrong length"))?;
        Ok(PasswordHash(p))
    }
}

impl Serialize for PasswordHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        base64::encode(&self.0).serialize(serializer)
    }
}

pub struct Pattern(pub Regex);

impl<'de> Deserialize<'de> for Pattern {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let r = Regex::new(&s).map_err(serde::de::Error::custom)?;
        Ok(Pattern(r))
    }
}

#[derive(Deserialize)]
pub struct AuthUser {
    pub password_hash: PasswordHash,
    pub secret_key: Option<String>,
    pub whitelist: Option<Vec<Pattern>>,
}

#[derive(Deserialize)]
pub struct AuthConfig {
    pub domain: String,
    pub users: HashMap<String, AuthUser>,
}
