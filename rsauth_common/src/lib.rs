#[macro_use]
extern crate serde_derive;

extern crate base32;
extern crate regex;
extern crate serde;
extern crate sodiumoxide;

use regex::Regex;
use serde::de::{Deserialize, Deserializer, Error};
use serde::ser::{Serialize, Serializer};
use sodiumoxide::crypto::pwhash::HashedPassword;
use std::collections::HashMap;

pub fn encode_base32(b: &[u8]) -> String {
    base32::encode(base32::Alphabet::RFC4648 { padding: true }, b)
}

pub fn decode_base32(s: &str) -> Option<Vec<u8>> {
    base32::decode(base32::Alphabet::RFC4648 { padding: true }, s)

}

pub struct PasswordHash(pub HashedPassword);

impl<'de> Deserialize<'de> for PasswordHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let b = decode_base32(&s).ok_or_else(|| Error::custom("Invalid base32"))?;
        let p = HashedPassword::from_slice(&b).ok_or_else(|| Error::custom("Wrong length"))?;
        Ok(PasswordHash(p))
    }
}

impl Serialize for PasswordHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        encode_base32(&self.0.as_ref()).serialize(serializer)
    }
}

pub struct SecretKey(pub Vec<u8>);

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let b = decode_base32(&s).ok_or_else(|| Error::custom("Invalid base32"))?;
        Ok(SecretKey(b))
    }
}

pub struct Pattern(pub Regex);

impl<'de> Deserialize<'de> for Pattern {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let r = Regex::new(&s).map_err(Error::custom)?;
        Ok(Pattern(r))
    }
}

#[derive(Deserialize)]
pub struct AuthUser {
    pub password_hash: PasswordHash,
    pub secret_key: Option<SecretKey>,
    pub whitelist: Option<Vec<Pattern>>,
}

#[derive(Deserialize)]
pub struct AuthConfig {
    pub domain: String,
    pub users: HashMap<String, AuthUser>,
}
