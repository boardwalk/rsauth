use ipnetwork::IpNetwork;
use regex::Regex;
use serde::Deserialize;
use serde::de::{Deserializer, Error};
use sodiumoxide::crypto::pwhash::HashedPassword;

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
    pub username: String,
    pub allowed_ips: Option<Vec<IpNetwork>>,
    pub password_hash: Option<PasswordHash>,
    pub secret_key: Option<SecretKey>,
    pub whitelist: Option<Vec<Pattern>>,
}

#[derive(Deserialize)]
pub struct AuthConfig {
    pub domain: String,
    pub users: Vec<AuthUser>,
}
