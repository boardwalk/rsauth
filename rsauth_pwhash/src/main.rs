extern crate rsauth_common;
extern crate serde_json;
extern crate sodiumoxide;

use rsauth_common::PasswordHash;
use serde_json::to_string;
use sodiumoxide::crypto::pwhash::{pwhash, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE};

fn main() {
    let pw = pwhash(b"snazbottom", OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE).unwrap();
    let s = to_string(&PasswordHash(pw)).unwrap();
    println!("Hashed password: {}", s);
}
