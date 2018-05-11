extern crate rsauth_common;
extern crate sodiumoxide;

use rsauth_common::encode_base32;
use sodiumoxide::crypto::pwhash::{pwhash, MEMLIMIT_INTERACTIVE, OPSLIMIT_INTERACTIVE};
use std::io::{stdin, stdout, Read, Write};

fn main() {
    let mut pass = Vec::new();
    stdin().read_to_end(&mut pass).unwrap();

    let hashed_pass = pwhash(&pass, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE).unwrap();
    let hashed_pass = encode_base32(hashed_pass.as_ref());

    stdout().write_all(hashed_pass.as_ref()).unwrap();
}
