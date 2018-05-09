extern crate base64;
extern crate futures;
extern crate hyper;
extern crate rsauth_common;
extern crate serde_json;
extern crate serde;
extern crate sodiumoxide;

use futures::Future;
use hyper::StatusCode;
use hyper::error::Error;
use hyper::header::{Authorization, Basic, ContentLength, ContentType, Cookie, Header, Raw, Formatter};
use hyper::server::{Http, Request, Response, Service, const_service};
use std::env;
use std::fs::File;
use sodiumoxide::crypto::secretbox::xsalsa20poly1305 as secretbox;
use sodiumoxide::crypto::pwhash::pwhash_verify;
use rsauth_common::AuthConfig;

#[derive(Clone)]
pub struct WWWAuthenticate;

impl Header for WWWAuthenticate {
    fn header_name() -> &'static str {
        "WWW-Authenticate"
    }

    fn parse_header(_raw: &Raw) -> Result<Self, Error> {
        Ok(WWWAuthenticate) // We don't use the parsing half of this
    }

    fn fmt_header(&self, f: &mut Formatter) -> Result<(), ::std::fmt::Error> {
        f.fmt_line(&String::from("basic realm=Private"))
    }
}

struct AuthService {
    config: AuthConfig,
}

impl AuthService {
    pub fn new() -> AuthService {
        let path = format!("{}/.config/pyauth.json", env::var("HOME").unwrap());
        let file = File::open(path).unwrap();
        let config = serde_json::from_reader(file).unwrap();
        AuthService { config }
    }

    fn handle(&self, req: Request) -> Response {
        if let Some(cookie) = req.headers().get::<Cookie>() {
            if let Some(resp) = self.handle_cookie(cookie) {
                return resp;
            }
        }

        if let Some(authorization) = req.headers().get::<Authorization<Basic>>() {
            if let Some(resp) = self.handle_authorization(authorization) {
                return resp;
            }
        }

        self.make_authenticate("Authentication required")
    }

    fn handle_cookie(&self, cookie: &Cookie) -> Option<Response> {
        let val = match cookie.get("pyauth") {
            Some(val) => val,
            None => return None,
        };

        let _val = match base64::decode(val) {
            Ok(val) => val,
            Err(_) => return Some(self.make_bad_request("Bad base64 cookie value")),
        };

        None // TODO
    }

    fn handle_authorization(&self, authorization: &Authorization<Basic>) -> Option<Response> {
        let credentials = match authorization.password {
            Some(ref password) => password,
            None => return Some(self.make_bad_request("Missing credentials")),
        };

        let user = match self.config.users.get(&authorization.username) {
            Some(user) => user,
            None => return Some(self.make_authenticate("No such user")),
        };

        let password = match user.secret_key {
            Some(ref _secret_key) => {
                let colon = match credentials.find(':') {
                    Some(colon) => colon,
                    None => return Some(self.make_authenticate("Missing TOTP code (use totp_code:password)")),
                };

                let _totp_code = &credentials[..colon];
                // TODO check totp_code against secret_key

                &credentials[colon + 1..]
            }
            None => credentials,
        };

        if !pwhash_verify(&user.password_hash.0, password.as_ref()) {
            return Some(self.make_authenticate("Wrong password"));
        }

        // let hashed_password = match self.config

        println!("password: {}", password);
        None // TODO
    }

    fn make_authenticate(&self, text: &'static str) -> Response {
        Response::new()
            .with_status(StatusCode::Unauthorized)
            .with_header(WWWAuthenticate)
            .with_header(ContentLength(text.len() as u64))
            .with_header(ContentType::plaintext())
            .with_body(text)
    }

    fn make_bad_request(&self, text: &'static str) -> Response {
        Response::new()
            .with_status(StatusCode::BadRequest)
            .with_header(ContentLength(text.len() as u64))
            .with_header(ContentType::plaintext())
            .with_body(text)
    }
}

impl Service for AuthService {
    type Request = Request;
    type Response = Response;
    type Error = Error;
    type Future = Box<Future<Item = Self::Response, Error = Error>>;

    fn call(&self, req: Self::Request) -> Self::Future {
        Box::new(futures::finished(self.handle(req)))
    }
}

fn main() {
    let addr = ([127, 0, 0, 1], 3204).into();

    let new_service = const_service(AuthService::new());

    let server = Http::new()
        .sleep_on_errors(true)
        .bind(&addr, new_service)
        .unwrap();

    server.run().unwrap();
}
