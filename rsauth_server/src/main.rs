#[macro_use]
extern crate serde_derive;

extern crate base64;
extern crate futures;
extern crate hyper;
extern crate rsauth_common;
extern crate serde;
extern crate serde_json;
extern crate sodiumoxide;

mod headers;

use futures::Future;
use headers::*;
use hyper::error::Error;
use hyper::header::{Authorization, Basic, ContentLength, ContentType, Cookie, Headers, SetCookie};
use hyper::server::{const_service, Http, Request, Response, Service};
use hyper::StatusCode;
use rsauth_common::AuthConfig;
use sodiumoxide::crypto::pwhash::pwhash_verify;
use sodiumoxide::crypto::secretbox::xsalsa20poly1305 as secretbox;
use std::env;
use std::fs::File;
use std::time::{Duration, SystemTime};

const COOKIE_NAME: &'static str = "rsauth";

#[derive(Serialize, Deserialize)]
pub struct AuthCookie {
    expires: SystemTime,
    username: String,
}

struct AuthService {
    config: AuthConfig,
    key: secretbox::Key,
}

impl AuthService {
    pub fn new() -> AuthService {
        let path = format!("{}/.config/pyauth.json", env::var("HOME").unwrap());
        let file = File::open(path).unwrap();
        let config = serde_json::from_reader(file).unwrap();
        let key = secretbox::gen_key();
        AuthService { config, key }
    }

    fn handle(&self, req: Request) -> Response {
        if let Some(cookie) = req.headers().get::<Cookie>() {
            if let Some(resp) = self.handle_cookie(&req, cookie) {
                return resp;
            }
        }

        if let Some(authorization) = req.headers().get::<Authorization<Basic>>() {
            if let Some(resp) = self.handle_authorization(&req, authorization) {
                return resp;
            }
        }

        Self::make_authenticate("Authentication required")
    }

    fn handle_cookie(&self, req: &Request, cookie: &Cookie) -> Option<Response> {
        let val = match cookie.get(COOKIE_NAME) {
            Some(val) => val,
            None => return None, // Our cookie not given
        };

        let val = match base64::decode(val) {
            Ok(val) => val,
            Err(_) => return None, // Ignore bad cookie
        };

        if val.len() < secretbox::NONCEBYTES {
            return None; // Ignore bad cookie
        }

        let (cookie, nonce) = val.split_at(val.len() - secretbox::NONCEBYTES);
        let nonce = secretbox::Nonce::from_slice(nonce).unwrap();

        let cookie = match secretbox::open(cookie, &nonce, &self.key) {
            Ok(cookie) => cookie,
            Err(_) => return None, // Ignore bad cookie
        };

        // We're going to unwrap() here because a failure here means our key has probably been
        // compromised and we should crash the service
        let cookie = String::from_utf8(cookie).unwrap();
        let cookie: AuthCookie = serde_json::from_str(&cookie).unwrap();

        if cookie.expires < SystemTime::now() {
            return None; // Ignore expired cookie
        }

        Some(self.authorize_request(req, &cookie.username, Headers::new()))
    }

    fn handle_authorization(
        &self,
        req: &Request,
        authorization: &Authorization<Basic>,
    ) -> Option<Response> {
        let credentials = match authorization.password {
            Some(ref password) => password,
            None => return Some(Self::make_bad_request("Missing credentials")),
        };

        let user = match self.config.users.get(&authorization.username) {
            Some(user) => user,
            None => return Some(Self::make_authenticate("No such user")),
        };

        let password = match user.secret_key {
            Some(ref _secret_key) => {
                let colon = match credentials.find(':') {
                    Some(colon) => colon,
                    None => {
                        return Some(Self::make_authenticate(
                            "Missing TOTP code (use totp_code:password)",
                        ))
                    }
                };

                let _totp_code = &credentials[..colon];
                // TODO check totp_code against secret_key

                &credentials[colon + 1..]
            }
            None => credentials,
        };

        if !pwhash_verify(&user.password_hash.0, password.as_ref()) {
            return Some(Self::make_authenticate("Wrong password"));
        }

        let cookie = AuthCookie {
            expires: SystemTime::now() + Duration::from_secs(7 * 24 * 60 * 60),
            username: authorization.username.clone(),
        };

        let cookie = match serde_json::to_string(&cookie) {
            Ok(cookie) => cookie,
            Err(_) => return Some(Self::make_server_error("Failed to serialize cookie")),
        };

        let nonce = secretbox::gen_nonce();
        let mut cookie = secretbox::seal(cookie.as_ref(), &nonce, &self.key);
        cookie.extend_from_slice(nonce.as_ref());

        let cookie = base64::encode(&cookie);
        let cookie = format!(
            "{}={}; Domain={}", //; Secure; HttpOnly",
            COOKIE_NAME, cookie, self.config.domain
        );

        let mut headers = Headers::new();
        headers.set(SetCookie(vec![cookie]));
        Some(self.authorize_request(req, &authorization.username, headers))
    }

    fn authorize_request(&self, req: &Request, username: &str, mut headers: Headers) -> Response {
        // We can only get this far if the user exists
        let user = self.config.users.get(username).unwrap();

        let (status, text) = if let Some(ref whitelist) = user.whitelist {
            let uri = match req.headers().get::<OriginalURI>() {
                Some(uri) => &uri.0,
                None => return Self::make_bad_request("Missing Original-URI"),
            };

            if whitelist.iter().any(|patt| patt.0.is_match(uri)) {
                (StatusCode::Ok, "Allowed, passed whitelist")
            } else {
                (StatusCode::Forbidden, "Forbidden, failed whitelist")
            }
        } else {
            (StatusCode::Ok, "Allowed, no whitelist")
        };

        headers.set(User(username.into()));
        Self::make_response(status, text, headers)
    }

    fn make_authenticate(text: &'static str) -> Response {
        let mut headers = Headers::new();
        headers.set(WWWAuthenticate);
        Self::make_response(StatusCode::Unauthorized, text, headers)
    }

    fn make_bad_request(text: &'static str) -> Response {
        Self::make_response(StatusCode::BadRequest, text, Headers::new())
    }

    fn make_server_error(text: &'static str) -> Response {
        Self::make_response(StatusCode::InternalServerError, text, Headers::new())
    }

    fn make_response(status: StatusCode, text: &'static str, mut headers: Headers) -> Response {
        headers.set(ContentLength(text.len() as u64));
        headers.set(ContentType::plaintext());
        Response::new()
            .with_status(status)
            .with_headers(headers)
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
