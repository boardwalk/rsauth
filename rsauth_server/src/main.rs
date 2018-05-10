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

const AUTH_COOKIE_NAME: &'static str = "rsauth";

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
            if let Some(resp) = self.handle_cookie(cookie) {
                return resp;
            }
        }

        if let Some(authorization) = req.headers().get::<Authorization<Basic>>() {
            if let Some(resp) = self.handle_authorization(&req, authorization) {
                return resp;
            }
        }

        self.make_authenticate("Authentication required")
    }

    fn handle_cookie(&self, cookie: &Cookie) -> Option<Response> {
        let val = match cookie.get(AUTH_COOKIE_NAME) {
            Some(val) => val,
            None => return None,
        };

        let _val = match base64::decode(val) {
            Ok(val) => val,
            Err(_) => return Some(self.make_bad_request("Bad base64 cookie value")),
        };

        None // TODO
    }

    fn handle_authorization(
        &self,
        req: &Request,
        authorization: &Authorization<Basic>,
    ) -> Option<Response> {
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
                    None => {
                        return Some(self.make_authenticate(
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
            return Some(self.make_authenticate("Wrong password"));
        }

        let auth_cookie = AuthCookie {
            expires: SystemTime::now() + Duration::from_secs(7 * 24 * 60 * 60),
            username: authorization.username.clone(),
        };

        let auth_cookie = match serde_json::to_string(&auth_cookie) {
            Ok(auth_cookie) => auth_cookie,
            Err(_) => return Some(self.make_server_error("Failed to serialize cookie")),
        };

        let nonce = secretbox::gen_nonce();
        let mut auth_cookie = secretbox::seal(auth_cookie.as_ref(), &nonce, &self.key);
        auth_cookie.extend_from_slice(nonce.as_ref());

        let auth_cookie = base64::encode(&auth_cookie);

        let set_cookie = SetCookie(vec![format!(
            "{}={}; Domain={}; Path=/; Secure; HttpOnly",
            AUTH_COOKIE_NAME, auth_cookie, self.config.domain
        )]);

        let mut headers = Headers::new();
        headers.set(set_cookie);

        Some(self.authorize_request(req, &authorization.username, &headers))
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

    fn make_server_error(&self, text: &'static str) -> Response {
        Response::new()
            .with_status(StatusCode::InternalServerError)
            .with_header(ContentLength(text.len() as u64))
            .with_header(ContentType::plaintext())
            .with_body(text)
    }

    fn authorize_request(&self, req: &Request, username: &str, headers: &Headers) -> Response {
        let user = self.config.users.get(username).unwrap();

        let (status, text) = if let Some(ref whitelist) = user.whitelist {
            let scheme = req.headers().get::<OriginalScheme>().unwrap();
            let host = req.headers().get::<OriginalHost>().unwrap();
            let uri = req.headers().get::<OriginalURI>().unwrap();
            let full_uri = format!("{}://{}{}", scheme.0, host.0, uri.0);

            if whitelist.iter().any(|patt| patt.0.is_match(&full_uri)) {
                (StatusCode::Ok, "Allowed, passed whitelist")
            } else {
                (StatusCode::Forbidden, "Forbidden, failed whitelist")
            }
        } else {
            (StatusCode::Ok, "Allowed, no whitelist")
        };

        let mut headers_copy = headers.clone();
        headers_copy.set(ContentLength(text.len() as u64));
        headers_copy.set(ContentType::plaintext());
        headers_copy.set(User(username.into()));

        Response::new()
            .with_status(status)
            .with_headers(headers_copy)
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
