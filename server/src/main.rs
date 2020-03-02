mod totp;

use hyper::{Body, Error, HeaderMap, Request, Response, StatusCode};
use hyper::header::{AsHeaderName, HeaderValue, self};
use hyper::server::Server;
use hyper::service::{make_service_fn, service_fn};
use rsauth_common::*;
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::pwhash::pwhash_verify;
use sodiumoxide::crypto::secretbox::xsalsa20poly1305 as secretbox;
use std::env;
use std::fs::File;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

const COOKIE_NAME: &str = "rsauth";

#[derive(Serialize, Deserialize)]
pub struct AuthCookie {
    expires: SystemTime,
    username: String,
}

struct Context {
    config: AuthConfig,
    key: secretbox::Key,
}

impl Context {
    pub fn new() -> Self {
        let path = format!("{}/.config/rsauth.json", env::var("HOME").unwrap());
        let file = File::open(path).unwrap();
        let config = serde_json::from_reader(file).unwrap();
        let key = secretbox::gen_key();
        Self { config, key }
    }
}

fn handle(context: &Context, req: &Request<Body>) -> Response<Body> {
    if let Some(cookie) = get_header(req.headers(), header::COOKIE) {
        if let Some(resp) = handle_cookie(context, req, cookie) {
            return resp;
        }
    }

    if let Some(authorization) = get_header(req.headers(), header::AUTHORIZATION) {
        if let Some((username, password)) = parse_basic_authorization(authorization) {
            if let Some(resp) = handle_authorization(context, req, &username, &password) {
                return resp;
            }
        }
    }

    if let Some(resp) = handle_passwordless(context, req) {
        return resp;
    }

    make_authenticate("Authentication required")
}

fn handle_cookie(context: &Context, req: &Request<Body>, cookie: &str) -> Option<Response<Body>> {
    let val = match get_cookie(COOKIE_NAME, cookie) {
        Some(val) => val,
        None => return None, // Our cookie not given
    };

    let val = match decode_base32(val) {
        Some(val) => val,
        None => return None, // Ignore bad cookie
    };

    if val.len() < secretbox::NONCEBYTES {
        return None; // Ignore bad cookie
    }

    let (cookie, nonce) = val.split_at(val.len() - secretbox::NONCEBYTES);
    let nonce = secretbox::Nonce::from_slice(nonce).unwrap();

    let cookie = match secretbox::open(cookie, &nonce, &context.key) {
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

    Some(authorize_request(context, req, &cookie.username, HeaderMap::new()))
}

fn handle_authorization(context: &Context, req: &Request<Body>, username: &str, credentials: &str) -> Option<Response<Body>> {
    let user = match context.config.users.get(username) {
        Some(user) => user,
        None => return Some(make_authenticate("No such user")),
    };

    let password = match user.secret_key {
        Some(ref secret_key) => {
            if credentials.len() < totp::TOTP_LEN {
                return Some(make_authenticate("Password too short for TOTP code"));
            }

            let totp_code = &credentials[..totp::TOTP_LEN];
            let expected_totp_code = totp::calc_totp(&secret_key.0, SystemTime::now());

            if totp_code != expected_totp_code {
                return Some(make_authenticate("Wrong TOTP code"));
            }

            &credentials[totp::TOTP_LEN..]
        }
        None => credentials,
    };

    let pw_hash = match user.password_hash {
        Some(ref pw_hash) => pw_hash,
        None => return Some(make_authenticate("No password hash for this user")),
    };

    if !pwhash_verify(&pw_hash.0, password.as_ref()) {
        return Some(make_authenticate("Wrong password"));
    }

    let cookie = AuthCookie {
        expires: SystemTime::now() + Duration::from_secs(7 * 24 * 60 * 60),
        username: username.to_string(),
    };

    let cookie = match serde_json::to_string(&cookie) {
        Ok(cookie) => cookie,
        Err(_) => return Some(make_server_error("Failed to serialize cookie")),
    };

    let nonce = secretbox::gen_nonce();
    let mut cookie = secretbox::seal(cookie.as_ref(), &nonce, &context.key);
    cookie.extend_from_slice(nonce.as_ref());

    let cookie = encode_base32(&cookie);
    let cookie = format!(
        "{}={}; Domain={}; Path=/; Expires=Fri, 13 May, 2050 00:00:00 GMT; Secure; HttpOnly",
        COOKIE_NAME, cookie, context.config.domain
    );

    let mut headers = HeaderMap::new();
    headers.insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    Some(authorize_request(context, req, username, headers))
}

fn get_header<H>(headers: &HeaderMap<HeaderValue>, header: H) -> Option<&str>
where
    H: AsHeaderName,
{
    match headers.get(header) {
        Some(value) => match value.to_str() {
            Ok(s) => Some(s),
            Err(_) => None,
        },
        None => None,
    }
}

fn handle_passwordless(context: &Context, req: &Request<Body>) -> Option<Response<Body>> {
    let ip: IpAddr = match get_header(req.headers(), "Real-IP") {
        Some(s) => match s.parse() {
            Ok(ip) => ip,
            Err(_) => return Some(make_bad_request("Invalid Real-IP")),
        },
        None => return Some(make_bad_request("Missing Real-IP")),
    };

    for (username, user) in &context.config.users {
        if let Some(allowed_ips) = &user.allowed_ips {
            if allowed_ips.iter().find(|aip| *aip == &ip).is_some() {
                // Good!
            } else if user.password_hash.is_none() {
                // Good!
            } else {
                continue; // Not good :(
            }
        } else {
            if user.password_hash.is_none() {
                // Good!
            } else {
                continue; // Not good :(
            }
        }

        let resp = authorize_request(context, req, username, HeaderMap::new());
        if resp.status() == StatusCode::OK {
            return Some(resp);
        }
    }

    None
}

fn authorize_request(context: &Context, req: &Request<Body>, username: &str, mut headers: HeaderMap<HeaderValue>) -> Response<Body> {
    let uri = match get_header(req.headers(), "Original-URI") {
        Some(uri) => uri,
        None => return make_bad_request("Missing Original-URI"),
    };

    let user = &context.config.users[username];
    let (status, text) = if let Some(ref whitelist) = user.whitelist {
        if whitelist.iter().any(|patt| patt.0.is_match(uri)) {
            (StatusCode::OK, "Allowed, passed whitelist")
        } else {
            (StatusCode::FORBIDDEN, "Forbidden, failed whitelist")
        }
    } else {
        (StatusCode::OK, "Allowed, no whitelist")
    };

    headers.insert("User", HeaderValue::from_str(username).unwrap());
    make_response(status, text, headers)
}

fn make_authenticate(text: &'static str) -> Response<Body> {
    let mut headers = HeaderMap::new();
    headers.insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("basic realm=Private"));
    make_response(StatusCode::UNAUTHORIZED, text, headers)
}

fn make_bad_request(text: &'static str) -> Response<Body> {
    make_response(StatusCode::BAD_REQUEST, text, HeaderMap::new())
}

fn make_server_error(text: &'static str) -> Response<Body> {
    make_response(StatusCode::INTERNAL_SERVER_ERROR, text, HeaderMap::new())
}

fn make_response(status: StatusCode, body: &'static str, mut headers: HeaderMap<HeaderValue>) -> Response<Body> {
    let mut resp = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=UTF-8"))
        .body(Body::from(body))
        .unwrap();

    let mut last_name = None;
    for (name, value) in headers.drain() {
        if name.is_some() {
            last_name = name;
        }

        resp.headers_mut().insert(last_name.as_ref().unwrap().clone(), value);
    }

    resp
}

fn get_cookie<'a>(name: &str, cookies: &'a str) -> Option<&'a str> {
    for cookie in cookies.split("; ") {
        if let Some(sep) = cookie.find('=') {
            if &cookie[..sep] == name {
                return Some(&cookie[sep + 1..]);
            }
        }
    }

    None
}

fn parse_basic_authorization(authorization: &str) -> Option<(String, String)> {
    if !authorization.starts_with("Basic ") {
        return None;
    }

    let user_pass = match base64::decode(&authorization["Basic ".len()..]) {
        Ok(user_pass) => user_pass,
        Err(_) => return None,
    };

    let user_pass = match String::from_utf8(user_pass) {
        Ok(user_pass) => user_pass,
        Err(_) => return None,
    };

    let sep = match user_pass.find(':') {
        Some(sep) => sep,
        None => return None,
    };

    let username = user_pass[..sep].to_string();
    let password = user_pass[sep + 1..].to_string();
    Some((username, password))
}

#[tokio::main]
async fn main() {
    let addr = ([127, 0, 0, 1], 3204).into();

    let context = Arc::new(Context::new());

    let make_service = make_service_fn(move |_| {
        let context = context.clone();
        async move {
            let context = context.clone();
            Ok::<_, Error>(service_fn(move |req| {
                let context = context.clone();
                async move {
                    Ok::<_, Error>(handle(&*context, &req))
                }
            }))
        }
    });

    let server = Server::bind(&addr).serve(make_service);
    server.await.unwrap();
}
