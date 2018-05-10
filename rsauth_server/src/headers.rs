use hyper::error::Error;
use hyper::header::{Header, Raw, Formatter};

fn raw_to_str(raw: &Raw) -> Result<String, Error> {
    let scheme = raw.one().ok_or(Error::Header)?;
    String::from_utf8(Vec::from(scheme)).map_err(|_| Error::Header)
}

#[derive(Clone)]
pub struct WWWAuthenticate;

impl Header for WWWAuthenticate {
    fn header_name() -> &'static str {
        "WWW-Authenticate"
    }

    fn parse_header(_raw: &Raw) -> Result<Self, Error> {
        unimplemented!(); // We don't use the parsing half of this
    }

    fn fmt_header(&self, f: &mut Formatter) -> Result<(), ::std::fmt::Error> {
        f.fmt_line(&String::from("basic realm=Private"))
    }
}


#[derive(Clone)]
pub struct User(pub String);

impl Header for User {
    fn header_name() -> &'static str {
        "User"
    }

    fn parse_header(_raw: &Raw) -> Result<Self, Error> {
        unimplemented!(); // We don't use the parsing half of this
    }

    fn fmt_header(&self, f: &mut Formatter) -> Result<(), ::std::fmt::Error> {
        f.fmt_line(&self.0)
    }
}

#[derive(Clone)]
pub struct OriginalScheme(pub String);

impl Header for OriginalScheme {
    fn header_name() -> &'static str {
        "Original-Scheme"
    }

    fn parse_header(raw: &Raw) -> Result<Self, Error> {
        raw_to_str(raw).map(OriginalScheme)
    }

    fn fmt_header(&self, _f: &mut Formatter) -> Result<(), ::std::fmt::Error> {
        unimplemented!(); // We don't use the formatting half of this
    }
}

#[derive(Clone)]
pub struct OriginalHost(pub String);

impl Header for OriginalHost {
    fn header_name() -> &'static str {
        "Original-Host"
    }

    fn parse_header(raw: &Raw) -> Result<Self, Error> {
        raw_to_str(raw).map(OriginalHost)
    }

    fn fmt_header(&self, _f: &mut Formatter) -> Result<(), ::std::fmt::Error> {
        unimplemented!(); // We don't use the formatting half of this
    }
}

#[derive(Clone)]
pub struct OriginalURI(pub String);

impl Header for OriginalURI {
    fn header_name() -> &'static str {
        "Original-URI"
    }

    fn parse_header(raw: &Raw) -> Result<Self, Error> {
        raw_to_str(raw).map(OriginalURI)
    }

    fn fmt_header(&self, _f: &mut Formatter) -> Result<(), ::std::fmt::Error> {
        unimplemented!(); // We don't use the formatting half of this
    }
}
