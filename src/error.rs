use std::{fmt, io};

use pem::PemError;
use rcgen::RcgenError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Hyper(hyper::Error),
    Pem(PemError),
    Cert(RcgenError),
    Storage(String),
    /// instant_acme error
    Acme(instant_acme::Error),
    /// std::io error.
    Io(io::Error),
    /// Some other error. Notice that `Error` is
    /// `From<String>` and `From<&str>` and it becomes `Other`.
    Other(String),
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Hyper(e) => write!(f, "{}", e),
            Error::Pem(p) => write!(f, "{}", p),
            Error::Cert(c) => write!(f, "{}", c),
            Error::Storage(s) => write!(f, "{}", s),
            Error::Acme(a) => write!(f, "{}", a),
            Error::Io(i) => write!(f, "{}", i),
            Error::Other(s) => write!(f, "{}", s),
        }
    }
}

impl From<hyper::Error> for Error {
    fn from(value: hyper::Error) -> Self {
        Error::Hyper(value)
    }
}

impl From<PemError> for Error {
    fn from(value: PemError) -> Self {
        Error::Pem(value)
    }
}

impl From<RcgenError> for Error {
    fn from(value: RcgenError) -> Self {
        Error::Cert(value)
    }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Error::Storage(value.to_string())
    }
}

impl From<instant_acme::Error> for Error {
    fn from(value: instant_acme::Error) -> Self {
        Error::Acme(value)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Other(s)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Other(s.to_string())
    }
}
