use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use instant_acme::{Account, AccountCredentials};
use pem::Pem;
use rcgen::KeyPair;

use crate::storage::x509::X509Cert;

pub(crate) type Storage = Arc<StorageInner>;

pub(crate) fn new(location: &PathBuf) -> Storage {
    Arc::new(StorageInner {
        location: location.clone()
    })
}

pub(crate) struct StorageInner {
    location: PathBuf,
}

impl StorageInner {
    pub(crate) async fn get_account(&self, directory: &str) -> Option<AccountCredentials<'static>> {
        let key = escape_string(directory);
        let path = self.location.join("accounts").join(key);

        match tokio::fs::read_to_string(path).await {
            Ok(s) => match serde_json::from_str(&s) {
                Ok(ac) => Some(ac),
                Err(_) => None
            },
            Err(_) => None
        }
    }
    pub(crate) async fn store_account(&self, directory: &str, acct: &Account) -> io::Result<()> {
        let key = escape_string(directory);
        let path = self.location.join("accounts").join(key);

        let creds = acct.credentials();
        let data = serde_json::to_string_pretty(&creds)?;
        create_and_write(path, data).await
    }

    pub(crate) async fn get_certificate(&self, name: &str) -> Option<X509Cert> {
        let key = escape_string(name);
        let path = self.location
            .join("certificates")
            .join(&*key)
            .join("certificate.crt");

        match tokio::fs::read_to_string(path).await {
            Ok(s) => match pem::parse(s) {
                Ok(d) => match X509Cert::from_der(d.contents()) {
                    Ok(c) => Some(c),
                    Err(_) => None,
                },
                Err(_) => None,
            },
            Err(_) => None,
        }
    }

    pub(crate) async fn store_certificate(&self, name: &str, cert: &Pem) -> io::Result<()> {
        let key = escape_string(name);
        let path = self.location
            .join("certificates")
            .join(&*key)
            .join("certificate.crt");

        create_and_write(path, cert.to_string()).await
    }

    pub(crate) async fn store_chain(&self, name: &str, chain: &[Pem]) -> io::Result<()> {
        let key = escape_string(name);
        let path = self.location
            .join("certificates")
            .join(&*key)
            .join("certificate_full_chain.crt");

        let data: String = chain.iter().map(|p| p.to_string()).collect::<Vec<String>>().join("");

        create_and_write(path, data).await
    }

    pub(crate) async fn get_key(&self, name: &str) -> Option<KeyPair> {
        let key = escape_string(name);
        let path = self.location
            .join("certificates")
            .join(&*key)
            .join("certificate.key");

        match tokio::fs::read_to_string(path).await {
            Ok(s) => match KeyPair::from_pem(&*s) {
                Ok(k) => Some(k),
                Err(_) => None,
            },
            Err(_) => None
        }
    }

    pub(crate) async fn store_key(&self, name: &str, pair: &KeyPair) -> io::Result<()> {
        let key = escape_string(name);
        let path = self.location
            .join("certificates")
            .join(&*key)
            .join("certificate.key");

        let data = pair.serialize_pem();

        create_and_write(path, data).await
    }
}

async fn create_and_write(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> io::Result<()> {
    if let Some(parent) = path.as_ref().parent() {
        tokio::fs::create_dir_all(parent).await?
    }
    tokio::fs::write(path, contents).await
}

fn escape_string(string: &str) -> String {
    /*
        # pound
        % percent
        & ampersand
        { left curly bracket
        } right curly bracket
        \ back slash
        < left angle bracket
        > right angle bracket
        * asterisk
        ? question mark
        / forward slash
          blank spaces
        $ dollar sign
        ! exclamation point
        ' single quotes
        " double quotes
        : colon
        @ at sign
        + plus sign
        ` backtick
        | pipe
        = equal sign
     */
    string.replace(['#', '%', '&', '{', '}', '\\', '<', '>', '*', '?', '/', ' ', '$', '!', '\'', '"', ':', '@', '+', '`', '|', '='], "_")
}

pub mod x509 {
    use std::fmt;

    use ouroboros::self_referencing;
    use x509_parser::{certificate::X509Certificate, prelude::FromDer};

    #[self_referencing]
    pub struct X509Cert {
        der_buf: Vec<u8>,
        #[borrows(der_buf)]
        #[covariant]
        cert: X509Certificate<'this>,
    }

    impl X509Cert {
        pub fn from_der(der: &[u8]) -> Result<Self, ()> {
            // Because we're self-referencing the buffer and the parsed certificate
            // we need to parse it twice.
            // Once to get the actual length of the buffer (and cut off any tail).
            // And a second time to actually store the parsed value.

            let (rest, _cert) = X509Certificate::from_der(der).map_err(|_| ())?;
            let der_buf: Vec<u8> = der[..(der.len() - rest.len())].into();

            X509CertTryBuilder {
                der_buf,
                cert_builder: |buf| match X509Certificate::from_der(&buf[..]) {
                    Err(_) => Err(()),
                    Ok((_rest, cert)) => Ok(cert),
                },
            }
                .try_build()
        }

        pub fn cert(&self) -> &X509Certificate<'_> {
            self.borrow_cert()
        }
    }

    impl fmt::Debug for X509Cert {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.borrow_cert().fmt(f)
        }
    }
}