use std::collections::HashSet;
use std::fs::File;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use clap::Parser;
use hcl::from_reader;
use hyper::body::Buf;
use hyper::client::HttpConnector;
use hyper::header::CONTENT_TYPE;
use hyper::{Method, Request};
use hyper_rustls::HttpsConnector;
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewOrder, OrderStatus,
};
use rcgen::{Certificate, CertificateParams, DistinguishedName, KeyPair, PKCS_ECDSA_P384_SHA384};
use serde::Deserialize;
use serde_json::json;
use tokio::runtime::Builder;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use x509_parser::nom::AsBytes;
use x509_parser::time::ASN1Time;

use config::{AccountInfo, CertificateInfo, Config};
use storage::Storage;

use crate::config::AcmeDnsConfig;
use crate::error::Error;
use crate::error::Error::Acme;
use crate::storage::x509::X509Cert;
use crate::Decision::{DoNotRenew, Renew};
use crate::Reason::{Names, ThirtyDays, ValidityPeriod};

mod config;
mod error;
mod storage;

fn main() {
    let args = Cli::parse();

    let conf: Config = match File::open(&args.config) {
        Ok(f) => match from_reader(f) {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "level=FATAL msg=\"{}\" file=\"{}\" err=\"{}\"",
                    "couldn't parse config file",
                    &args.config.display(),
                    e
                );
                std::process::exit(exitcode::CONFIG);
            }
        },
        Err(e) => {
            eprintln!(
                "level=FATAL msg=\"{}\" file=\"{}\" err=\"{}\"",
                "couldn't open config file",
                &args.config.display(),
                e
            );
            std::process::exit(exitcode::OSFILE);
        }
    };

    let runtime = Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(manage_certs(conf))
}

fn get_client() -> hyper::Client<HttpsConnector<HttpConnector>, String> {
    hyper::Client::builder().build(
        hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .https_only()
            .enable_http1()
            .enable_http2()
            .build(),
    )
}

async fn manage_certs(cfg: Config) {
    let storage = storage::new(&cfg.storage);

    let account = match get_account(&cfg.account, storage.clone()).await {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: couldn't obtain account: {}", e);
            return;
        }
    };

    println!("got account for directory {}", cfg.account.directory);

    let mut cert_handles: Vec<JoinHandle<error::Result<()>>> = vec![];

    for (name, cert) in cfg.certificates.into_iter() {
        let _account = account.clone();
        let _storage = storage.clone();
        cert_handles.push(tokio::spawn(async move {
            process_certificate(&*name, cert, _account, _storage).await
        }))
    }

    for task in cert_handles {
        match task.await.expect("error: unable to join") {
            Ok(_) => {}
            Err(e) => eprintln!("error: while managing certificate: {}", e),
        }
    }

    if let Err(e) = storage
        .store_account(&*cfg.account.directory, &account)
        .await
    {
        eprintln!("error: unable to save account information: {}", e);
    }
}

async fn get_account(acct_info: &AccountInfo, storage: Storage) -> error::Result<Account> {
    // first try to load from cache
    match storage.get_account(&acct_info.directory).await {
        Some(ac) => match Account::from_credentials(ac) {
            Ok(a) => Ok(a),
            Err(e) => Err(e.into()),
        },
        None => {
            let mailto = "mailto:".to_owned() + &acct_info.email;
            match Account::create(
                &instant_acme::NewAccount {
                    contact: &vec![&*mailto],
                    terms_of_service_agreed: acct_info.accept_terms,
                    only_return_existing: false,
                },
                &acct_info.directory,
                None,
            )
            .await
            {
                Ok(a) => {
                    println!("Created new account for {}", acct_info.directory);
                    match storage.store_account(&acct_info.directory, &a).await {
                        Ok(_) => (),
                        Err(e) => eprintln!("error: couldn't cache account credentials: {}", e),
                    };
                    Ok(a)
                }
                Err(e) => Err(e.into()),
            }
        }
    }
}

enum Decision {
    DoNotRenew(Reason),
    Renew(Reason),
}

enum Reason {
    ThirtyDays,
    ValidityPeriod,
    Names,
    None,
}

fn should_renew_cert(definition: &CertificateInfo, cert: &X509Cert) -> Decision {
    let cert = cert.cert();

    // First check the validity
    let thirty_days = Duration::new(30 * 86400, 0);
    let now = ASN1Time::now();
    let validity = cert.validity();
    match validity.time_to_expiration() {
        // None means the certificate isn't currently valid,
        None => {
            // but sometimes the certificates is not *yet* valid
            if validity.not_before > now {
                return DoNotRenew(ValidityPeriod);
            }
            if validity.not_after < now {
                return Renew(ValidityPeriod);
            }
        }
        Some(t) if t < thirty_days => return Renew(ThirtyDays),
        Some(_) => return DoNotRenew(ThirtyDays),
    }

    // If we reach here, then the certificate is currently valid and expires in more than 30 days
    // So check the domains
    let def_domains: HashSet<&str> = definition.domains.keys().map(|s| s.as_str()).collect();
    let binding = match cert.subject_alternative_name() {
        Ok(s) => match s {
            Some(be) => be
                .value
                .general_names
                .iter()
                .map(|n| n.to_string())
                .collect(),
            None => HashSet::with_capacity(1),
        },
        Err(_) => return Renew(Reason::None),
    };
    let mut cert_domains: HashSet<&str> = binding.iter().map(|s| s.as_str()).collect();
    if let Some(cn) = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
    {
        cert_domains.insert(cn);
    }
    if !def_domains.is_subset(&cert_domains) {
        return Renew(Names);
    }

    // If we got here, then the domains on the certificate are a superset of those on the
    // definition, so we don't need to renew.
    return DoNotRenew(Reason::None);
}

async fn process_certificate(
    name: &str,
    definition: CertificateInfo,
    acct: Account,
    storage: Storage,
) -> error::Result<()> {
    println!("processing certificate {}", name);

    if let Some(stored_cert) = storage.get_certificate(name).await {
        match should_renew_cert(&definition, &stored_cert) {
            DoNotRenew(reason) => {
                match reason {
                    ValidityPeriod => {
                        println!("certificate {} not yet valid, so not renewing", name)
                    }
                    // ThirtyDays => println!("certificate {} is still valid for more than 30 days, so not renewing", name),
                    _ => {}
                }
                return Ok(());
            }
            Renew(reason) => match reason {
                ValidityPeriod => println!(
                    "certificate {} is past it's expiration date, so renewing",
                    name
                ),
                ThirtyDays => println!(
                    "certificate {} is within 30 days of it's expiration date, so renewing",
                    name
                ),
                Names => println!(
                    "certificate {} doesn't cover defined domains, so renewing",
                    name
                ),
                Reason::None => println!("certificate {} is weird, so renewing anyway", name),
            },
        }
    }

    let names: Vec<String> = definition
        .domains
        .iter()
        .map(|(domain, _)| domain.to_owned())
        .collect();
    let identifiers: Vec<Identifier> = names
        .iter()
        .map(|name| Identifier::Dns(name.to_owned()))
        .collect();

    let mut order = acct
        .new_order(&NewOrder {
            identifiers: &identifiers,
        })
        .await?;

    let _state = order.state();
    let authorizations = order.authorizations().await?;
    let mut update_records_tasks = Vec::with_capacity(authorizations.len());
    for authz in &authorizations {
        match authz.status {
            AuthorizationStatus::Valid => continue,
            _ => {}
        }

        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Dns01)
            .ok_or(Acme("no DNS challenge found".into()))?;

        let Identifier::Dns(identifier) = &authz.identifier;
        let _cfg = definition
            .domains
            .iter()
            .find_map(|(domain, cfg)| {
                if identifier == domain {
                    Some(cfg)
                } else {
                    None
                }
            })
            .ok_or::<Error>("".into())?
            .clone();
        let challenge_value = order.key_authorization(challenge).dns_value();
        let challenge_url = challenge.url.to_owned();

        update_records_tasks.push(tokio::spawn(update_txt_record(
            _cfg,
            challenge_value,
            challenge_url,
        )));
    }

    for challenge in update_records_tasks {
        let url = challenge
            .await
            .expect("error: unable to join")
            .expect("error: unable to update challenge");
        order.set_challenge_ready(&*url).await?;
    }

    // Exponentially back off until the order becomes ready or invalid.
    let mut tries = 1u8;
    let mut delay = Duration::from_millis(250);
    loop {
        sleep(delay).await;
        let state = match order.refresh().await {
            Ok(s) => s,
            Err(_) => order.refresh().await.unwrap(),
        };
        if let OrderStatus::Ready | OrderStatus::Invalid = state.status {
            //info!("order state: {:#?}", state);
            break;
        }

        delay *= 2;
        tries += 1;
        match tries < 15 {
            true => {} //info!(?state, tries, "order is not ready, waiting {delay:?}"),
            false => {
                //error!(?state, tries, "order is not ready");
                return Err("order is not ready".into());
            }
        }
    }

    let state = order.state();
    if state.status != OrderStatus::Ready {
        // return Err(anyhow::anyhow!(
        //     "unexpected order status: {:?}",
        //     state.status
        // ));
        return Err("unexpected order status".into());
    }

    // If the order is ready, we can provision the certificate.
    // Use the rcgen library to create a Certificate Signing Request.

    let mut params = CertificateParams::new(names.clone());
    params.distinguished_name = DistinguishedName::new();
    params.key_pair = get_or_create_key_pair(storage.clone(), &*name).await.into();
    params.alg = &PKCS_ECDSA_P384_SHA384;
    let cert = Certificate::from_params(params)?;
    let csr = cert.serialize_request_der()?;

    // Finalize the order and print certificate chain, private key and account credentials.

    order.finalize(&csr).await?;
    let cert_chain_pem = loop {
        match order.certificate().await? {
            Some(cert_chain_pem) => break cert_chain_pem,
            None => sleep(Duration::from_secs(1)).await,
        }
    };

    println!("certificate {} issued", name);

    let full_chain = pem::parse_many(&cert_chain_pem)?;
    storage.store_certificate(name, &full_chain[0]).await?;
    storage.store_chain(name, &full_chain).await?;

    let mut data = cert.serialize_private_key_pem();
    data.push_str(&*cert_chain_pem);

    create_and_write(definition.destination, data).await?;

    if let Some(cmd_str) = definition.command {
        println!("running renewal command: {:#?}", cmd_str);
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(cmd_str);
        let output = cmd.output()?;
        if !output.stdout.is_empty() {
            println!("\t{:?}", output.stdout.as_bytes());
        }
        if !output.status.success() {
            return Err("failed to run renewal command".into());
        }
    }

    Ok(())
}

async fn update_txt_record(
    cfg: AcmeDnsConfig,
    challenge_value: String,
    challenge_url: String,
) -> error::Result<String> {
    let client = get_client();
    let payload = json!({
    "subdomain": &*cfg.subdomain,
    "txt": challenge_value,
    });
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("{}/update", cfg.server))
        .header(CONTENT_TYPE, "application/json")
        .header("X-Api-User", &*cfg.username)
        .header("X-Api-Key", &*cfg.password)
        .body(payload.to_string())
        .unwrap();
    match client.request(request).await {
        Ok(r) => {
            let status = r.status();
            if status.is_success() {
                return Ok(challenge_url);
            }
            let body = r.into_body();
            let body = hyper::body::aggregate(body).await?;
            #[derive(Deserialize)]
            struct _Error {
                error: String,
            }
            Err(serde_json::from_reader::<_, _Error>(body.reader())?
                .error
                .into())
        }
        Err(e) => Err(e.into()),
    }
}

async fn get_or_create_key_pair(storage: Storage, name: &str) -> KeyPair {
    match storage.get_key(name).await {
        Some(k) => k,
        None => {
            let pair =
                KeyPair::generate(&PKCS_ECDSA_P384_SHA384).expect("error: unable to generate key");
            storage
                .store_key(name, &pair)
                .await
                .expect("error: unable to save private key");
            pair
        }
    }
}

async fn create_and_write(
    path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    if let Some(parent) = path.as_ref().parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await?
        }
    }
    tokio::fs::write(path, contents).await
}

// Simple command to obtain and manage ACME certificates using the DNS solver, with acme-dns
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    // Path of the config file
    #[arg(short, long, default_value = "/etc/haproxy-acmedns/config.hcl")]
    //#[arg(short, long, default_value = "config.hcl")]
    config: std::path::PathBuf,
}
