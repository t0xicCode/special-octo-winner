use std::path::PathBuf;

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct Config {
    pub(crate) storage: PathBuf,

    #[serde(serialize_with = "hcl::ser::block")]
    pub(crate) account: AccountInfo,

    #[serde(rename = "certificate", serialize_with = "hcl::ser::labeled_block")]
    pub(crate) certificates: IndexMap<String, CertificateInfo>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct AccountInfo {
    pub(crate) email: String,
    pub(crate) directory: String,
    pub(crate) accept_terms: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct CertificateInfo {
    pub(crate) destination: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub(crate) command: Option<String>,
    #[serde(rename = "domain", serialize_with = "hcl::ser::labeled_block")]
    pub(crate) domains: IndexMap<String, AcmeDnsConfig>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct AcmeDnsConfig {
    pub(crate) server: String,
    pub(crate) subdomain: String,
    pub(crate) username: String,
    pub(crate) password: String,
}
