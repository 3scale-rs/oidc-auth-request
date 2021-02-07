#![allow(dead_code)]

use crate::upstream::Upstream;
use core::convert::TryFrom;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum MissingError {
    #[error("no backend configured")]
    Backend,
    #[error("no services configured")]
    Services,
    #[error("no credentials defined for service `{0}`")]
    Credentials(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Client {
    id: String,
    secret: String,
}

impl Client {
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    pub fn secret(&self) -> &str {
        self.secret.as_str()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct OIDCUrls {
    login: String,
    token: String,
}

// FIXME this should likely just be URLs.
impl OIDCUrls {
    pub fn login(&self) -> &str {
        self.login.as_str()
    }

    pub fn token(&self) -> &str {
        self.token.as_str()
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct OIDC {
    id: String,
    upstream: Upstream,
    urls: OIDCUrls,
    clients: Vec<Client>,
}

impl OIDC {
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    pub fn upstream(&self) -> &Upstream {
        &self.upstream
    }

    pub fn urls(&self) -> &OIDCUrls {
        &self.urls
    }

    pub fn clients(&self) -> &[Client] {
        self.clients.as_slice()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct OIDCMatch {
    oidc: String,
    client: String,
}

impl OIDCMatch {
    pub fn oidc(&self) -> &str {
        self.oidc.as_str()
    }

    pub fn client(&self) -> &str {
        self.client.as_str()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Match {
    method: Option<String>,
    prefix: String,
    #[serde(rename = "with")]
    oidc_match: OIDCMatch,
}

impl Match {
    pub fn method(&self) -> Option<&str> {
        self.method.as_deref()
    }

    pub fn prefix(&self) -> &str {
        self.prefix.as_str()
    }

    pub fn oidc_match(&self) -> &OIDCMatch {
        &self.oidc_match
    }

    pub fn match_prefix(&self, path: &str) -> bool {
        path.starts_with(&self.prefix)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Rule {
    authorities: Vec<String>,
    #[serde(rename = "match")]
    matches: Vec<Match>,
}

impl Rule {
    pub fn authorities(&self) -> &[String] {
        self.authorities.as_slice()
    }

    pub fn matches(&self) -> &[Match] {
        self.matches.as_slice()
    }

    pub fn match_authority(&self, authority: &str) -> bool {
        self.authorities.iter().any(|auth| auth == authority)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename = "oidc-auth-request")]
pub(crate) struct Configuration {
    oidcs: Vec<OIDC>,
    rules: Vec<Rule>,
}

impl TryFrom<&[u8]> for Configuration {
    type Error = anyhow::Error;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        Ok(serde_json::from_slice(buf)?)
    }
}

impl Configuration {
    pub fn oidcs(&self) -> &[OIDC] {
        self.oidcs.as_slice()
    }

    pub fn rules(&self) -> &[Rule] {
        self.rules.as_slice()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    mod fixtures {
        pub const CONFIG: &str = r#"{
            "oidcs": [
              {
                "id": "keycloak",
                "upstream": {
                  "name": "keycloak",
                  "url": "http://keycloak",
                  "timeout": 5000
                },
                "urls": {
                  "login": "http://keycloak/auth/realms/wasmauth/protocol/openid-connect/auth",
                  "token": "http://keycloak/auth/realms/wasmauth/protocol/openid-connect/token"
                },
                "clients": [
                  {
                    "id": "test",
                    "secret": "PLACEHOLDER"
                  }
                ]
              }
            ],
            "rules": [
              {
                "authorities": [
                  "web",
                  "web.app"
                ],
                "match": [
                  {
                    "prefix": "/oidc",
                    "with": {
                      "oidc": "keycloak",
                      "client": "test"
                    }
                  }
                ]
              }
            ]
        }"#;
    }

    fn parse_config(input: &str) -> Configuration {
        let parsed = serde_json::from_str::<'_, Configuration>(input);
        match parsed {
            Err(ref e) => eprintln!("Error: {:#?}", e),
            _ => (),
        }
        assert!(parsed.is_ok());
        let parsed = parsed.unwrap();
        eprintln!("PARSED:\n{:#?}", parsed);
        parsed
    }

    #[test]
    fn it_parses_a_configuration_string() {
        parse_config(fixtures::CONFIG);
    }
}
