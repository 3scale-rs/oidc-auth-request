use serde::de::{Error, Unexpected};
use serde::{Deserialize, Deserializer};

pub(crate) type Url = ::url::Url;

// Deserialize a URL but require that it has an authority or fail
pub(crate) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Url, D::Error> {
    let url = Url::deserialize(deserializer)?;
    if !url.has_authority() {
        Err(Error::invalid_value(
            Unexpected::Str(url.as_str()),
            &"an URL with an authority including scheme, any user credentials, host, and an optional port",
        ))
    } else {
        Ok(url)
    }
}

pub(crate) fn authority(url: &Url) -> Option<String> {
    use std::fmt::Write;

    if !url.has_authority() {
        return None;
    }

    let username = url.username();
    let mut authority = String::new();
    let mut add_at = false;
    if !username.is_empty() {
        authority.push_str(username);
        add_at = true;
    }

    let passwd = url.password();
    if let Some(passwd) = passwd {
        authority.push(':');
        authority.push_str(passwd);
        add_at = true;
    }

    if add_at {
        authority.push('@');
    }

    // has_authority => has_host
    authority.push_str(url.host_str().unwrap());
    if let Some(port) = url.port() {
        if write!(authority, ":{}", port).is_err() {
            return None;
        }
    }

    Some(authority)
}
