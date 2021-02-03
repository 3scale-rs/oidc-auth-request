use anyhow::anyhow;
use core::convert::{Into, TryFrom};
use core::iter::Extend;
use core::time::Duration;

mod serde;

const DEFAULT_TIMEOUT_MS: u64 = 1000u64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    name: String,
    scheme: String,
    authority: String,
    base_path: Option<String>,
    // timeout in ms
    timeout: Duration,
}

impl Upstream {
    pub fn set_default_timeout(&mut self, timeout: u64) {
        self.timeout = Duration::from_millis(timeout);
    }

    pub fn default_timeout(&self) -> u128 {
        self.timeout.as_millis()
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn scheme(&self) -> &str {
        self.scheme.as_str()
    }

    pub fn authority(&self) -> &str {
        self.authority.as_str()
    }

    pub fn base_path(&self) -> Option<&str> {
        self.base_path.as_deref()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn call<C: proxy_wasm::traits::Context>(
        &self,
        ctx: &C,
        path: impl ToString,
        method: &str,
        headers: Vec<(&str, &str)>,
        body: Option<&[u8]>,
        trailers: Option<Vec<(&str, &str)>>,
        timeout: Option<u64>,
    ) -> Result<u32, anyhow::Error> {
        let mut path = path.to_string();

        if let Some(base_path) = self.base_path.as_deref() {
            path.insert_str(0, base_path)
        }

        let mut hdrs = vec![
            (":authority", self.authority()),
            (":scheme", self.scheme()),
            (":method", method),
            (":path", path.as_str()),
        ];

        hdrs.extend(headers);

        let trailers = trailers.unwrap_or_default();
        log::debug!(
            "calling out {} (using {} scheme) with headers -> {:?} <- and body -> {:?} <-",
            self.name(),
            self.scheme(),
            hdrs,
            body
        );
        ctx.dispatch_http_call(
            self.name.as_str(),
            hdrs,
            body,
            trailers,
            timeout
                .map(Duration::from_millis)
                .unwrap_or_else(|| self.timeout),
        )
        .map_err(|e| {
            anyhow!(
                "failed to dispatch HTTP ({}) call to cluster {} with authority {}: {:?}",
                self.scheme,
                self.name,
                self.authority,
                e
            )
        })
    }
}

pub struct UpstreamBuilder {
    url: url::Url,
    authority: String,
}

impl UpstreamBuilder {
    pub fn build(self, name: impl ToString, timeout: Option<u64>) -> Upstream {
        let name = name.to_string();
        let scheme = self.url.scheme().to_string();
        let base_path = match self.url.path() {
            "/" => None,
            path => path.to_string().into(),
        };

        Upstream {
            name,
            scheme,
            authority: self.authority,
            base_path,
            timeout: Duration::from_millis(timeout.unwrap_or(DEFAULT_TIMEOUT_MS)),
        }
    }
}

impl TryFrom<url::Url> for UpstreamBuilder {
    type Error = anyhow::Error;

    fn try_from(url: url::Url) -> Result<Self, Self::Error> {
        let authority = crate::url::authority(&url)
            .ok_or_else(|| anyhow!("url does not contain an authority"))?;
        Ok(UpstreamBuilder { url, authority })
    }
}
