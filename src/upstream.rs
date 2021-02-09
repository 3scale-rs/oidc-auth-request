use anyhow::anyhow;
use core::convert::TryFrom;
use core::iter::Extend;
use core::time::Duration;
use url::Url;

mod serde;

const DEFAULT_TIMEOUT_MS: u64 = 1000u64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    name: String,
    url: Url,
    // timeout in ms
    timeout: Duration,
}

impl Upstream {
    #[allow(dead_code)]
    pub fn set_default_timeout(&mut self, timeout: u64) {
        self.timeout = Duration::from_millis(timeout);
    }

    pub fn default_timeout(&self) -> u128 {
        self.timeout.as_millis()
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    #[allow(dead_code)]
    pub fn scheme(&self) -> &str {
        self.url.scheme()
    }

    pub fn authority(&self) -> &str {
        self.url.authority()
    }

    pub fn path(&self) -> &str {
        self.url.path()
    }

    pub fn query_string(&self) -> Option<&str> {
        self.url.query()
    }

    #[allow(dead_code, clippy::too_many_arguments)]
    fn do_call<C: proxy_wasm::traits::Context>(
        ctx: &C,
        name: &str,
        scheme: &str,
        authority: &str,
        path: &str,
        method: &str,
        headers: Vec<(&str, &str)>,
        body: Option<&[u8]>,
        trailers: Option<Vec<(&str, &str)>>,
        timeout_ms: Option<u64>,
    ) -> Result<u32, anyhow::Error> {
        let mut hdrs = vec![
            (":authority", authority),
            (":scheme", scheme),
            (":method", method),
            (":path", path),
        ];

        hdrs.extend(headers);

        let trailers = trailers.unwrap_or_default();
        log::debug!(
            "calling out {} (using {} scheme) with headers -> {:?} <- and body -> {:?} <-",
            name,
            scheme,
            hdrs,
            body
        );
        ctx.dispatch_http_call(
            name,
            hdrs,
            body,
            trailers,
            timeout_ms.or_else(0).map(Duration::from_millis).unwrap(),
        )
        .map_err(|e| {
            anyhow!(
                "failed to dispatch HTTP ({}) call to cluster {} with authority {}: {:?}",
                scheme,
                name,
                authority,
                e
            )
        })
    }

    #[allow(dead_code, clippy::too_many_arguments)]
    pub fn call<C: proxy_wasm::traits::Context>(
        &self,
        ctx: &C,
        path: &str,
        method: &str,
        headers: Vec<(&str, &str)>,
        body: Option<&[u8]>,
        trailers: Option<Vec<(&str, &str)>>,
        timeout_ms: Option<u64>,
    ) -> Result<u32, anyhow::Error> {
        let extra_path = path.trim_start_matches('/');
        let mut path = self.path().to_string();
        path.push_str(extra_path);

        if let Some(qs) = self.query_string() {
            if !path.contains('?') {
                path.push('?');
            }
            path.push_str(qs);
        }

        Self::do_call(
            ctx,
            self.name(),
            self.scheme(),
            self.authority(),
            path.as_str(),
            method,
            headers,
            body,
            trailers,
            timeout_ms.or(self.timeout.as_millis()),
        )
    }

    #[allow(dead_code, clippy::too_many_arguments)]
    pub fn call_with_url<C: proxy_wasm::traits::Context>(
        &self,
        ctx: &C,
        url: &Url,
        method: &str,
        headers: Vec<(&str, &str)>,
        body: Option<&[u8]>,
        trailers: Option<Vec<(&str, &str)>>,
        timeout_ms: Option<u64>,
    ) -> Result<u32, anyhow::Error> {
        let mut path: std::borrow::Cow<str> = url.path().into();

        if let Some(qs) = url.query() {
            let path_mut = path.to_mut();
            path_mut.push('?');
            path_mut.push_str(qs);
        }

        let mut hdrs = vec![
            (":authority", url.authority()),
            (":scheme", url.scheme()),
            (":method", method),
            (":path", path.as_ref()),
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
            timeout_ms
                .map(Duration::from_millis)
                .unwrap_or_else(|| self.timeout),
        )
        .map_err(|e| {
            anyhow!(
                "failed to dispatch HTTP ({}) call to cluster {} with authority {}: {:?}",
                self.scheme(),
                self.name(),
                self.authority(),
                e
            )
        })
    }
}

pub struct UpstreamBuilder {
    url: url::Url,
}

impl UpstreamBuilder {
    pub fn build(mut self, name: impl ToString, timeout: Option<u64>) -> Upstream {
        let name = name.to_string();

        // any specified path should always be considered a directory in which to further mount paths
        if !self.url.path().ends_with('/') {
            self.url.set_path(format!("{}/", self.url.path()).as_str());
        }

        Upstream {
            name,
            url: self.url,
            timeout: Duration::from_millis(timeout.unwrap_or(DEFAULT_TIMEOUT_MS)),
        }
    }
}

impl TryFrom<url::Url> for UpstreamBuilder {
    type Error = anyhow::Error;

    fn try_from(url: url::Url) -> Result<Self, Self::Error> {
        if !url.has_authority() {
            return Err(anyhow!("url does not contain an authority"));
        }

        Ok(UpstreamBuilder { url })
    }
}
