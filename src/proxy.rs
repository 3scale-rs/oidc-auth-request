use log::{debug, error, info, warn};
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use url::form_urlencoded::Serializer;

use crate::configuration::Configuration;

mod request_headers;
use request_headers::RequestHeaders;

pub(crate) struct OIDCAuthRequest {
    context_id: u32,
    call_token: Option<u32>,
    url: Option<url::Url>,
    configuration: Configuration,
}

impl OIDCAuthRequest {
    pub fn configuration(&self) -> &Configuration {
        &self.configuration
    }
}

impl HttpContext for OIDCAuthRequest {
    fn on_http_request_headers(&mut self, _: usize) -> FilterHeadersStatus {
        info!("on_http_request_headers: context_id {}", self.context_id);
        let headers = RequestHeaders::new(self);
        if headers.get("authorization").is_some() {
            info!("auth header present");
            return FilterHeadersStatus::Continue;
        }

        let url = match headers.url() {
            Ok(url) => url,
            Err(e) => {
                error!("failed to parse request metadata: {:#?}", e);
                return FilterHeadersStatus::StopIteration;
            }
        };

        info!("parsed url {}", url.to_string());

        self.url = Some(url);
        let url = self.url.as_ref().unwrap();

        let authority = match url.authority() {
            authority if !authority.is_empty() => authority,
            _ => {
                error!("failed to parse request authority");
                return FilterHeadersStatus::StopIteration;
            }
        };

        let oidcs = self.configuration().oidcs();
        let rules = self.configuration().rules();

        let rule = match rules.iter().find(|r| r.match_authority(authority)) {
            Some(rule) => rule,
            None => {
                info!("oidc_auth_request: authority not found: {}", authority);
                return FilterHeadersStatus::Continue;
            }
        };
        info!("oidc_auth_request: found authority match for {}", authority);

        let path = url.path();
        let rule_match = match rule.matches().iter().find(|m| m.match_prefix(path)) {
            Some(r#match) => r#match,
            None => {
                info!("oidc_auth_request: rule not found for {}", path);
                return FilterHeadersStatus::Continue;
            }
        };
        info!("oidc_auth_request: found rule match for path {}", path);

        let oidc_match = rule_match.oidc_match();
        let oidc_id = oidc_match.oidc();
        let oidc = match oidcs.iter().find(|o| o.id() == oidc_id) {
            Some(oidc) => oidc,
            None => {
                warn!("oidc_auth_request: could not find OIDC id {}", oidc_id);
                return FilterHeadersStatus::Continue;
            }
        };
        let clients = oidc.clients();
        let client_id = oidc_match.client();
        let client = match clients.iter().find(|c| c.id() == client_id) {
            Some(client) => client,
            None => {
                warn!(
                    "oidc_auth_request: could not find OIDC client id {}",
                    client_id
                );
                return FilterHeadersStatus::Continue;
            }
        };
        let client_secret = client.secret();
        let mut code_value = None;
        let qs = match url
            .query_pairs()
            .filter_map(|(k, v)| match k.as_ref() {
                "code" => {
                    code_value = Some(v);
                    None
                }
                "session_state" => None,
                _ => Some((k, v)),
            })
            .fold(Serializer::new(String::new()), |mut acc, (k, v)| {
                acc.append_pair(k.as_ref(), v.as_ref());
                acc
            })
            .finish()
        {
            qs if qs.is_empty() => None,
            qs => Some(qs),
        };

        let oidc_token = headers
            .get_cookie_from_header("cookie", "oidc_token")
            .flatten();
        if let Some(token) = oidc_token {
            info!("cookie with token found, setting authorization");
            let token_type = headers
                .get_cookie_from_header("cookie", "token_type")
                .flatten()
                .unwrap_or("Bearer");
            let value = format!("{} {}", token_type, token);
            self.set_http_request_header("authorization", Some(value.as_str()));
            return FilterHeadersStatus::Continue;
        }
        info!("cookie with token not found, looking for code param");

        if let Some(code) = code_value {
            let mut redirect_path = url.path().to_string();
            if let Some(qs) = qs {
                redirect_path.push('?');
                redirect_path.push_str(qs.as_str());
            }
            let payload: String = Serializer::new(String::new())
                .append_pair("grant_type", "authorization_code")
                .append_pair("code", code.as_ref())
                .append_pair(
                    "redirect_uri",
                    format!("{}://{}{}", url.scheme(), authority, redirect_path).as_str(),
                )
                .append_pair("client_id", client_id)
                .append_pair("client_secret", client_secret)
                .finish();

            info!("Contacting token endpoint with payload: {}", payload);

            match oidc.upstream().call_url(
                self,
                oidc.urls().token(),
                "POST",
                vec![("Content-Type", "application/x-www-form-urlencoded")],
                Some(payload.as_bytes()),
                None,
                5000.into(),
            ) {
                Ok(call_token) => self.call_token = Some(call_token),
                Err(e) => error!("{}", e),
            }
        } else {
            info!("no code found, redirecting to auth");
            let uri = Serializer::new(format!("{}?", oidc.urls().login()))
                .append_pair("client_id", "test")
                .append_pair("response_type", "code")
                .append_pair("scope", "openid profile email")
                .append_pair(
                    "redirect_uri",
                    format!("{}://{}{}", url.scheme(), authority, url.path()).as_str(),
                )
                .finish();
            self.send_http_response(302, vec![("Location", uri.as_str())], None);
        }

        return FilterHeadersStatus::StopIteration;
    }

    fn on_http_response_headers(&mut self, _: usize) -> FilterHeadersStatus {
        self.set_http_response_header("Powered-By", Some("3scale"));
        FilterHeadersStatus::Continue
    }
}

impl Context for OIDCAuthRequest {
    fn on_http_call_response(&mut self, call_token: u32, _: usize, body_size: usize, _: usize) {
        info!("on_http_call_response: call_token is {}", call_token);
        let headers = self.get_http_call_response_headers();
        let status = headers
            .iter()
            .find(|(key, _)| key.as_str() == ":status")
            .map(|(_, value)| value.as_str());
        let body = self.get_http_call_response_body(0, body_size);
        let body_str = match body {
            Some(ref bytes) => String::from_utf8_lossy(bytes.as_slice()),
            None => "(nothing)".into(),
        };
        debug!(
            "Got back response status {:?} and body: {}",
            status, body_str
        );

        if let Some(body) = body {
            let json = serde_json::from_slice::<serde_json::Value>(body.as_slice());
            if let Err(e) = json {
                error!("failed to parse JSON response back from IDP: {}", e);
                self.send_http_response(403, vec![], Some(b"Access forbidden.\n"));
                return;
            }
            let json = json.unwrap();
            debug!("JSON received: {:#?}", json);
            if let Some(error) = json.get("error") {
                error!(
                    "error fetching token {}: {}",
                    error,
                    json.get("error_description")
                        .map(|v| v.as_str())
                        .flatten()
                        .unwrap_or("no error description found"),
                );
                return;
            }
            if let Some(token) = json.get("id_token") {
                info!("token found, setting cookie");
                let url = self.url.as_ref().unwrap();
                let expiry = json
                    .get("expires_in")
                    .map(|v| v.as_u64())
                    .flatten()
                    .unwrap_or(60);
                // FIXME rather than redirect, maybe resume_http_request with the right cookie?
                self.send_http_response(
                    302,
                    vec![
                        (
                            "set-cookie",
                            format!(
                                "oidc_token={};Max-Age={};token_type={};Max-Age={}",
                                token,
                                expiry,
                                json.get("token_type")
                                    .map(|v| v.as_str())
                                    .flatten()
                                    .unwrap_or("Bearer"),
                                expiry,
                            )
                            .as_str(),
                        ),
                        (
                            "Location",
                            format!("{}://{}{}", url.scheme(), url.authority(), url.path())
                                .as_str(),
                        ),
                    ],
                    None,
                );
                return;
            } else {
                error!("no id_token field found in JSON response");
            }
        } else {
            error!("no response body from IDP");
        }

        self.send_http_response(403, vec![], Some(b"Access forbidden.\n"));
    }
}

struct RootOIDCAuthRequest {
    vm_configuration: Option<Vec<u8>>,
    configuration: Option<Configuration>,
}

impl RootOIDCAuthRequest {
    pub fn new() -> Self {
        Self {
            vm_configuration: None,
            configuration: None,
        }
    }
}

impl Context for RootOIDCAuthRequest {}

impl RootContext for RootOIDCAuthRequest {
    fn on_vm_start(&mut self, vm_configuration_size: usize) -> bool {
        info!(
            "on_vm_start: vm_configuration_size is {}",
            vm_configuration_size
        );
        let vm_config = proxy_wasm::hostcalls::get_buffer(
            BufferType::VmConfiguration,
            0,
            vm_configuration_size,
        );

        if let Err(e) = vm_config {
            error!("on_vm_start: error retrieving VM configuration: {:#?}", e);
            return false;
        }

        self.vm_configuration = vm_config.unwrap();

        if let Some(conf) = self.vm_configuration.as_ref() {
            info!(
                "on_vm_start: VM configuration is {}",
                core::str::from_utf8(conf).unwrap()
            );
            true
        } else {
            warn!("on_vm_start: empty VM config");
            false
        }
    }

    fn on_configure(&mut self, plugin_configuration_size: usize) -> bool {
        use core::convert::TryFrom;

        info!(
            "on_configure: plugin_configuration_size is {}",
            plugin_configuration_size
        );

        let conf = proxy_wasm::hostcalls::get_buffer(
            BufferType::PluginConfiguration,
            0,
            plugin_configuration_size,
        );

        if let Err(e) = conf {
            error!(
                "on_configure: error retrieving plugin configuration: {:#?}",
                e
            );
            return false;
        }

        let conf = conf.unwrap();
        if conf.is_none() {
            warn!("on_configure: empty plugin configuration");
            return true;
        }

        let conf = conf.unwrap();
        info!(
            "on_configure: raw config is {}",
            String::from_utf8_lossy(conf.as_slice())
        );

        let conf = Configuration::try_from(conf.as_slice());
        if let Err(e) = conf {
            error!("on_configure: error parsing plugin configuration {}", e);
            return false;
        }

        self.configuration = conf.unwrap().into();
        info!(
            "on_configure: plugin configuration {:#?}",
            self.configuration
        );

        true
    }

    fn on_create_child_context(&mut self, context_id: u32) -> Option<ChildContext> {
        info!("creating new context {}", context_id);
        let ctx = OIDCAuthRequest {
            context_id,
            call_token: None,
            url: None,
            configuration: self.configuration.as_ref().unwrap().clone(),
        };

        Some(ChildContext::HttpContext(Box::new(ctx)))
    }
}

#[cfg_attr(
    all(
        target_arch = "wasm32",
        target_vendor = "unknown",
        target_os = "unknown"
    ),
    export_name = "_start"
)]
#[cfg_attr(
    not(all(
        target_arch = "wasm32",
        target_vendor = "unknown",
        target_os = "unknown"
    )),
    allow(dead_code)
)]
// This is a C interface, so make it explicit in the fn signature (and avoid mangling)
extern "C" fn start() {
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(RootOIDCAuthRequest::new())
    });
}
