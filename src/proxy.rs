use std::{borrow::Cow, ops::Deref, time::Duration};

use anyhow::format_err;
use log::{error, info, warn};
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use url::form_urlencoded::{self, Serializer};

use crate::configuration::Configuration;

pub(crate) struct OIDCAuthRequest {
    context_id: u32,
    configuration: Configuration,
}

impl OIDCAuthRequest {
    pub fn configuration(&self) -> &Configuration {
        &self.configuration
    }
}

pub fn parse_path(path: &str) -> (&str, Option<&str>) {
    let mut v = path.splitn(2, '?');
    let path = v.next().unwrap();
    let qs = v.next();
    (path, qs)
}

fn extract_cookies<'a>(cookie_value: &'a str) -> impl Iterator<Item = (&'a str, Option<&'a str>)> {
    cookie_value.split(';').map(|kv| {
        let mut kviter = kv.splitn(2, '=');
        (kviter.next().unwrap(), kviter.next())
    })
}
fn get_cookie<'a>(cookie_value: &'a str, name: &str) -> Option<Option<&'a str>> {
    extract_cookies(cookie_value)
        .find_map(|(cookie, v)| if cookie == name { Some(v) } else { None })
}

pub fn get_cookie_from_header(
    ctx: &dyn HttpContext,
    header: &str,
    name: &str,
) -> Option<Option<String>> {
    match ctx.get_http_request_header(header) {
        Some(cookie_value) => {
            get_cookie(cookie_value.as_str(), name).map(|value| value.map(ToString::to_string))
        }
        None => None,
    }
}

pub(crate) fn handle_oidc(
    ctx: &dyn HttpContext,
    oidc: &crate::configuration::OIDC,
    client: &crate::configuration::Client,
) -> i32 {
    1
}

impl HttpContext for OIDCAuthRequest {
    fn on_http_request_headers(&mut self, _: usize) -> FilterHeadersStatus {
        info!("on_http_request_headers: context_id {}", self.context_id);
        let scheme = self
            .get_http_request_header(":scheme")
            .unwrap_or_else(|| "http".into());
        let authority = self.get_http_request_header(":authority").unwrap();
        let path = self.get_http_request_header(":path").unwrap();
        let (path, qs) = parse_path(path.as_str());
        let _method = self.get_http_request_header(":method").unwrap();

        let oidcs = self.configuration.oidcs();
        let rules = self.configuration.rules();

        let rule = match rules.iter().find(|r| r.match_authority(authority.as_str())) {
            Some(rule) => rule,
            None => return FilterHeadersStatus::Continue,
        };
        info!("oidc_auth_request: found authority match for {}", authority);

        let rule_match = match rule.matches().iter().find(|m| m.match_prefix(path)) {
            Some(r#match) => r#match,
            None => return FilterHeadersStatus::Continue,
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
        let qs = qs
            .map(|qs| {
                form_urlencoded::parse(qs.as_bytes())
                    .filter_map(|(k, v)| match k.as_ref() {
                        "code" => {
                            code_value = Some(v);
                            None
                        }
                        "session_state" => None,
                        _ => Some((k, v)),
                    })
                    .fold(
                        Serializer::new(String::with_capacity(qs.len())),
                        |mut acc, (k, v)| {
                            acc.append_pair(k.as_ref(), v.as_ref());
                            acc
                        },
                    )
                    .finish()
            })
            .and_then(|qs| if qs.is_empty() { None } else { Some(qs) });

        let headers = self.get_http_request_headers();
        let auth = headers.iter().find_map(|(h, v)| {
            if h == "authorization" {
                Some(v.as_str())
            } else {
                None
            }
        });

        if auth.is_some() {
            info!("auth header present");
            return FilterHeadersStatus::Continue;
        }

        info!("auth header not present - checking for cookie with token");
        let oidc_token = get_cookie_from_header(self, "cookie", "oidc_token").flatten();
        if let Some(mut token) = oidc_token {
            info!("cookie with token found, setting authorization");
            token.insert_str(0, "Bearer ");
            self.set_http_request_header("authorization", Some(&token));
            return FilterHeadersStatus::Continue;
        }
        info!("cookie with token not found, looking for code param");

        if let Some(code) = code_value {
            let mut redirect_path = path.to_string();
            if let Some(qs) = qs {
                redirect_path.push('?');
                redirect_path.push_str(qs.as_str());
            }
            let payload: String = Serializer::new(String::new())
                .append_pair("grant_type", "authorization_code")
                .append_pair("code", code.as_ref())
                .append_pair(
                    "redirect_uri",
                    format!("http://{}{}", authority, redirect_path).as_str(),
                )
                .append_pair("client_id", client_id)
                .append_pair("client_secret", client_secret)
                .finish();

            info!("Contacting token endpoint with payload: {}", payload);

            self.dispatch_http_call(
                oidc.upstream().name(),
                vec![
                    (":method", "POST"),
                    (":path", oidc.urls().token()),
                    (":authority", oidc.upstream().authority()),
                    ("Content-Type", "application/x-www-form-urlencoded"),
                ],
                Some(payload.as_bytes()),
                vec![],
                Duration::from_secs(5),
            )
            .unwrap();
        } else {
            info!("no code found, redirecting to auth");
            let uri = Serializer::new(String::new())
                .append_pair("client_id", "test")
                .append_pair("response_type", "code")
                .append_pair("scope", "openid profile email")
                .append_pair(
                    "redirect_uri",
                    format!("{}://{}{}", scheme, authority, path).as_str(),
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
    fn on_http_call_response(&mut self, call_token: u32, _: usize, _: usize, _: usize) {
        info!("on_http_call_response: call_token is {}", call_token);
        let authorized = self
            .get_http_call_response_headers()
            .into_iter()
            .find(|(key, _)| key.as_str() == ":status")
            .map(|(_, value)| value.as_str() == "200")
            .unwrap_or(false);

        if authorized {
            info!("on_http_call_response: authorized {}", call_token);
            self.resume_http_request();
        } else {
            info!("on_http_call_response: forbidden {}", call_token);
            self.send_http_response(403, vec![], Some(b"Access forbidden.\n"));
        }
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
