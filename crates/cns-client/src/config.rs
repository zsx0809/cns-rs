use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    #[serde(default = "default_socks5_listen")]
    pub socks5_listen: String,

    #[serde(default)]
    pub tproxy_listen: Option<String>,

    #[serde(default)]
    pub gid: Option<u32>,

    pub cns_server: String,

    #[serde(default)]
    pub cns_password: String,

    #[serde(default = "default_proxy_key")]
    pub proxy_key: String,

    #[serde(default = "default_udp_flag")]
    pub udp_flag: String,

    #[serde(default = "default_header_host")]
    pub header_host: String,

    #[serde(default)]
    pub custom_header: Option<String>,

    #[serde(default = "default_true")]
    pub enable_tfo: bool,

    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

fn default_socks5_listen() -> String {
    "127.0.0.1:1080".to_string()
}

fn default_proxy_key() -> String {
    "Meng".to_string()
}

fn default_udp_flag() -> String {
    "httpUDP".to_string()
}

fn default_header_host() -> String {
    "mclient.alipay.com".to_string()
}

fn default_true() -> bool {
    true
}

fn default_timeout() -> u64 {
    60
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            socks5_listen: default_socks5_listen(),
            tproxy_listen: None,
            gid: None,
            cns_server: "127.0.0.1:1254".to_string(),
            cns_password: String::new(),
            proxy_key: default_proxy_key(),
            udp_flag: default_udp_flag(),
            header_host: default_header_host(),
            custom_header: None,
            enable_tfo: default_true(),
            timeout_seconds: default_timeout(),
        }
    }
}

impl ClientConfig {
    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: ClientConfig = serde_json::from_str(&content)?;
        Ok(config)
    }

    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_seconds)
    }

    pub fn render_fake_header(&self, encrypted_target: &str) -> Vec<u8> {
        if let Some(ref tpl) = self.custom_header {
            let rendered = tpl
                .replace("[HOST_HEADER]", &self.header_host)
                .replace("[PROXY_KEY]", &self.proxy_key)
                .replace("[ENCRYPTED_TARGET]", encrypted_target);
            rendered.into_bytes()
        } else {
            format!(
                "GET / HTTP/1.1\r\nHost: {}\r\n{}: {}\r\n\r\n",
                self.header_host, self.proxy_key, encrypted_target
            )
            .into_bytes()
        }
    }

    pub fn render_udp_header(&self) -> Vec<u8> {
        format!(
            "GET / HTTP/1.1\r\nHost: {}\r\n{}: on\r\n\r\n",
            self.header_host, self.udp_flag
        )
        .into_bytes()
    }
}
