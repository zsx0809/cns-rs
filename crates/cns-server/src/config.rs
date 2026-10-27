use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_listen_addr", alias = "Listen_addr", alias = "listen_addr")]
    pub listen_addr: Vec<String>,

    #[serde(default = "default_proxy_key", alias = "Proxy_key", alias = "proxy_key")]
    pub proxy_key: String,

    #[serde(default = "default_udp_flag", alias = "Udp_flag", alias = "udp_flag")]
    pub udp_flag: String,

    #[serde(default, alias = "Encrypt_password", alias = "encrypt_password")]
    pub encrypt_password: String,

    #[serde(default = "default_tcp_timeout", alias = "Tcp_timeout", alias = "tcp_timeout")]
    pub tcp_timeout: u64,

    #[serde(default = "default_udp_timeout", alias = "Udp_timeout", alias = "udp_timeout")]
    pub udp_timeout: u64,

    #[serde(default = "default_true", alias = "Enable_dns_tcpOverUdp", alias = "enable_dns_tcp_over_udp")]
    pub enable_dns_tcp_over_udp: bool,

    #[serde(default = "default_true", alias = "Enable_TFO", alias = "enable_tfo")]
    pub enable_tfo: bool,
}

fn default_listen_addr() -> Vec<String> {
    vec![":1254".to_string()]
}

fn default_proxy_key() -> String {
    "Meng".to_string()
}

fn default_udp_flag() -> String {
    "httpUDP".to_string()
}

fn default_tcp_timeout() -> u64 {
    300
}

fn default_udp_timeout() -> u64 {
    30
}

fn default_true() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            proxy_key: default_proxy_key(),
            udp_flag: default_udp_flag(),
            encrypt_password: String::new(),
            tcp_timeout: default_tcp_timeout(),
            udp_timeout: default_udp_timeout(),
            enable_dns_tcp_over_udp: default_true(),
            enable_tfo: default_true(),
        }
    }
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&content)?;
        Ok(config)
    }

    pub fn tcp_timeout_duration(&self) -> Duration {
        Duration::from_secs(self.tcp_timeout)
    }

    pub fn udp_timeout_duration(&self) -> Duration {
        Duration::from_secs(self.udp_timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_legacy_config_json() {
        let raw = r#"{
            "Tcp_timeout": 300,
            "Udp_timeout": 30,
            "Listen_addr": [":1254"],
            "proxy_key": "Meng",
            "encrypt_password": "666",
            "Enable_dns_tcpOverUdp": true,
            "Enable_TFO": true
        }"#;

        let cfg: Config = serde_json::from_str(raw).unwrap();
        assert_eq!(cfg.listen_addr, vec![":1254"]);
        assert_eq!(cfg.proxy_key, "Meng");
        assert_eq!(cfg.encrypt_password, "666");
        assert_eq!(cfg.tcp_timeout, 300);
        assert_eq!(cfg.enable_tfo, true);
    }
}
