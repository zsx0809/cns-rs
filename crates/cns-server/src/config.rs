use serde::Deserialize;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

/// 服务端配置。
///
/// 设计约束：
/// * 与原版 CNS 的 `config.json` 字段（含首字母大写变体）保持兼容；
/// * **不再** 在解析失败时静默退回默认值 —— 一个逗号写错就变成「无口令开放代理」
///   是不可接受的故障模式，启动期必须 fail-fast。
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_listen_addr", alias = "Listen_addr", alias = "listen_addr")]
    pub listen_addr: Vec<String>,

    #[serde(default = "default_proxy_key", alias = "Proxy_key", alias = "proxy_key")]
    pub proxy_key: String,

    #[serde(default = "default_udp_flag", alias = "Udp_flag", alias = "udp_flag")]
    pub udp_flag: String,

    #[serde(default, alias = "Encrypt_password", alias = "encrypt_password", alias = "password")]
    pub encrypt_password: String,

    #[serde(default = "default_tcp_timeout", alias = "Tcp_timeout", alias = "tcp_timeout")]
    pub tcp_timeout: u64,

    #[serde(default = "default_udp_timeout", alias = "Udp_timeout", alias = "udp_timeout")]
    pub udp_timeout: u64,

    #[serde(
        default = "default_true",
        alias = "Enable_dns_tcpOverUdp",
        alias = "enable_dns_tcp_over_udp"
    )]
    pub enable_dns_tcp_over_udp: bool,

    #[serde(default = "default_true", alias = "Enable_TFO", alias = "enable_tfo")]
    pub enable_tfo: bool,

    /// 最大并发会话数（旧实现为硬编码 4096）
    #[serde(default = "default_max_connections", alias = "Max_connections")]
    pub max_connections: usize,

    /// 首包握手超时（秒），防 Slowloris
    #[serde(default = "default_handshake_timeout")]
    pub handshake_timeout: u64,

    /// 回源连接超时（秒）
    #[serde(default = "default_dial_timeout")]
    pub dial_timeout: u64,

    /// true = IPv6 监听仅收 v6；默认 false（双栈，兼容 IPv4-only 移动网络）
    #[serde(default)]
    pub ipv6_only: bool,

    /// true = 监听 socket 开启 IP_TRANSPARENT（透明代理/TPROXY 需要）
    #[serde(default = "default_false")]
    pub transparent: bool,

    /// 监听工作线程数，0 = 按 CPU 核数（依赖 SO_REUSEPORT，不可用时自动退化为 1）
    #[serde(default = "default_workers")]
    pub workers: usize,

    /// 是否提供 httpDNS (`dn=`) 服务。公开递归解析有滥用风险，默认关闭。
    #[serde(default)]
    pub enable_httpdns: bool,

    /// httpDNS / 域名回源使用的上游 DNS（默认走系统解析器）
    #[serde(default = "default_dns_upstream")]
    pub dns_upstream: Vec<String>,

    /// DNS 结果缓存条数上限
    #[serde(default = "default_dns_cache_size")]
    pub dns_cache_size: usize,

    /// 允许回源到内网/环回/链路本地地址。默认 false —— 否则本服务就是打内网的 SSRF 跳板。
    #[serde(default)]
    pub allow_private_targets: bool,

    /// 额外放行的目标网段（CIDR，如 `"10.0.0.0/8"`），仅在明确需要时配置
    #[serde(default)]
    pub allow_target_cidrs: Vec<String>,

    /// 单客户端 IP 最大并发会话，0 = 不限制
    #[serde(default = "default_per_ip_limit")]
    pub max_connections_per_ip: usize,

    /// 无显式端口时的缺省目标端口
    #[serde(default = "default_target_port")]
    pub default_target_port: u16,

    /// 客户端伪装域名（用于排除「把伪装域当真实目标」的错误）。可与客户端 header_host 对齐。
    #[serde(default = "default_header_host")]
    pub header_host: String,
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
fn default_false() -> bool {
    false
}
fn default_max_connections() -> usize {
    4096
}
fn default_handshake_timeout() -> u64 {
    10
}
fn default_dial_timeout() -> u64 {
    10
}
fn default_workers() -> usize {
    0
}
fn default_dns_upstream() -> Vec<String> {
    vec!["223.5.5.5:53".to_string(), "8.8.8.8:53".to_string()]
}
fn default_dns_cache_size() -> usize {
    4096
}
fn default_per_ip_limit() -> usize {
    128
}
fn default_target_port() -> u16 {
    80
}
fn default_header_host() -> String {
    "mclient.alipay.com".to_string()
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
            max_connections: default_max_connections(),
            handshake_timeout: default_handshake_timeout(),
            dial_timeout: default_dial_timeout(),
            ipv6_only: false,
            transparent: false,
            workers: default_workers(),
            enable_httpdns: false,
            dns_upstream: default_dns_upstream(),
            dns_cache_size: default_dns_cache_size(),
            allow_private_targets: false,
            allow_target_cidrs: Vec::new(),
            max_connections_per_ip: default_per_ip_limit(),
            default_target_port: default_target_port(),
            header_host: default_header_host(),
        }
    }
}

impl Config {
    /// 从 JSON 读取配置；任何错误都必须让启动流程终止，而不是回落到不安全默认值。
    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", path.display()))?;
        let cfg: Config = serde_json::from_str(&content)
            .map_err(|e| anyhow::anyhow!("invalid JSON in {}: {e}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// 校验危险配置组合，返回明确错误。
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.listen_addr.is_empty() {
            anyhow::bail!("listen_addr must not be empty");
        }
        if self.encrypt_password.is_empty() {
            // 不是错误，但等于纯明文混淆；保留为可运行状态由部署者负责
            tracing::warn!(
                "encrypt_password is EMPTY: traffic is unobfuscated plaintext. \
                 Set a password unless you are debugging."
            );
        }
        if self.tcp_timeout == 0 || self.udp_timeout == 0 {
            anyhow::bail!("tcp_timeout / udp_timeout must be > 0");
        }
        if self.handshake_timeout == 0 || self.dial_timeout == 0 {
            anyhow::bail!("handshake_timeout / dial_timeout must be > 0");
        }
        if self.max_connections == 0 {
            anyhow::bail!("max_connections must be > 0");
        }
        for cidr in &self.allow_target_cidrs {
            parse_cidr(cidr)
                .ok_or_else(|| anyhow::anyhow!("invalid allow_target_cidrs entry: {cidr}"))?;
        }
        Ok(())
    }

    pub fn tcp_timeout_duration(&self) -> Duration {
        Duration::from_secs(self.tcp_timeout)
    }

    pub fn udp_timeout_duration(&self) -> Duration {
        Duration::from_secs(self.udp_timeout)
    }

    pub fn handshake_timeout_duration(&self) -> Duration {
        Duration::from_secs(self.handshake_timeout)
    }

    pub fn dial_timeout_duration(&self) -> Duration {
        Duration::from_secs(self.dial_timeout)
    }

    /// 目标地址是否允许回源。默认拒绝所有非全球可达地址。
    pub fn target_allowed(&self, ip: IpAddr) -> bool {
        if self.allow_private_targets {
            return true;
        }
        self.allow_target_cidrs
            .iter()
            .filter_map(|c| parse_cidr(c))
            .any(|(net, len)| ip_in_cidr(&ip, net, len))
            || !is_restricted_ip(ip)
    }
}

/// 环回 / 私网 / 链路本地 / 组播 / 运营商级 NAT / 云元数据 —— 默认一律拒绝。
pub fn is_restricted_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_unspecified()
                || v4.is_link_local()
                || v4.is_multicast()
                // 100.64.0.0/10 CGNAT（含 Android/iOS 热点常见段）
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                // 0.0.0.0/8 "this host on this network"
                || o[0] == 0
                // 169.254.0.0/16 已被 is_link_local 覆盖；198.18.0.0/15 基准测试段
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                // 240.0.0.0/4 保留
                || o[0] >= 240
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // ::ffff:0:0/96 IPv4-mapped → 按内层 v4 判定
                || (v6.octets()[..10] == [0u8; 10]
                    && v6.octets()[10..12] == [0xff, 0xff]
                    && is_restricted_ip(IpAddr::V4(std::net::Ipv4Addr::from([
                        v6.octets()[12],
                        v6.octets()[13],
                        v6.octets()[14],
                        v6.octets()[15],
                    ]))))
                // fc00::/7 ULA, fe80::/10 link-local, ff00::/8 multicast
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || (v6.segments()[0] & 0xff00) == 0xff00
        }
    }
}

/// 解析 `"10.0.0.0/8"`，返回 `(网络地址字节, 前缀长度)`
pub fn parse_cidr(cidr: &str) -> Option<(IpAddr, u8)> {
    let (addr_str, len_str) = cidr.split_once('/')?;
    let addr: IpAddr = addr_str.trim().parse().ok()?;
    let len: u8 = len_str.trim().parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    if len > max {
        return None;
    }
    Some((addr, len))
}

/// 判断 `ip` 是否落在 `net/len` 内（v4 与 v6 分别按各自位宽对齐前缀）
fn ip_in_cidr(ip: &IpAddr, net: IpAddr, len: u8) -> bool {
    let (a, b, bits) = match (*ip, net) {
        (IpAddr::V4(x), IpAddr::V4(y)) => {
            (u128::from(u32::from(x)), u128::from(u32::from(y)), 32u32)
        }
        (IpAddr::V6(x), IpAddr::V6(y)) => {
            (u128::from_be_bytes(x.octets()), u128::from_be_bytes(y.octets()), 128u32)
        }
        _ => return false,
    };
    if len as u32 > bits {
        return false;
    }
    let mask: u128 = if len == 0 { 0 } else { (!0u128) << (bits - len as u32) };
    (a & mask) == (b & mask)
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
        cfg.validate().unwrap();
        assert_eq!(cfg.listen_addr, vec![":1254"]);
        assert_eq!(cfg.proxy_key, "Meng");
        assert_eq!(cfg.encrypt_password, "666");
        assert_eq!(cfg.tcp_timeout, 300);
        assert!(cfg.enable_tfo);
        // 新默认值：双栈 + httpDNS 关闭 + 私网目标拒绝
        assert!(!cfg.ipv6_only);
        assert!(!cfg.enable_httpdns);
        assert!(!cfg.allow_private_targets);
    }

    #[test]
    fn test_invalid_config_is_rejected_not_defaulted() {
        // 缺逗号 → 必须报错
        let bad = r#"{"listen_addr": [":1254"] "proxy_key": "Meng"}"#;
        assert!(serde_json::from_str::<Config>(bad).is_err());

        // 语义非法 → validate 拒绝
        let zero = r#"{"tcp_timeout": 0, "udp_timeout": 30}"#;
        let cfg: Config = serde_json::from_str(zero).unwrap();
        assert!(cfg.validate().is_err());

        let empty_listen = r#"{"listen_addr": [], "tcp_timeout": 300, "udp_timeout": 30}"#;
        let cfg: Config = serde_json::from_str(empty_listen).unwrap();
        assert!(cfg.validate().is_err());

        let bad_cidr =
            r#"{"tcp_timeout":300,"udp_timeout":30,"allow_target_cidrs":["10.0.0.0/33"]}"#;
        let cfg: Config = serde_json::from_str(bad_cidr).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_restricted_ips() {
        for s in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fc00::1",
            "ff02::1",
            "::ffff:192.168.0.1",
        ] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(is_restricted_ip(ip), "{s} should be restricted");
            let cfg = Config::default();
            assert!(!cfg.target_allowed(ip), "{s} should be blocked");
        }

        for s in ["1.1.1.1", "93.184.216.34", "2001:4860:4860::8888"] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(!is_restricted_ip(ip), "{s} should be public");
            assert!(Config::default().target_allowed(ip));
        }
    }

    #[test]
    fn test_allow_private_targets_and_cidr() {
        let open = Config { allow_private_targets: true, ..Default::default() };
        assert!(open.target_allowed("192.168.1.1".parse().unwrap()));

        let cidr =
            Config { allow_target_cidrs: vec!["10.0.0.0/8".to_string()], ..Default::default() };
        cidr.validate().unwrap();
        assert!(cidr.target_allowed("10.9.9.9".parse().unwrap()));
        assert!(!cidr.target_allowed("192.168.9.9".parse().unwrap()));
    }

    #[test]
    fn test_cidr_parsing() {
        assert_eq!(parse_cidr("10.0.0.0/8").unwrap().1, 8);
        assert!(parse_cidr("10.0.0.0/33").is_none());
        assert!(parse_cidr("nope").is_none());
        assert!(ip_in_cidr(&"10.20.30.40".parse().unwrap(), "10.0.0.0".parse().unwrap(), 8));
        assert!(!ip_in_cidr(&"11.20.30.40".parse().unwrap(), "10.0.0.0".parse().unwrap(), 8));
        assert!(ip_in_cidr(&"2001:db8::1".parse().unwrap(), "2001:db8::".parse().unwrap(), 32));
    }
}
