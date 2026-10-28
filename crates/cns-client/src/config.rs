use serde::Deserialize;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

/// 客户端配置。
///
/// 兼容旧版字段名；新增项全部有默认值，旧 `client.json` 不改也能跑。
#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    /// SOCKS5 监听地址，空串 = 不启用
    #[serde(default = "default_socks5_listen")]
    pub socks5_listen: String,

    /// 本地 DNS 中继监听地址（iptables REDIRECT 把 UDP/53 打到这里）
    #[serde(default = "default_dns_listen")]
    pub dns_listen: String,

    #[serde(default)]
    pub tproxy_listen: Option<String>,

    /// 进程 GID（防回环，配合 iptables `--gid-owner`）
    #[serde(default)]
    pub gid: Option<u32>,

    /// CNS 服务端地址
    #[serde(default = "default_cns_server")]
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

    /// DNS 上游策略：
    /// * `"orig"`（默认）——沿用 App 原本要查的 DNS（经 iptables 捕获的 orig_dst），
    ///   运营商劫持/DNS 分流场景唯一正确的做法；
    /// * `"fixed"` —— 忽略 orig_dst，恒用 `dns_upstream`。
    #[serde(default = "default_dns_mode")]
    pub dns_mode: String,

    /// 固定/兜底 DNS 上游（`orig` 模式下作为 orig_dst 不可用时的回退）
    #[serde(default = "default_dns_upstream")]
    pub dns_upstream: Vec<String>,

    /// 是否本地拦截 AAAA 并秒回 NODATA。
    /// **IPv6-only / IPv6 可用网络必须关掉它**，否则双栈 App 解析不到任何地址。
    #[serde(default = "default_true")]
    pub block_ipv6: bool,

    /// 本地 DNS 缓存条目数上限
    #[serde(default = "default_dns_cache_size")]
    pub dns_cache_size: usize,

    /// 是否启用 httpUDP 隧道（SOCKS5 UDP ASSOCIATE 依赖它）
    #[serde(default = "default_true")]
    pub enable_udp_tunnel: bool,

    /// 隧道连接复用：同一目标的最大并发在途请求数
    #[serde(default = "default_max_inflight")]
    pub max_inflight_per_tunnel: usize,

    /// 会话最大时长（秒），0 = 不限。用于定期重建隧道以躲过基站 NAT 老化
    #[serde(default = "default_session_max_age")]
    pub session_max_age_seconds: u64,

    /// 透明代理劫持方式：`redirect`（iptables REDIRECT）/ `tproxy`（TPROXY+IP_TRANSPARENT）/ `auto`
    #[serde(default = "default_tproxy_mode")]
    pub tproxy_mode: String,

    /// SOCKS5 UDP relay 的监听地址；空串 = 自动复用 socks5_listen 的端口（推荐，
    /// 因为 SOCKS5 回复里的 BND.PORT 必须与 App 实际发送 UDP 的端口一致）
    #[serde(default)]
    pub socks5_udp_listen: String,

    /// 共享缓冲池容量（每方向 32KB）。默认 64 个 ≈ 2MB，适配手机内存。
    #[serde(default = "default_pool_cap")]
    pub buffer_pool_cap: usize,
}

fn default_socks5_listen() -> String {
    "127.0.0.1:1080".to_string()
}
fn default_dns_listen() -> String {
    "127.0.0.1:6653".to_string()
}
fn default_cns_server() -> String {
    "127.0.0.1:1254".to_string()
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
fn default_dns_mode() -> String {
    "orig".to_string()
}
fn default_dns_upstream() -> Vec<String> {
    vec!["223.5.5.5:53".to_string(), "8.8.8.8:53".to_string()]
}
fn default_dns_cache_size() -> usize {
    2048
}
fn default_max_inflight() -> usize {
    64
}
fn default_session_max_age() -> u64 {
    600
}
fn default_tproxy_mode() -> String {
    "auto".to_string()
}
fn default_pool_cap() -> usize {
    64
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            socks5_listen: default_socks5_listen(),
            dns_listen: default_dns_listen(),
            tproxy_listen: None,
            gid: None,
            cns_server: default_cns_server(),
            cns_password: String::new(),
            proxy_key: default_proxy_key(),
            udp_flag: default_udp_flag(),
            header_host: default_header_host(),
            custom_header: None,
            enable_tfo: default_true(),
            timeout_seconds: default_timeout(),
            dns_mode: default_dns_mode(),
            dns_upstream: default_dns_upstream(),
            block_ipv6: default_true(),
            dns_cache_size: default_dns_cache_size(),
            enable_udp_tunnel: default_true(),
            max_inflight_per_tunnel: default_max_inflight(),
            session_max_age_seconds: default_session_max_age(),
            tproxy_mode: default_tproxy_mode(),
            socks5_udp_listen: String::new(),
            buffer_pool_cap: default_pool_cap(),
        }
    }
}

impl ClientConfig {
    /// 解析后的透明代理劫持方式（非法值回退 Auto，但 validate 会先拒绝）
    pub fn tproxy_mode_parsed(&self) -> crate::inbound::TproxyMode {
        crate::inbound::TproxyMode::parse(&self.tproxy_mode)
            .unwrap_or(crate::inbound::TproxyMode::Auto)
    }

    /// 从 JSON 读取。解析失败必须返回错误（不再静默使用默认配置）。
    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", path.display()))?;
        let cfg: ClientConfig = serde_json::from_str(&content)
            .map_err(|e| anyhow::anyhow!("invalid JSON in {}: {e}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.cns_server.trim().is_empty() {
            anyhow::bail!("cns_server must not be empty");
        }
        // 让明显写错的地址在启动时就报错，而不是等第一个请求
        if !self.socks5_listen.is_empty() {
            self.socks5_listen.parse::<SocketAddr>().map_err(|e| {
                anyhow::anyhow!("invalid socks5_listen '{}': {e}", self.socks5_listen)
            })?;
        }
        self.dns_listen
            .parse::<SocketAddr>()
            .map_err(|e| anyhow::anyhow!("invalid dns_listen '{}': {e}", self.dns_listen))?;
        if self.timeout_seconds == 0 {
            anyhow::bail!("timeout_seconds must be > 0");
        }
        match self.dns_mode.as_str() {
            "orig" | "fixed" => {}
            other => anyhow::bail!("dns_mode must be \"orig\" or \"fixed\", got \"{other}\""),
        }
        if self.dns_upstream.is_empty() && self.dns_mode == "fixed" {
            anyhow::bail!("dns_mode=fixed requires a non-empty dns_upstream");
        }
        if crate::inbound::TproxyMode::parse(&self.tproxy_mode).is_none() {
            anyhow::bail!(
                "invalid tproxy_mode '{}' (expected redirect|tproxy|auto)",
                self.tproxy_mode
            );
        }
        if !self.socks5_udp_listen.is_empty() {
            self.socks5_udp_listen.parse::<SocketAddr>().map_err(|e| {
                anyhow::anyhow!("invalid socks5_udp_listen '{}': {e}", self.socks5_udp_listen)
            })?;
        }
        if self.buffer_pool_cap == 0 {
            anyhow::bail!("buffer_pool_cap must be > 0");
        }

        // 隧道协议约束：CNS 的 tcpDNS 快速路径由服务端按「目标以 :53 结尾」识别
        // （`SessionType::DnsTcpOverUdp`）。若上游端口不是 53，服务端会把它当**普通
        // TCP 隧道**处理 —— 而 DNS 是 UDP，于是回源必然失败，表现为「所有域名解析超时」
        // 这种极难定位的静默故障。因此在启动期直接拒绝，而不是等运行时挂掉。
        for item in &self.dns_upstream {
            match item.parse::<SocketAddr>() {
                Ok(addr) if addr.port() != 53 => anyhow::bail!(
                    "dns_upstream '{item}' 的端口不是 53：隧道内只有 :53 会走 tcpDNS \
                     快速通道，其它端口会被服务端当成普通 TCP 隧道而导致解析全失败。\
                     请改成 ip:53（如需非标端口，请让本机 resolver 监听 53 或使用 \
                     httpUDP 通道）。"
                ),
                // 允许裸 IP（运行时自动补 :53）；其余无法解析的写法在启动期就拒绝
                Err(_) if item.parse::<std::net::IpAddr>().is_err() => {
                    anyhow::bail!("invalid dns_upstream entry '{item}' (expect ip or ip:53)")
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_seconds)
    }

    /// 握手响应缓冲上限
    pub fn max_handshake_response(&self) -> usize {
        16 * 1024
    }

    pub fn session_max_age(&self) -> Option<Duration> {
        if self.session_max_age_seconds == 0 {
            None
        } else {
            Some(Duration::from_secs(self.session_max_age_seconds))
        }
    }

    /// 渲染免流伪装头。
    ///
    /// `[PROXY_KEY]` 占位符在模板里出现两次是合法的（既要带目标也要带标志），
    /// 这里保持与旧实现相同的单一替换语义，避免模板行为漂移。
    pub fn render_fake_header(&self, encrypted_target: &str) -> Vec<u8> {
        if let Some(tpl) = self.custom_header.as_ref() {
            let rendered = tpl
                .replace("[HOST_HEADER]", &self.header_host)
                .replace("[PROXY_KEY]", &self.proxy_key)
                .replace("[ENCRYPTED_TARGET]", encrypted_target);
            return normalize_header(&rendered);
        }
        normalize_header(&format!(
            "GET / HTTP/1.1\r\nHost: {}\r\n{}: {}\r\n\r\n",
            self.header_host, self.proxy_key, encrypted_target
        ))
    }

    /// httpUDP 会话的开关头（旧实现定义了但**从未被调用**，导致新客户端
    /// 完全无法使用 UDP 免流通道）
    pub fn render_udp_header(&self) -> Vec<u8> {
        normalize_header(&format!(
            "GET / HTTP/1.1\r\nHost: {}\r\n{}: on\r\n\r\n",
            self.header_host, self.udp_flag
        ))
    }
}

/// 保证头以 `\r\n\r\n` 结尾且不含裸 `\n`（部分模板手写容易漏 CRLF，
/// 服务端会一直等不到头部结束符）
fn normalize_header(s: &str) -> Vec<u8> {
    let unified = s.replace("\r\n", "\n").replace('\n', "\r\n");
    let mut out = unified.into_bytes();
    if !out.ends_with(b"\r\n\r\n") {
        if out.ends_with(b"\r\n") {
            out.extend_from_slice(b"\r\n");
        } else {
            out.extend_from_slice(b"\r\n\r\n");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_write(name: &str, content: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("cns-client-cfg-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, content).unwrap();
        p
    }

    #[test]
    fn legacy_json_still_loads_with_new_defaults() {
        let p = tmp_write(
            "legacy.json",
            r#"{
  "socks5_listen": "127.0.0.1:1080",
  "cns_server": "1.2.3.4:1254",
  "cns_password": "pw",
  "proxy_key": "Meng",
  "udp_flag": "httpUDP",
  "header_host": "mclient.alipay.com",
  "custom_header": null,
  "enable_tfo": true,
  "timeout_seconds": 60
}"#,
        );
        let cfg = ClientConfig::from_file(&p).unwrap();
        assert_eq!(cfg.dns_mode, "orig");
        assert!(cfg.block_ipv6);
        assert!(cfg.enable_udp_tunnel);
        assert_eq!(cfg.dns_upstream.len(), 2);
        assert_eq!(cfg.max_inflight_per_tunnel, 64);
        assert_eq!(cfg.session_max_age(), Some(Duration::from_secs(600)));
    }

    #[test]
    fn broken_json_is_an_error_not_a_default() {
        let p = tmp_write("broken.json", r#"{"cns_server": "1.2.3.4:1254" "timeout_seconds": 60}"#);
        let err = ClientConfig::from_file(&p).unwrap_err();
        assert!(err.to_string().contains("invalid JSON"), "{err}");
    }

    #[test]
    fn semantic_validation_rejects_dangerous_values() {
        assert!(ClientConfig { timeout_seconds: 0, ..Default::default() }.validate().is_err());

        assert!(ClientConfig { cns_server: "  ".to_string(), ..Default::default() }
            .validate()
            .is_err());

        assert!(ClientConfig { dns_mode: "magic".to_string(), ..Default::default() }
            .validate()
            .is_err());

        assert!(ClientConfig {
            dns_mode: "fixed".to_string(),
            dns_upstream: Vec::new(),
            ..Default::default()
        }
        .validate()
        .is_err());

        // socks5_listen 空串 = 不启用，必须合法
        assert!(ClientConfig { socks5_listen: String::new(), ..Default::default() }
            .validate()
            .is_ok());

        assert!(ClientConfig { socks5_listen: "not-an-addr".to_string(), ..Default::default() }
            .validate()
            .is_err());

        // 默认配置本身必须自洽
        ClientConfig::default().validate().unwrap();
    }

    #[test]
    fn new_relay_options_validate_and_parse() {
        // 非法 tproxy_mode 必须被拒绝
        assert!(ClientConfig { tproxy_mode: "invis".to_string(), ..Default::default() }
            .validate()
            .is_err());

        let cfg = ClientConfig { tproxy_mode: "TPROXY".to_string(), ..Default::default() };
        cfg.validate().unwrap();
        assert_eq!(cfg.tproxy_mode_parsed(), crate::inbound::TproxyMode::Tproxy);

        // 非法 socks5_udp_listen 被拒绝，空串合法
        assert!(ClientConfig { socks5_udp_listen: "abc".to_string(), ..Default::default() }
            .validate()
            .is_err());
        assert!(ClientConfig { socks5_udp_listen: String::new(), ..Default::default() }
            .validate()
            .is_ok());

        // buffer_pool_cap = 0 会让缓冲池永远拿不到复用收益，直接拒绝
        assert!(ClientConfig { buffer_pool_cap: 0, ..Default::default() }.validate().is_err());

        // 默认值必须自洽且为 redirect 生态的保守选择
        let d = ClientConfig::default();
        d.validate().unwrap();
        assert_eq!(d.tproxy_mode_parsed(), crate::inbound::TproxyMode::Auto);
        assert_eq!(d.buffer_pool_cap, 64);
    }

    #[test]
    fn non_53_dns_upstream_is_refused_at_startup() {
        // 回归：这条配置会让解析静默全挂（服务端把非 :53 当普通 TCP 隧道）
        let bad = ClientConfig {
            dns_upstream: vec!["127.0.0.1:19501".to_string()],
            ..Default::default()
        };
        let err = bad.validate().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("不是 53"), "{msg}");

        // 裸 IP 与显式 :53 都合法
        assert!(ClientConfig {
            dns_upstream: vec!["223.5.5.5".to_string(), "8.8.8.8:53".to_string()],
            ..Default::default()
        }
        .validate()
        .is_ok());

        // 乱七八糟的写法也要在启动期拦住
        assert!(ClientConfig {
            dns_upstream: vec!["resolver.example.com:53".to_string()],
            ..Default::default()
        }
        .validate()
        .is_err());
    }

    #[test]
    fn fake_header_contains_required_parts() {
        let cfg = ClientConfig::default();
        let h = cfg.render_fake_header("abc123=");
        let s = String::from_utf8(h).unwrap();
        assert!(s.starts_with("GET / HTTP/1.1\r\n"));
        assert!(s.contains("Host: mclient.alipay.com\r\n"));
        assert!(s.contains("Meng: abc123=\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn udp_header_uses_udp_flag_not_proxy_key() {
        let cfg = ClientConfig { udp_flag: "httpUDP".to_string(), ..Default::default() };
        let s = String::from_utf8(cfg.render_udp_header()).unwrap();
        assert!(s.contains("httpUDP: on\r\n"), "{s}");
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn custom_header_template_is_rendered_and_normalized() {
        let cfg = ClientConfig {
            custom_header: Some(
                "GET /index.html HTTP/1.1\nHost: [HOST_HEADER]\n[PROXY_KEY]: [ENCRYPTED_TARGET]\nConnection: keep-alive\n".to_string(),
            ),
            ..Default::default()
        };
        let s = String::from_utf8(cfg.render_fake_header("XYZ=")).unwrap();
        let bytes = s.as_bytes();
        assert!(bytes.ends_with(b"\r\n\r\n"));
        assert!(!s.contains("[HOST_HEADER]"));
        assert!(!s.contains("[PROXY_KEY]"));
        assert!(!s.contains("[ENCRYPTED_TARGET]"));
        assert!(s.contains("Host: mclient.alipay.com"));
        assert!(s.contains("Meng: XYZ="));
    }

    #[test]
    fn normalize_header_idempotent_on_good_input() {
        let good = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        assert_eq!(normalize_header(good), good.as_bytes());
        // 单 \n 输入必须被升级为 CRLF
        let out = normalize_header("GET / HTTP/1.1\nHost: a\n");
        assert_eq!(String::from_utf8(out).unwrap(), "GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    }
}
