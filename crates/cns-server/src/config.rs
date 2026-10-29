use cns_core::net_addr::IpCidr;
use cns_core::transport::MIN_MSS;
use serde::Deserialize;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// 服务端配置。
///
/// 设计约束：
/// * 与原版 CNS 的 `config.json` 字段（含首字母大写变体）保持兼容；
/// * **不再** 在解析失败时静默退回默认值 —— 一个逗号写错就变成「无口令开放代理」
///   是不可接受的故障模式，启动期必须 fail-fast。
/// * v0.3.0 起新增的回源参数（族偏好 / Happy Eyeballs / MSS / fakeip 守卫段）同样
///   遵守这条原则：**非法值直接拒绝启动**，不做 clamp、不做「回落默认」。
///   理由和 encrypt_password 一样：`outbound_mss: 15000` 若被静默夹成 1460，
///   运维看到的运行参数和他写进文件的参数不一致，MTU 黑洞就会重新变成玄学 bug
///   （这台内核没有 `xt_TCPMSS`，用户态 MSS 是唯一的钳制点，见 `transport::mss`）。
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

    // -----------------------------------------------------------------
    // v0.3.0：双栈回源择优 + 用户态 MSS + fakeip 泄漏守卫
    // -----------------------------------------------------------------
    /// 回源双栈族偏好：`auto` | `ipv4` | `ipv6`（大小写不敏感）。
    ///
    /// `auto` = RFC 8305 风格竞速：v6 首发，`happy_eyeballs_ms` 后错峰并发 v4。
    /// 显式写 `ipv4`/`ipv6` 的场景是「机房 v6 出口是黑洞/被运营商劫持」，
    /// 竞速虽然最终仍能通，但每连接都要白等一个错峰窗口 —— 这时应该锁族。
    #[serde(default = "default_prefer_family")]
    pub prefer_family: String,

    /// IPv6 首发后延迟多久发起 IPv4（毫秒）。合法区间 1..=2000，默认 200。
    ///
    /// RFC 8305 实测推荐值是 250ms；这里取 200 是因为免流隧道本身有 RTT 抖动，
    /// 错峰窗口越小，v6 黑洞链路下用户感知的「首次连接延迟」越接近 v4-only。
    /// 上界 2000 是防呆：写成 30000 的人其实想要的是 `prefer_family="ipv4"`。
    #[serde(default = "default_happy_eyeballs_ms")]
    pub happy_eyeballs_ms: u64,

    /// 每族最多尝试的候选地址数，合法区间 1..=64，默认 8。
    ///
    /// 上限存在的意义是防资源放大：CDN 域名一条应答可能挂 20+ 个 A 记录，
    /// 竞速并发数 = 候选总数（每族取前 N 个），N 不设限就是 self-DoS。
    #[serde(default = "default_dial_probe_count")]
    pub dial_probe_count: usize,

    /// 回源 socket 的 `TCP_MAXSEG`；0 = 不改（交给内核按路由算）。
    ///
    /// 合法区间 `{0} ∪ [536, 1460]`。536 = RFC 879 最小 MSS（内核 below 它会拒设），
    /// 1460 = 1500 MTU − 40。默认 1310 对应 tun_mtu=1350 的 v4 口径。
    ///
    /// 为什么服务端回源也要钳 MSS：隧道是两段独立路径。客户端 -> 服务端那一段
    /// 由 `ListenOptions.tun_mtu` 钳住了（accepted socket 继承），但服务端 -> 真实目标
    /// 这一段跑在机房的网络上，若上游站点的链路 MTU 更小且中间设备静默丢大包，
    /// 表现就是「网页能打开、图片卡在 90%」—— 和用户侧黑洞是同一个病灶的另一半。
    #[serde(default = "default_outbound_mss")]
    pub outbound_mss: u16,

    /// 客户端 fakeip 段（CIDR 列表）。落在任一段内的目标 IP **一律拒绝回源**。
    ///
    /// 语义要分清：客户端启用 fakeip 后，隧道里送来的目标**理论上全是域名**
    /// （客户端 tproxy 会先把 fakeip 反查回域名再发过来）。这一层守卫只挡一种情况：
    /// **客户端反查失败**（映射过期、持久化文件损坏、fakeip 表被清），把
    /// `198.18.0.77` 这种 fakeip 原样当目标串送来。此时若服务端真去回源，
    /// 那个包要么打到机房里不存在的地址上超时，要么（更糟）DNS 侧再解析一次
    /// 又返回 fakeip，形成「解析 → 回源 → 解析」环。所以这里必须**明确报错**
    /// 而不是静默丢弃，日志要能一眼看出是泄漏而非目标不可达。
    ///
    /// 客户端启用 `fakeip_v6_from_own_prefix` 时 v6 段是从本机前缀推导的，服务端
    /// **无法**预知；那一路的权威守卫在客户端。这里的默认列表只是最小集，运维可自行追加。
    #[serde(default = "default_fakeip_guard_cidrs")]
    pub fakeip_guard_cidrs: Vec<String>,
}

/// `happy_eyeballs_ms` 上界（防呆，见字段注释）
pub const MAX_HAPPY_EYEBALLS_MS: u64 = 2000;
/// `dial_probe_count` 上界（防候选地址放大）
pub const MAX_DIAL_PROBE_COUNT: usize = 64;
/// `prefer_family` 合法取值
pub const PREFER_FAMILY_VALUES: [&str; 3] = ["auto", "ipv4", "ipv6"];

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
fn default_prefer_family() -> String {
    "auto".to_string()
}
fn default_happy_eyeballs_ms() -> u64 {
    200
}
fn default_dial_probe_count() -> usize {
    8
}
fn default_outbound_mss() -> u16 {
    1310
}
fn default_fakeip_guard_cidrs() -> Vec<String> {
    // 与客户端 ClientConfig 的 fakeip_v4 / fakeip_v6 默认值同源，改一边必须改另一边
    vec!["198.18.0.0/15".to_string(), "fd53::/48".to_string()]
}

/// 归一化后的族偏好。
///
/// 用 `Display` 而不是 `AsRef<str>`：日志与错误消息里要能原样打印出配置值。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FamilyPreference {
    Auto,
    Ipv4,
    Ipv6,
}

impl FamilyPreference {
    /// 解析配置串。空串按 `auto` 处理（JSON 里写 `"prefer_family": ""` 的人
    /// 表达的是「我不想指定」，不是非法意图）；其余非三个枚举值的写法一律报错。
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let t = s.trim();
        if t.is_empty() {
            return Ok(Self::Auto);
        }
        let lower = t.to_ascii_lowercase();
        match lower.as_str() {
            "auto" => Ok(Self::Auto),
            "ipv4" | "v4" => Ok(Self::Ipv4),
            "ipv6" | "v6" => Ok(Self::Ipv6),
            other => anyhow::bail!(
                "invalid prefer_family '{other}'. Allowed: {} (case-insensitive); \
                 an empty string means 'auto'",
                PREFER_FAMILY_VALUES.join(" | ")
            ),
        }
    }

    /// 该偏好下，`addr` 属于候选族吗
    pub fn accepts(self, addr: IpAddr) -> bool {
        match self {
            Self::Auto => true,
            Self::Ipv4 => addr.is_ipv4(),
            Self::Ipv6 => addr.is_ipv6(),
        }
    }

    /// 该偏好下的首发族（`None` = 无显式族偏好，由竞速顺序决定：v6 首发）。
    /// 这是 `resolve_for_dial` 与 dial 共用的一处真源，避免两边各写一套规则。
    pub fn first_family(self) -> Option<bool> {
        match self {
            Self::Auto => None,
            Self::Ipv4 => Some(false),
            Self::Ipv6 => Some(true),
        }
    }

    pub fn is_auto(self) -> bool {
        matches!(self, Self::Auto)
    }
}

impl std::fmt::Display for FamilyPreference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Auto => "auto",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        })
    }
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
            prefer_family: default_prefer_family(),
            happy_eyeballs_ms: default_happy_eyeballs_ms(),
            dial_probe_count: default_dial_probe_count(),
            outbound_mss: default_outbound_mss(),
            fakeip_guard_cidrs: default_fakeip_guard_cidrs(),
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
        // 监听项必须能展开成至少一个 SocketAddr。bind_listeners() 对非法项是
        // 「log error + skip」，若全部非法就会得到一个「进程活着、端口没监听」的
        // 服务端 —— 客户端表现为永远连不上，日志里只有一行不起眼的 error。
        // 这类静默失败必须在启动前终止。
        for spec in &self.listen_addr {
            let expanded = cns_core::transport::expand_listen_spec(spec);
            if expanded.is_empty() {
                anyhow::bail!(
                    "listen_addr '{spec}' 无法解析。合法写法：\":1254\"（双栈通配）、\
                     \"0.0.0.0:1254\"、\"[::]:1254\"、\"1.2.3.4:1254\"；\
                     IPv6 地址必须带方括号，不要写成 2a0c::1:1254"
                );
            }
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

        // ---- v0.3.0 新增字段：一律 fail-fast，不静默回落 ----
        self.validate_dualstack_fields()?;
        Ok(())
    }

    /// v0.3.0 新增的回源参数校验。
    ///
    /// 单独抽出来是因为 `DialPolicy::from_config` 也必须跑同一套检查（嵌入式调用方
    /// 可以绕过 `validate()` 直接手改 `Config` 字段），两处共用一份真源。
    fn validate_dualstack_fields(&self) -> anyhow::Result<()> {
        self.family_preference()?;

        if self.happy_eyeballs_ms == 0 || self.happy_eyeballs_ms > MAX_HAPPY_EYEBALLS_MS {
            anyhow::bail!(
                "invalid happy_eyeballs_ms={} (must be 1..={})",
                self.happy_eyeballs_ms,
                MAX_HAPPY_EYEBALLS_MS
            );
        }
        if self.dial_probe_count == 0 || self.dial_probe_count > MAX_DIAL_PROBE_COUNT {
            anyhow::bail!(
                "invalid dial_probe_count={} (must be 1..={})",
                self.dial_probe_count,
                MAX_DIAL_PROBE_COUNT
            );
        }
        // {0} ∪ [MIN_MSS, MAX_MSS]：故意不做 clamp，理由见字段注释
        if self.outbound_mss != 0
            && !(MIN_MSS..=cns_core::transport::MAX_MSS).contains(&self.outbound_mss)
        {
            anyhow::bail!(
                "invalid outbound_mss={} (must be 0 or {MIN_MSS}..={})",
                self.outbound_mss,
                cns_core::transport::MAX_MSS
            );
        }
        // 允许「非规范网络地址」写法（198.18.5.77/15）：IpCidr 会先掩码归一化。
        // IpCidr::parse 的错误必须透出给运维 —— 段配错等于守卫静默失效，
        // 而守卫静默失效的表现是「解析环 + 随机超时」，事后极难归因。
        for spec in &self.fakeip_guard_cidrs {
            IpCidr::parse(spec)
                .map_err(|e| anyhow::anyhow!("invalid fakeip_guard_cidrs entry: {e}"))?;
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

    /// 解析并校验 `prefer_family`（非法值返回 Err，绝不回落 auto）。
    /// 启动期被 `validate()` 调一次，之后走 `DialPolicy::from_config`。
    pub fn family_preference(&self) -> anyhow::Result<FamilyPreference> {
        FamilyPreference::parse(&self.prefer_family)
    }

    /// fakeip 守卫段的**解析视图**（启动期校验用，错误信息必须可读）。
    pub fn parsed_fakeip_guard_cidrs(&self) -> anyhow::Result<Vec<IpCidr>> {
        self.fakeip_guard_cidrs
            .iter()
            .map(|s| IpCidr::parse(s).map_err(|e| anyhow::anyhow!("invalid CIDR: {e}")))
            .collect()
    }
}

/// 回源拨号策略：`Config` 里那几个新字段的**校验过**的运行时视图。
///
/// 为什么单独有这个类型而不是让 `dial_tcp` 直接读 `Config`：
/// * `prefer_family` 每连接都要解析字符串（`Config` 存的是 String，兼容旧 JSON），
///   一次解析一次失败，避免热路径反复 `bail!`；
/// * `fakeip_guard_cidrs` 必须解析成 `IpCidr` 才安全 —— 手写 `ip_in_cidr` 曾把
///   IPv4-mapped 的 `::ffff:198.18.0.1` 漏掉（族不匹配直接 false），那正是
///   fakeip 泄漏最容易走的路径。`IpCidr::contains` 内部先 `canonicalize_ip`。
/// * 构造即校验，非法值根本拿不到实例（`Guard` 的 `allow_private` 是同类思路）。
#[derive(Debug, Clone)]
pub struct DialPolicy {
    pub prefer: FamilyPreference,
    pub happy_eyeballs: Duration,
    pub probe_count: usize,
    pub outbound_mss: u16,
    /// 解析好的 fakeip 段；`Arc` 让每次拨号复制 policy 时不重复 clone Vec
    pub fakeip_guard: Arc<Vec<IpCidr>>,
    /// 单个候选的 connect 预算（来自 `dial_timeout`）
    pub dial_timeout: Duration,
}

impl DialPolicy {
    /// 从配置构造，逐字段校验。这是 v0.2.0 起「不许静默回落」原则在 dial 侧的落点：
    /// 即便调用方绕过了 `Config::validate()`（比如嵌入式用法直接 `Config::default()`
    /// 后手改字段），这里仍会拒绝非法值。
    pub fn from_config(cfg: &Config) -> anyhow::Result<Self> {
        // 复用 Config 的同一套校验：热路径拿到的 policy 一定是「合法值视图」，
        // dial 内部就不需要再对 mss/probe_count 做第二次判断（也就没有第二套真源）。
        cfg.validate_dualstack_fields()?;
        Ok(Self {
            prefer: cfg.family_preference()?,
            happy_eyeballs: Duration::from_millis(cfg.happy_eyeballs_ms),
            probe_count: cfg.dial_probe_count,
            outbound_mss: cfg.outbound_mss,
            fakeip_guard: Arc::new(cfg.parsed_fakeip_guard_cidrs()?),
            dial_timeout: cfg.dial_timeout_duration(),
        })
    }

    /// 兜底视图：给「配置已被判定非法、仍要打印一行诊断」的路径用（启动失败日志）。
    /// 业务路径必须用 `from_config`，它保证拿到的是合法值。
    pub fn diag_from_config(cfg: &Config) -> Self {
        Self {
            prefer: cfg.family_preference().unwrap_or(FamilyPreference::Auto),
            happy_eyeballs: Duration::from_millis(cfg.happy_eyeballs_ms.min(MAX_HAPPY_EYEBALLS_MS)),
            probe_count: cfg.dial_probe_count.clamp(1, MAX_DIAL_PROBE_COUNT),
            outbound_mss: cfg.outbound_mss,
            fakeip_guard: Arc::new(
                cfg.fakeip_guard_cidrs.iter().filter_map(|s| IpCidr::parse(s).ok()).collect(),
            ),
            dial_timeout: cfg.dial_timeout_duration(),
        }
    }

    /// 目标是否落在客户端 fakeip 段内。
    ///
    /// 公开出来（而非只在本模块用）是因为 httpDNS 的应答同样不能回 fakeip：
    /// 给客户端返回一个 fakeip 只会让泄漏往回传一层。
    pub fn is_fakeip_leak(&self, ip: IpAddr) -> bool {
        self.fakeip_guard.iter().any(|c| c.contains(ip))
    }

    /// 把 fakeip 段注入 `Guard`，得到「SSRF 守卫 + fakeip 泄漏守卫」的完整视图。
    ///
    /// 注入点放在这里（而不是每个调用方自己 `with_fakeip_guard`）是为了保证
    /// 任何一条回源路径都不会漏掉守卫 —— 漏掉的后果是解析环，不是报错。
    pub fn apply_to(&self, guard: crate::outbound::Guard) -> crate::outbound::Guard {
        guard.with_fakeip_guard(Arc::clone(&self.fakeip_guard))
    }

    pub fn fakeip_guard_display(&self) -> String {
        if self.fakeip_guard.is_empty() {
            return "-".to_string();
        }
        self.fakeip_guard.iter().map(|c| c.display()).collect::<Vec<_>>().join(",")
    }

    /// 一行诊断文本，供启动日志与 `--stats` 打印（把「看不见的择优策略」变成可见的）。
    pub fn diag_line(&self) -> String {
        format!(
            "prefer={} eyeballs={}ms probes={} mss={} fakeip_guard=[{}]",
            self.prefer,
            self.happy_eyeballs.as_millis(),
            self.probe_count,
            if self.outbound_mss == 0 { "off".to_string() } else { self.outbound_mss.to_string() },
            self.fakeip_guard_display(),
        )
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
///
/// 保留是给 `allow_target_cidrs` 的既有路径用的。**新代码一律用 `IpCidr`**：
/// 它做了主机位清零、前导零拒绝与 IPv4-mapped 规范化，这个函数都没有。
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

    /// 旧 JSON 不含 v0.3.0 字段也必须能起（默认值即最终行为）
    #[test]
    fn v030_defaults_match_contract() {
        let cfg: Config = serde_json::from_str("{}").unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.prefer_family, "auto");
        assert_eq!(cfg.happy_eyeballs_ms, 200);
        assert_eq!(cfg.dial_probe_count, 8);
        assert_eq!(cfg.outbound_mss, 1310);
        assert_eq!(cfg.fakeip_guard_cidrs, vec!["198.18.0.0/15", "fd53::/48"]);

        let d = DialPolicy::from_config(&cfg).unwrap();
        assert_eq!(d.prefer, FamilyPreference::Auto);
        assert_eq!(d.happy_eyeballs, Duration::from_millis(200));
        assert_eq!(d.probe_count, 8);
        assert_eq!(d.outbound_mss, 1310);
        assert_eq!(d.fakeip_guard.len(), 2);
        // 与客户端 ClientConfig 默认 fakeip 段同源
        assert!(d.is_fakeip_leak("198.18.0.77".parse().unwrap()));
        assert!(d.is_fakeip_leak("fd53::1234".parse().unwrap()));
        assert!(!d.is_fakeip_leak("1.1.1.1".parse().unwrap()));
    }

    /// 当前部署参数必须原样可读（config.json 里是真实值，不是占位符）
    #[test]
    fn deployed_config_json_still_validates() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config.json");
        let Ok(raw) = fs::read_to_string(&path) else { return };
        let cfg: Config = serde_json::from_str(&raw).unwrap();
        cfg.validate().expect("deployed config.json must pass validation");
        assert_eq!(cfg.listen_addr, vec!["[::]:21200"]);
        assert_eq!(cfg.encrypt_password, "换成你的口令");
        assert_eq!(cfg.prefer_family, "auto");
        assert_eq!(cfg.happy_eyeballs_ms, 200);
        assert_eq!(cfg.outbound_mss, 1260);
        assert_eq!(cfg.fakeip_guard_cidrs, vec!["198.18.0.0/15", "fd53::/48"]);
    }

    /// 每个新字段的非法值都必须被拒，且**不静默回落**
    #[test]
    fn v030_invalid_values_are_rejected_not_defaulted() {
        let cases = [
            r#"{"prefer_family":"ipv5"}"#,
            r#"{"prefer_family":"dual"}"#,
            r#"{"happy_eyeballs_ms":0}"#,
            r#"{"happy_eyeballs_ms":2001}"#,
            r#"{"dial_probe_count":0}"#,
            r#"{"dial_probe_count":65}"#,
            r#"{"outbound_mss":535}"#,
            r#"{"outbound_mss":1461}"#,
            r#"{"outbound_mss":15000}"#,
            r#"{"fakeip_guard_cidrs":["198.18.0.0/33"]}"#,
            r#"{"fakeip_guard_cidrs":["not-a-cidr"]}"#,
            r#"{"fakeip_guard_cidrs":["010.0.0.0/8"]}"#,
            r#"{"fakeip_guard_cidrs":["[fd53::]/48"]}"#,
        ];
        for raw in cases {
            let cfg: Config = serde_json::from_str(raw).unwrap();
            let msg = cfg.validate().unwrap_err().to_string();
            // 错误信息里必须带上 offending 值，否则运维对着两个 CIDR 列表猜哪个错了
            assert!(!msg.is_empty(), "{raw} rejected with no message");
            assert!(
                msg.contains("prefer_family")
                    || msg.contains("happy_eyeballs_ms")
                    || msg.contains("dial_probe_count")
                    || msg.contains("outbound_mss")
                    || msg.contains("fakeip_guard_cidrs"),
                "{raw} rejected without naming the field: {msg}"
            );
        }

        // 合法边界值：0（关 MSS）、1、2000、64、MIN/MAX_MSS
        for raw in [
            r#"{"outbound_mss":0}"#,
            r#"{"outbound_mss":536,"happy_eyeballs_ms":1,"dial_probe_count":64}"#,
            r#"{"outbound_mss":1460,"happy_eyeballs_ms":2000,"dial_probe_count":1}"#,
            r#"{"prefer_family":"IPv6"}"#,
            r#"{"prefer_family":" ipv4 "}"#,
            r#"{"prefer_family":""}"#,
            r#"{"fakeip_guard_cidrs":[]}"#,
        ] {
            let cfg: Config = serde_json::from_str(raw).unwrap();
            cfg.validate().unwrap_or_else(|e| panic!("{raw} should be valid: {e}"));
        }
    }

    /// 错误消息要点名具体字段与取值，「配置非法」这种话在现场帮不了任何人
    #[test]
    fn validation_errors_name_the_field() {
        let cfg: Config = serde_json::from_str(r#"{"prefer_family":"ipv5"}"#).unwrap();
        let msg = cfg.validate().unwrap_err().to_string();
        assert!(msg.contains("prefer_family"), "{msg}");
        assert!(msg.contains("ipv5"), "{msg}");

        let cfg: Config = serde_json::from_str(r#"{"outbound_mss":15000}"#).unwrap();
        let msg = cfg.validate().unwrap_err().to_string();
        assert!(msg.contains("outbound_mss=15000"), "{msg}");

        let cfg: Config = serde_json::from_str(r#"{"fakeip_guard_cidrs":["fd53::/200"]}"#).unwrap();
        let msg = cfg.validate().unwrap_err().to_string();
        assert!(msg.contains("fakeip_guard_cidrs"), "{msg}");
    }

    #[test]
    fn family_preference_semantics() {
        assert_eq!(FamilyPreference::parse("AUTO").unwrap(), FamilyPreference::Auto);
        assert_eq!(FamilyPreference::parse("v6").unwrap(), FamilyPreference::Ipv6);
        assert_eq!(FamilyPreference::parse("V4").unwrap(), FamilyPreference::Ipv4);
        assert!(FamilyPreference::parse("").unwrap().is_auto());
        assert!(FamilyPreference::parse("  ").unwrap().is_auto());
        assert!(FamilyPreference::parse("both").is_err());

        let v4: IpAddr = "1.1.1.1".parse().unwrap();
        let v6: IpAddr = "2001:4860::8888".parse().unwrap();
        assert!(FamilyPreference::Auto.accepts(v4) && FamilyPreference::Auto.accepts(v6));
        assert!(FamilyPreference::Ipv4.accepts(v4) && !FamilyPreference::Ipv4.accepts(v6));
        assert!(FamilyPreference::Ipv6.accepts(v6) && !FamilyPreference::Ipv6.accepts(v4));
        // auto 不指定首发族（由 v6 首发的竞速顺序决定）
        assert_eq!(FamilyPreference::Auto.first_family(), None);
        assert_eq!(FamilyPreference::Ipv4.first_family(), Some(false));
        assert_eq!(FamilyPreference::Ipv6.first_family(), Some(true));
        assert_eq!(FamilyPreference::Ipv6.to_string(), "ipv6");
    }

    /// fakeip 守卫：IPv4-mapped 的 fakeip 也必须拦住（客户端 tproxy 拿到的
    /// local_addr 在双栈 socket 上就是 ::ffff:x 形式）
    #[test]
    fn fakeip_guard_covers_mapped_and_non_normalized_input() {
        // 空列表 = 守卫关闭，合法配置（不能因为「少了默认段」就拒绝启动）
        let cfg: Config = serde_json::from_str(r#"{"fakeip_guard_cidrs":[]}"#).unwrap();
        cfg.validate().expect("empty guard list is legal (guard disabled)");
        let d = DialPolicy::from_config(&cfg).unwrap();
        assert!(!d.is_fakeip_leak("198.18.0.1".parse().unwrap()), "列表空了就不该拦");

        let mut cfg = Config::default();
        // 非规范网络地址写法：运维手滑把主机位写进去，仍应覆盖整段
        cfg.fakeip_guard_cidrs = vec!["198.18.5.77/15".to_string()];
        let d = DialPolicy::from_config(&cfg).unwrap();
        assert!(d.is_fakeip_leak("198.19.255.254".parse().unwrap()));
        assert!(!d.is_fakeip_leak("198.16.0.1".parse().unwrap()));

        cfg.fakeip_guard_cidrs = vec!["fd53::/48".to_string()];
        let d = DialPolicy::from_config(&cfg).unwrap();
        assert!(d.is_fakeip_leak("fd53::abcd".parse().unwrap()));
        assert!(!d.is_fakeip_leak("fd54::1".parse().unwrap()), "别的 ULA 段不该被误杀");
        // v6 段列表绝不吞 v4 地址（族匹配）
        assert!(!d.is_fakeip_leak("198.18.0.1".parse().unwrap()));

        // 关键：IPv4-mapped 形式的 fakeip 必须命中 v4 段 —— IpCidr::contains 内部
        // 先 canonicalize_ip，这正是弃用本地 ip_in_cidr（族不一致直接 false）的原因。
        cfg.fakeip_guard_cidrs = vec!["198.18.0.0/15".to_string()];
        let d = DialPolicy::from_config(&cfg).unwrap();
        assert!(
            d.is_fakeip_leak("::ffff:198.18.0.77".parse().unwrap()),
            "IPv4-mapped fakeip 泄漏必须拦住"
        );
        assert!(!d.is_fakeip_leak("::ffff:1.1.1.1".parse().unwrap()));
    }

    /// DialPolicy 构造即校验：绕过 Config::validate 的手改字段也拦得住
    #[test]
    fn dial_policy_rejects_illegal_config() {
        let cfg = Config { prefer_family: "ipv5".into(), ..Default::default() };
        assert!(DialPolicy::from_config(&cfg).is_err());

        let cfg = Config { happy_eyeballs_ms: 0, ..Default::default() };
        assert!(DialPolicy::from_config(&cfg).is_err());

        let cfg = Config { fakeip_guard_cidrs: vec!["198.18.0.0/15".into()], ..Default::default() };
        let d = DialPolicy::from_config(&cfg).unwrap();
        assert!(d.diag_line().contains("prefer=auto"));
        assert!(d.diag_line().contains("198.18.0.0/15"));
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
