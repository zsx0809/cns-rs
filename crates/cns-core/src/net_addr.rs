//! 地址/端点解析的统一入口。
//!
//! 存在的理由有三条，每一条都是实测踩出来的：
//!
//! 1. **curl 与 getaddrinfo 对「裸 IPv6 + 端口」的宽容度不同。**
//!    Rust 的 `ToSocketAddrs` 走系统 `getaddrinfo`，`2a0c:…::12c:13872` 能被它猜出来；
//!    而 curl 严格按 RFC 3986 解析 URL，同一个串直接 `exit 3 / URL rejected`，
//!    于是模块的连通性检测把「脚本拼装 URL 的 bug」报成「服务端不可达」。
//!    结论：凡是要进 URL 的地址，**必须**先加方括号，绝不指望对端宽容。
//!
//! 2. **`getaddrinfo` 不认「完整 8 段、无端口」的裸 IPv6。**
//!    `2001:db8:0:1:2:3:4:5` 作为 `cns_server`（端口走默认）在 shell 侧能补成
//!    `:1254`，在 Rust 侧却 `Name or service not known`。同一个配置文件、两种命运，
//!    这是最难查的那类不一致。这里显式补默认端口，让两边行为对齐。
//!
//! 3. **歧义必须消歧，而不是留给运气。**
//!    `a:b:c:d` 这种四段短 IPv6 + 数字尾巴，语法上既像地址又像地址:端口。
//!    判定规则：末段若 >4 个十六进制字符，它**不可能**是 IPv6 分组（分组上限 4 位），
//!    必然是端口；反之若整串是合法 IPv6，则按纯地址解释并补默认端口。
//!    需要「完整 8 段地址 + 自定义端口」时，唯一正确写法是方括号。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// 配置里没写端口时使用的 CNS 服务端默认端口。
pub const DEFAULT_CNS_PORT: u16 = 1254;

/// 归一化后的端点，`host` 永不含方括号（便于喂 `iptables -d` / 日志对齐）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// 字面 IP 或域名，**不含方括号、不含 zone id**
    pub host: String,
    pub port: u16,
    /// 字面 IPv6 地址
    pub is_ipv6: bool,
}

impl Endpoint {
    /// 展示/拼接形式：IPv6 自动带方括号。
    /// 任何进 URL 的 host 都应走这里，不要手写 `format!("{host}:{port}")`。
    pub fn display(&self) -> String {
        if self.is_ipv6 {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// 拼 URL（IPv6 加方括号）。`scheme` 例："http"。
    pub fn to_url(&self, scheme: &str) -> String {
        format!("{scheme}://{}/", self.display())
    }
}

/// 是否为字面 IPv4（严格：四段、每段 0-255、不允许前导零）。
pub fn is_ipv4_literal(s: &str) -> bool {
    s.parse::<std::net::Ipv4Addr>().is_ok()
}

/// 是否为字面 IPv6（不含方括号；允许内嵌末段 IPv4，**不允许** zone id）。
pub fn is_ipv6_literal(s: &str) -> bool {
    s.parse::<std::net::Ipv6Addr>().is_ok()
}

/// 去掉 `%wlan0` 之类的 zone id。
///
/// 这里刻意**不**做宽容：链路本地地址的 zone id 对「连出去的服务端」毫无意义
/// （从手机去连 `fe80::1%wlan0` 基本不可能是用户本意），静默剥离只会把配错
/// 的地址变成另一条规则。因此两侧实现（shell 与 Rust）一律显式拒绝。
fn reject_zone(spec: &str) -> Result<(), String> {
    if spec.contains('%') {
        return Err(format!(
            "不支持 zone id（%…）: {spec}。链路本地地址无法作为公网服务端，\
             请填全局地址，例如 [2001:db8::1]:13872"
        ));
    }
    Ok(())
}

/// 解析配置里的 `cns_server` / 监听项 / 上游项。
///
/// 接受的全部写法：
/// * `1.2.3.4:1254`、`1.2.3.4`
/// * `example.com:443`、`example.com`
/// * `[2a0c::12c]:13872`、`[2a0c::12c]`（推荐）
/// * `2a0c::12c:13872`（裸 IPv6+端口，宽容支持）
/// * `2001:db8:0:1:2:3:4:5`（完整 8 段，补默认端口）
/// * `fe80::1%wlan0:1254`（zone id 自动剥离）
/// * `:1254` / `*:1254`（仅端口，host 为空——监听场景）
///
/// 错误信息必须具体：配置错是现场最常见的故障源，`invalid address` 这种话帮不了任何人。
pub fn parse_endpoint(spec: &str, default_port: u16) -> Result<Endpoint, String> {
    let raw = spec.trim();
    if raw.is_empty() {
        return Err("地址为空".to_string());
    }
    // 容忍误填的 scheme 与路径
    let mut s = raw;
    if let Some(pos) = s.find("://") {
        s = &s[pos + 3..];
    }
    if let Some(pos) = s.find('/') {
        s = &s[..pos];
    }
    reject_zone(s)?;

    // ---- 方括号形式 ----
    if s.starts_with('[') {
        let end = s.find(']').ok_or_else(|| format!("方括号不成对: {spec}"))?;
        let host = s[1..end].to_string();
        if host.is_empty() {
            return Err(format!("方括号内主机为空: {spec}"));
        }
        let rest = &s[end + 1..];
        let port = match rest {
            "" => default_port,
            other => {
                let p = other
                    .strip_prefix(':')
                    .ok_or_else(|| format!("方括号后必须是 :端口，实际是 {other}"))?;
                parse_port(p, spec)?
            }
        };
        // 括号里也可能是 IPv4（[1.2.3.4]:443 合法）
        let v6 = is_ipv6_literal(&host);
        if !v6 && !is_ipv4_literal(&host) && !is_domain(&host) {
            return Err(format!("方括号内不是合法地址: {host}"));
        }
        return Ok(Endpoint { host, port, is_ipv6: v6 });
    }
    if s.contains(']') {
        return Err(format!("方括号不成对: {spec}"));
    }

    // 分支顺序即优先级，写错就会串场景（实测踩过）：
    //   方括号 > 纯 IPv6 > 纯 IPv4/域名 > 裸 IPv6(+端口) > 单冒号(host:port / :port)
    // `:1254` 这种「只有端口」必须放到最后，否则 `::1:13899` 会被它抢走。

    // ---- 整串就是纯 IPv6（无端口）----
    if is_ipv6_literal(s) {
        return Ok(Endpoint { host: s.to_string(), port: default_port, is_ipv6: true });
    }

    // ---- 整串就是纯 IPv4 / 域名（无冒号）----
    if !s.contains(':') {
        let host = s.to_string();
        if !is_ipv4_literal(&host) && !is_domain(&host) {
            return Err(format!("既不是 IP 也不是合法域名: {host}"));
        }
        return Ok(Endpoint { host, port: default_port, is_ipv6: false });
    }

    // ---- 含冒号：裸 IPv6（可能带端口）----
    // 能走到这里，说明整串**不是**合法 IPv6（分支已在上一步排除）。
    if s.matches(':').count() >= 2 {
        let (head, tail) = s.rsplit_once(':').expect("含冒号");
        let tail_numeric = !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit());
        if tail_numeric && is_ipv6_literal(head) {
            return Ok(Endpoint {
                host: head.to_string(),
                port: parse_port(tail, spec)?,
                is_ipv6: true,
            });
        }
        return Err(format!(
            "无法解析裸 IPv6: {spec}。IPv6 与端口同时出现时必须用方括号，\
             例如 [{head}]:{tail}"
        ));
    }

    // ---- 恰好一个冒号：IPv4:端口 / 域名:端口 / 仅端口(:1254) ----
    let (host, port_s) = s.rsplit_once(':').expect("colon_count==1");
    let port = parse_port(port_s, spec)?;
    // 「只有端口」是服务端/客户端监听项的合法写法（`:1254`、`*:1254`），
    // 放在这里而不是开头，正是为了让 `::1:13899` 先被纯 IPv6/裸 IPv6 分支接住。
    if host.is_empty() || host == "*" {
        return Ok(Endpoint { host: String::new(), port, is_ipv6: false });
    }
    if is_ipv4_literal(host) {
        return Ok(Endpoint { host: host.to_string(), port, is_ipv6: false });
    }
    if !is_domain(host) {
        return Err(format!("主机部分非法: {host}"));
    }
    Ok(Endpoint { host: host.to_string(), port, is_ipv6: false })
}

fn parse_port(p: &str, spec: &str) -> Result<u16, String> {
    if p.is_empty() {
        return Err(format!("端口为空: {spec}"));
    }
    if !p.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("端口含非数字字符: {p}（来自 {spec}）"));
    }
    if p.len() > 1 && p.starts_with('0') {
        return Err(format!("端口不允许前导零: {p}（来自 {spec}）"));
    }
    let v: u32 = p.parse().map_err(|_| format!("端口越界: {p}（来自 {spec}）"))?;
    if v == 0 {
        return Err(format!("端口不能为 0: {spec}"));
    }
    if v > 65535 {
        return Err(format!("端口越界（>65535）: {p}（来自 {spec}）"));
    }
    Ok(v as u16)
}

/// 极宽松的域名校验（够用来挡住空格/斜杠/方括号这类误填）。
fn is_domain(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 2 || b.len() > 253 {
        return false;
    }
    if !b[0].is_ascii_alphanumeric() || !b[b.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_'))
}

/// 归一化任意地址写法为 `SocketAddr` 可解析的串（IPv6 补方括号、补默认端口）。
///
/// 用途：把用户写的 `2a0c::1:13872` / `223.5.5.5` 变成 `[2a0c::1]:13872` / `223.5.5.5:53`，
/// 这样 `parse::<SocketAddr>()` 与 `lookup_host()` 都稳定命中。
pub fn normalize_socket_str(spec: &str, default_port: u16) -> Result<String, String> {
    Ok(parse_endpoint(spec, default_port)?.display())
}

/// 直接解析成 `SocketAddr`（host 必须是字面 IP）。
pub fn parse_socket_addr(spec: &str, default_port: u16) -> Result<SocketAddr, String> {
    let ep = parse_endpoint(spec, default_port)?;
    let ip: IpAddr = ep.host.parse().map_err(|_| {
        format!("主机 '{host}' 不是字面 IP（需要解析域名的场景请用 connect_any）", host = ep.host)
    })?;
    Ok(SocketAddr::new(ip, ep.port))
}

/// 把 IPv4-mapped IPv6 地址（`::ffff:a.b.c.d`）还原为纯 IPv4。
///
/// 为什么放在 net_addr 而不是 protocol：这是**地址规范化**，不是协议编解码。
/// 放在叶子模块里，`net_addr` 就不必反向依赖 `protocol` —— 否则
/// `scripts/addr_parity.sh` 那种「把 net_addr.rs 单独编成 harness」的隔离测试
/// 会直接编不过（真实踩过）。`protocol::udp_frame` 反过来 re-export 它。
pub fn canonicalize_ip(ip: IpAddr) -> IpAddr {
    if let IpAddr::V6(v6) = ip {
        let o = v6.octets();
        if o[..10] == [0u8; 10] && o[10..12] == [0xff, 0xff] {
            return IpAddr::V4(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
        }
    }
    ip
}

/// `SocketAddr` 版本的 [`canonicalize_ip`]（端口原样保留）。
pub fn canonicalize_addr(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(canonicalize_ip(addr.ip()), addr.port())
}

/// 极简 CIDR：fakeip 段配置与 fakeip 泄漏守卫共用。
///
/// 为什么不用外部 crate：只需要「包含判断 + 网络地址/前缀长度 + 段内可分配地址数」，
/// 引一个 cidr crate 会让 Termux 上的编译时间再涨一截，而且和 shell 侧的
/// `cns_rules.sh::split_cidr` 差分测试需要保持同一套语义（前导零、超界前缀一律拒绝）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpCidr {
    pub network: IpAddr,
    pub prefix: u8,
}

impl IpCidr {
    /// 解析 `"198.18.0.0/15"`、`"fd53::/48"`；**允许省略前缀**（按 /24 与 /64 补，
    /// 由调用方决定是否 warn —— 省略前缀的 fakeip 段几乎肯定是配置者忘了写）。
    pub fn parse(spec: &str) -> Result<Self, String> {
        let s = spec.trim();
        if s.is_empty() {
            return Err("CIDR 为空".to_string());
        }
        let (addr_str, len_str) = match s.split_once('/') {
            Some((a, l)) => (a.trim(), Some(l.trim())),
            None => (s, None),
        };
        let network: IpAddr = addr_str
            .parse()
            .map_err(|_| format!("CIDR 的网络地址非法: {addr_str}（IPv6 段不要加方括号）"))?;
        let prefix: u8 = match len_str {
            Some(l) => l
                .parse()
                .map_err(|_| format!("CIDR 前缀长度非法: {l}（来自 {spec}）"))?,
            None => {
                if network.is_ipv6() {
                    64
                } else {
                    24
                }
            }
        };
        let max = if network.is_ipv6() { 128 } else { 32 };
        if prefix > max {
            return Err(format!("CIDR 前缀 {prefix} 超过 {max}（来自 {spec}）"));
        }
        // 拒绝前导零：010.0.0.0/8 在不同解析器下含义不同（八进制 vs 十进制）
        if addr_str.split('.').any(|p| p.len() > 1 && p.starts_with('0')) {
            return Err(format!("CIDR 网络地址不允许前导零: {spec}"));
        }
        Ok(Self { network, prefix })
    }

    pub fn is_v6(&self) -> bool {
        self.network.is_ipv6()
    }

    /// 归一化后的网络地址（主机位清零），用于展示与 shell 侧比对。
    pub fn masked(&self) -> IpAddr {
        if self.prefix == 0 {
            return self.network;
        }
        let bits = self.bit_len();
        let mask: u128 = (!0u128) << (bits - self.prefix as u32);
        ip_from_bits(ip_to_u128(self.network) & mask, self.network.is_ipv6())
    }

    #[inline]
    fn bit_len(&self) -> u32 {
        if self.network.is_ipv6() {
            128
        } else {
            32
        }
    }

    /// 是否包含该地址。**v4 段绝不包含 v6 地址**（含 IPv4-mapped：先规范化再判）。
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = canonicalize_ip(ip);
        if ip.is_ipv6() != self.network.is_ipv6() {
            return false;
        }
        if self.prefix == 0 {
            return true;
        }
        let bits = self.bit_len();
        let mask: u128 = (!0u128) << (bits - self.prefix as u32);
        ip_to_u128(self.network) & mask == ip_to_u128(ip) & mask
    }

    /// 展示形式（永远带前缀，与 shell 侧 `to_cidr_display` 一致）。
    pub fn display(&self) -> String {
        format!("{}/{}", self.network, self.prefix)
    }

    /// 段内**可分配**地址数。
    ///
    /// v4 扣掉网络地址与广播地址（/31、/32 例外，没有这两个概念）；
    /// v6 扣掉全零接口 ID（= 段基址本身，形如 `fd53::`）——它长得像
    /// subnet-router-anycast，部分栈与工具会把它特殊化，拿来当 fakeip 不值当。
    pub fn usable_hosts(&self) -> u128 {
        let bits = self.bit_len() as u128;
        let shift = (bits - self.prefix as u128).min(127);
        let total = 1u128 << shift;
        if self.network.is_ipv6() {
            total.saturating_sub(1)
        } else if self.prefix >= 31 || total < 2 {
            total
        } else {
            total - 2
        }
    }

    /// 段内第一个**可分配**地址（v4 跳过网络地址，v6 跳过段基址）。
    /// fakeip 分配器的游标起点，也是 shell 侧自检比对的锚点。
    pub fn first_usable(&self) -> IpAddr {
        let base = self.masked();
        if self.network.is_ipv6() {
            return ip_from_bits(ip_to_u128(base) + 1, true);
        }
        // /31 与 /32 没有「网络地址」可跳
        if self.prefix >= 31 {
            return base;
        }
        ip_from_bits(ip_to_u128(base) + 1, false)
    }

    /// 段内第 n 个可分配地址（n 从 0 起；越界返回 None，绝不回绕）。
    pub fn nth_usable(&self, n: u128) -> Option<IpAddr> {
        let hosts = self.usable_hosts();
        if hosts == 0 || n >= hosts {
            return None;
        }
        let v6 = self.network.is_ipv6();
        let bits = if v6 { 128 } else { 32 };
        let raw = ip_to_u128(self.first_usable()) + n;
        // 保险：结果必须仍在段内（v4 还要不是广播地址）
        let size = 1u128 << (bits - self.prefix as u128).min(127);
        if raw - ip_to_u128(self.masked()) >= size {
            return None;
        }
        if !v6 && self.prefix < 31 && raw - ip_to_u128(self.masked()) == size - 1 {
            return None; // 广播地址
        }
        Some(ip_from_bits(raw, v6))
    }
}

/// `IpCidr::parse` 的 `FromStr` 形态，让调用方能写 `s.parse::<IpCidr>()`。
///
/// 补这个实现的理由很实际：`ClientConfig` 里 fakeip 段是字符串，各处都要转成
/// `IpCidr`；有 `FromStr` 才能进 `?` 链与 `serde` 的 deserialize_with，
/// 否则每个调用点都要手写一遍 `.map_err(...)`。
impl std::str::FromStr for IpCidr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        IpCidr::parse(s)
    }
}

impl std::fmt::Display for IpCidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

#[inline]
fn ip_to_bits(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => {
            let mut o = [0u8; 16];
            o[12..].copy_from_slice(&v4.octets());
            o
        }
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// `IpAddr` → u128 位表示（v4 落在低 32 位，与 IPv4-mapped 同构）
pub fn ip_from_bits(v: u128, v6: bool) -> IpAddr {
    if v6 {
        IpAddr::V6(Ipv6Addr::from(v.to_be_bytes()))
    } else {
        IpAddr::V4(Ipv4Addr::from((v as u32).to_be_bytes()))
    }
}

/// `IpAddr` → 位表示
pub fn ip_to_u128(ip: IpAddr) -> u128 {
    u128::from_be_bytes(ip_to_bits(canonicalize_ip(ip)))
}

/// 把地址按前缀长度向下对齐（`240e:47c:d6c8:170f::1` + 40 → `240e:47c:d6c0::`）。
pub fn mask_addr(ip: IpAddr, prefix: u8) -> IpAddr {
    let v6 = ip.is_ipv6();
    let bits = if v6 { 128 } else { 32 };
    if prefix == 0 || prefix as u32 >= bits {
        return ip;
    }
    let mask: u128 = (!0u128) << (bits - prefix as u32);
    ip_from_bits(ip_to_u128(ip) & mask, v6)
}

/// 全局单播 IPv6（2000::/3）判定 —— fakeip 基底必须用它。
pub fn is_global_unicast_v6(ip: Ipv6Addr) -> bool {
    let first = ip.octets()[0];
    // 2000::/3 = 前三位 001；first 为 0 时是未指定/回环族，单独排除
    first != 0 && (first & 0b1110_0000) == 0b0010_0000
}

/// 从本机全局 IPv6 地址推导 fakeip 的 v6 段（`fakeip_v6_from_own_prefix`）。
///
/// 主次关系要说清楚：
/// * **主**：fakeip 能不能被劫持，取决于路由 —— `ip -6 route add local <段> dev lo
///   table local`（实测：任意 UID 的 socket 连 `fd53::77:443` 都被本机通配监听接住，
///   `local_addr` 就是原始目的地址）。必须用 `table local`：它是 pref 0，排在 netd 那
///   堆 per-UID / netid 策略路由（pref 11000/15040/22040/25000/29040）之前，
///   下进 main 表会被它们抢先劫走。
/// * **次**（这个函数管的部分）：段落在**本机自己的 /48 内**，好处是即使某条 local
///   路由没下成功，包也是发往与本机遇同前缀的地址，源地址选择与邻居发现都成立，
///   表现是超时而不是被 App 判定 IPv6 不可达；反过来，ULA 段（fd00::/8）一旦漏过
///   劫持就是永远不可达的黑洞地址，而 Chrome/OkHttp 类栈会因此把 AAAA 结果整体
///   拉黑、退回 IPv4-only —— 那正好又把「图片加载失败」请回来了。
///
/// 粒度取 /64：只占 /48 里的一个 /64，与真实邻居地址冲突概率极低，
/// 且自动跳过本机地址所在的那个 /64。
///
/// `marker` 是首选的 /64 编号（0x01..=0xff）；与本机 /64 撞号时自动顺延。
/// `marker == 0` 非法（语义不清），返回 None；没有全局 v6 时同样返回 None，
/// 调用方回退到配置里的固定段（`fd53::/48`）。
pub fn derive_fakeip_v6_prefix(
    addrs: &[Ipv6Addr],
    marker: u8,
) -> Option<(IpCidr, Ipv6Addr)> {
    if marker == 0 {
        return None;
    }
    let own = addrs.iter().copied().find(|a| is_global_unicast_v6(*a))?;
    let IpAddr::V6(base48) = mask_addr(IpAddr::V6(own), 48) else { return None };
    let own_64 = mask_addr(IpAddr::V6(own), 64);

    // 第 49~64 位就是 o[6]、o[7]：把 o[6] 当 /64 编号，o[7] 留 0
    let mut o = base48.octets();
    for delta in 0..=0xffu16 {
        let m = ((marker as u16 + delta) & 0xff) as u8;
        if m == 0 {
            continue; // 编号 0 = /48 基址本身，留给真实地址用
        }
        o[6] = m;
        o[7] = 0;
        let cand = Ipv6Addr::from(o);
        if mask_addr(IpAddr::V6(cand), 64) != own_64 {
            return Some((IpCidr { network: IpAddr::V6(cand), prefix: 64 }, own));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(spec: &str, host: &str, port: u16, v6: bool) {
        let ep = parse_endpoint(spec, DEFAULT_CNS_PORT)
            .unwrap_or_else(|e| panic!("{spec} 应解析成功，实际报错: {e}"));
        assert_eq!(ep.host, host, "{spec} host");
        assert_eq!(ep.port, port, "{spec} port");
        assert_eq!(ep.is_ipv6, v6, "{spec} 族判定");
    }

    fn bad(spec: &str) {
        assert!(parse_endpoint(spec, DEFAULT_CNS_PORT).is_err(), "{spec} 应该报错");
    }

    #[test]
    fn parses_ipv4_and_domain() {
        ok("1.2.3.4:1254", "1.2.3.4", 1254, false);
        ok("1.2.3.4", "1.2.3.4", DEFAULT_CNS_PORT, false);
        ok("example.com:443", "example.com", 443, false);
        ok("example.com", "example.com", DEFAULT_CNS_PORT, false);
        ok("[1.2.3.4]:8080", "1.2.3.4", 8080, false);
        assert!(is_ipv4_literal("10.0.0.200"));
        assert!(!is_ipv4_literal("1.2.3"));
        assert!(!is_ipv4_literal("300.1.1.1"));
        // 域名含点，绝不能被当成字面 IP
        assert!(!is_ipv4_literal("example.com"));
        assert!(!is_ipv4_literal("01.2.3.4"));
    }

    #[test]
    fn parses_bracketed_ipv6() {
        ok("[2001:db8::1]:13872", "2001:db8::1", 13872, true);
        ok("[2001:db8::1]", "2001:db8::1", DEFAULT_CNS_PORT, true);
        ok("[::1]:13899", "::1", 13899, true);
        ok("http://[2a0c::12c]:13872/", "2a0c::12c", 13872, true);
    }

    /// 回归：用户的原始写法。shell 与 Rust 必须给出同一个结果。
    #[test]
    fn parses_bare_ipv6_with_port() {
        ok("2001:db8::1:13872", "2001:db8::1", 13872, true);
        ok("::1:13899", "::1", 13899, true);
    }

    /// 回归：完整 8 段裸地址。getaddrinfo 会拒绝它，这里必须补默认端口。
    #[test]
    fn full_eight_group_ipv6_gets_default_port() {
        ok("2001:db8:0:1:2:3:4:5", "2001:db8:0:1:2:3:4:5", DEFAULT_CNS_PORT, true);
        assert_eq!(
            normalize_socket_str("2001:db8:0:1:2:3:4:5", DEFAULT_CNS_PORT).unwrap(),
            "[2001:db8:0:1:2:3:4:5]:1254"
        );
    }

    /// zone id 一律显式拒绝（shell 侧同规则）：静默 `fe80::1%wlan0` → `fe80::1`
    /// 会把一个连不上的地址变成一条看起来正确的放行规则，比直接报错更难查。
    #[test]
    fn rejects_zone_id() {
        bad("fe80::1%wlan0:1254");
        bad("[fe80::1%eth0]:8080");
        bad("fe80::1%wlan0");
    }

    #[test]
    fn rejects_malformed() {
        bad("");
        bad("1.2.3.4:0");
        bad("1.2.3.4:abc");
        bad("1.2.3.4:");
        bad("1.2.3.4:99999");
        bad("1.2.3.4:00123");
        bad("[2a0c::12c");
        bad("2a0c::12c]");
        bad("1.2.3.4:1254:77");
        bad("not a host:1254");
        bad("..:1254");
    }

    /// 这是最初那个 bug 的守门测试：URL 里 IPv6 必须带方括号。
    #[test]
    fn ipv6_url_always_bracketed() {
        let ep = parse_endpoint("2001:db8::1:13872", DEFAULT_CNS_PORT).unwrap();
        assert_eq!(ep.to_url("http"), "http://[2001:db8::1]:13872/");
        assert_eq!(
            parse_endpoint("1.2.3.4:1254", DEFAULT_CNS_PORT).unwrap().to_url("http"),
            "http://1.2.3.4:1254/"
        );
        assert_eq!(
            parse_endpoint("example.com:80", DEFAULT_CNS_PORT).unwrap().to_url("http"),
            "http://example.com:80/"
        );
    }

    #[test]
    fn port_only_for_listen() {
        ok(":1254", "", 1254, false);
        ok("*:1254", "", 1254, false);
    }

    #[test]
    fn dns_upstream_normalizes() {
        // 裸 IPv4 补 53
        assert_eq!(normalize_socket_str("223.5.5.5", 53).unwrap(), "223.5.5.5:53");
        // 裸 IPv6 补 53 且带括号
        assert_eq!(normalize_socket_str("2400:3200::1", 53).unwrap(), "[2400:3200::1]:53");
        // 歧义警示：`2400:3200::1:53` 语法上就是一个合法 IPv6（= 2400:3200:0:0:0:1:53），
        // 所以它被当作**纯地址**并补默认端口 53，而不是「2400:3200::1 的 53 端口」。
        // 想表达后者只有一种正确写法：方括号。shell 侧同规则，差分测试已锁死。
        assert_eq!(normalize_socket_str("2400:3200::1:53", 53).unwrap(), "[2400:3200::1:53]:53");
        assert_eq!(normalize_socket_str("[2400:3200::1]:53", 53).unwrap(), "[2400:3200::1]:53");
        assert!(parse_socket_addr("example.com:53", 53).is_err());
    }
}

#[cfg(test)]
mod cidr_tests {
    use super::*;

    #[test]
    fn parses_v4_and_v6_cidr() {
        let c = IpCidr::parse("198.18.0.0/15").unwrap();
        assert_eq!(c.prefix, 15);
        assert!(!c.is_v6());
        assert!(c.contains("198.19.255.254".parse().unwrap()));
        assert!(c.contains("198.18.0.1".parse().unwrap()));
        assert!(!c.contains("198.16.0.0".parse().unwrap()), "下边界外");
        assert!(!c.contains("198.20.0.0".parse().unwrap()), "上边界外");
        assert_eq!(c.display(), "198.18.0.0/15");

        let c6 = IpCidr::parse("fd53::/48").unwrap();
        assert!(c6.is_v6());
        assert!(c6.contains("fd53::7".parse().unwrap()));
        assert!(c6.contains("fd53:0:0:abcd::1".parse().unwrap()));
        assert!(!c6.contains("fd54::1".parse().unwrap()));
        assert!(!c6.contains("fd52:ffff::1".parse().unwrap()));
    }

    #[test]
    fn family_must_match() {
        let c = IpCidr::parse("198.18.0.0/15").unwrap();
        assert!(!c.contains("fd53::1".parse().unwrap()), "v4 段不能包含 v6");
        let c6 = IpCidr::parse("fd53::/48").unwrap();
        assert!(!c6.contains("198.18.0.1".parse().unwrap()), "v6 段不能包含 v4");
        // IPv4-mapped 必须先规范化，否则 ::ffff:198.18.0.1 会「逃出」v4 段
        assert!(c.contains("::ffff:198.18.0.1".parse().unwrap()));
    }

    #[test]
    fn missing_prefix_gets_sane_default() {
        assert_eq!(IpCidr::parse("198.18.0.0").unwrap().prefix, 24);
        assert_eq!(IpCidr::parse("fd53::").unwrap().prefix, 64);
    }

    #[test]
    fn rejects_garbage_and_leading_zeros() {
        for bad in [
            "", "  ", "198.18.0.0/33", "fd53::/129", "1.2.3/24", "example.com/24",
            "[fd53::]/48", "010.0.0.0/8", "198.18.0.0/abc", "198.18.0.0/-1",
        ] {
            assert!(IpCidr::parse(bad).is_err(), "{bad} 应当被拒绝");
        }
    }

    #[test]
    fn masked_and_usable_hosts() {
        let c = IpCidr::parse("198.18.5.7/24").unwrap();
        assert_eq!(c.masked().to_string(), "198.18.5.0");
        assert_eq!(c.usable_hosts(), 254);
        // v6 扣掉段基址（形如 fd53::，会被部分栈特殊化）
        assert_eq!(IpCidr::parse("fd53::/48").unwrap().usable_hosts(), (1u128 << 80) - 1);
        assert_eq!(IpCidr::parse("198.18.0.0/15").unwrap().usable_hosts(), (1 << 17) - 2);
    }

    #[test]
    fn whole_prefix_zero_contains_everything_of_family() {
        let c = IpCidr::parse("0.0.0.0/0").unwrap();
        assert!(c.contains("8.8.8.8".parse().unwrap()));
        assert!(!c.contains("fd53::1".parse().unwrap()), "v4/0 不含 v6");
    }

    #[test]
    fn bit_conversions_roundtrip() {
        for s in ["198.18.0.7", "2001:db8::1234"] {
            let ip: IpAddr = s.parse().unwrap();
            let v = ip_to_u128(ip);
            let back = ip_from_bits(v, ip.is_ipv6());
            assert_eq!(back, ip, "{s} 位转换必须可逆");
        }
        // IPv4-mapped：位值必须等于内层 v4 的位值（这正是 v4 段能命中它的原因），
        // 所以「按 v6 还原」得到 IPv4-compatible 形式是**预期**结果，不是 bug。
        let mapped: IpAddr = "::ffff:198.18.0.7".parse().unwrap();
        let plain: IpAddr = "198.18.0.7".parse().unwrap();
        assert_eq!(ip_to_u128(mapped), ip_to_u128(plain), "mapped 与内层 v4 必须同值");
        assert_eq!(ip_from_bits(ip_to_u128(plain), false), plain);
    }

    #[test]
    fn mask_addr_aligns_to_prefix() {
        assert_eq!(
            mask_addr("240e:47c:d6c8:170f:b8d0:c9ff:fe22:91cc".parse().unwrap(), 48).to_string(),
            "240e:47c:d6c8::",
            "/48 必须清零第 7 组及其之后"
        );
        assert_eq!(
            mask_addr("240e:47c:d6c8:170f::1".parse().unwrap(), 40).to_string(),
            "240e:47c:d600::",
            "/40 落在第 3 组的高字节上"
        );
        assert_eq!(mask_addr("202.96.128.86".parse().unwrap(), 24).to_string(), "202.96.128.0");
        assert_eq!(mask_addr("198.18.5.7".parse().unwrap(), 15).to_string(), "198.18.0.0");
        assert_eq!(mask_addr("::1".parse().unwrap(), 0).to_string(), "::1", "prefix=0 不动");
        assert_eq!(
            mask_addr("fd53::7".parse().unwrap(), 128).to_string(),
            "fd53::7",
            "prefix=128 是单地址"
        );
    }

    #[test]
    fn global_unicast_detection() {
        assert!(is_global_unicast_v6("240e:47c:d6c8::1".parse().unwrap()));
        assert!(is_global_unicast_v6("2001:4860::1".parse().unwrap()));
        assert!(is_global_unicast_v6("2408:8556:d020::1".parse().unwrap()));
        assert!(!is_global_unicast_v6("fd53::1".parse().unwrap()), "ULA 不是全局单播");
        assert!(!is_global_unicast_v6("fe80::1".parse().unwrap()), "link-local 不是");
        assert!(!is_global_unicast_v6("::1".parse().unwrap()));
        assert!(!is_global_unicast_v6("ff02::1".parse().unwrap()), "组播不是");
    }

    /// fakeip 的 v6 段落在本机自己的 /40 内（`fakeip_v6_from_own_prefix`）。
    #[test]
    fn derives_prefix_inside_own_allocated_space() {
        let own: Ipv6Addr = "240e:47c:d6c8:170f:b8d0:c9ff:fe22:91cc".parse().unwrap();
        let (cidr, base) = derive_fakeip_v6_prefix(&[own], 0x1f).unwrap();
        assert_eq!(base, own);
        assert_eq!(cidr.prefix, 64);
        // 与本机地址同 /48 —— 这是全部意义所在
        assert_eq!(mask_addr(cidr.network, 48), mask_addr(own.into(), 48), "必须同属运营商分配的 /48");
        // 但落在另一个 /64，避开本机 SLAAC 地址所在段
        assert_ne!(mask_addr(cidr.network, 64), mask_addr(own.into(), 64));
        assert_eq!(cidr.display(), "240e:47c:d6c8:1f00::/64");
        assert!(cidr.contains("240e:47c:d6c8:1f00::7".parse::<IpAddr>().unwrap()));
        assert!(cidr.contains("240e:47c:d6c8:1f00::ffff".parse::<IpAddr>().unwrap()));
        assert!(!cidr.contains(own.into()), "绝不能把本机真实地址当成 fakeip");
        assert!(!cidr.contains("240e:47c:d6c8:170f::1".parse::<IpAddr>().unwrap()), "本机 /64 必须排除");
    }

    #[test]
    fn prefers_first_global_candidate_and_skips_ula_and_linklocal() {
        let ula: Ipv6Addr = "fd11::1".parse().unwrap();
        let ll: Ipv6Addr = "fe80::1".parse().unwrap();
        let g: Ipv6Addr = "2408:8556:d020:de6d:38c4:87ff:fe13:83ed".parse().unwrap();
        let (cidr, base) = derive_fakeip_v6_prefix(&[ula, ll, g], 0x1f).unwrap();
        assert_eq!(base, g, "必须跳过 ULA 与 link-local");
        assert_eq!(mask_addr(cidr.network, 48), mask_addr(g.into(), 48));
        assert_eq!(cidr.display(), "2408:8556:d020:1f00::/64");
        assert!(derive_fakeip_v6_prefix(&[ula, ll], 0x1f).is_none(), "无全局 v6 时返回 None");
        assert!(derive_fakeip_v6_prefix(&[], 0x1f).is_none());
    }

    #[test]
    fn marker_zero_is_refused_and_collision_is_avoided() {
        let own: Ipv6Addr = "240e:47c:d6c8::1".parse().unwrap();
        assert!(
            derive_fakeip_v6_prefix(&[own], 0).is_none(),
            "marker=0 等于 /48 基址，会和真实前缀混用，必须拒绝"
        );
        let (cidr, _) = derive_fakeip_v6_prefix(&[own], 1).unwrap();
        assert_eq!(cidr.display(), "240e:47c:d6c8:100::/64");

        // 首选编号正好撞上本机 /64 时必须自动顺延，而不是返回本机段
        let own2: Ipv6Addr = "240e:47c:d6c8:2f00::abcd".parse().unwrap();
        let (c2, _) = derive_fakeip_v6_prefix(&[own2], 0x2f).unwrap();
        assert_eq!(c2.prefix, 64);
        assert_ne!(mask_addr(c2.network, 64), mask_addr(own2.into(), 64), "必须避开本机 /64");
        assert_eq!(c2.display(), "240e:47c:d6c8:3000::/64");
        assert!(!c2.contains(own2.into()));
    }

    #[test]
    fn cidr_implements_fromstr_and_display() {
        // 队友要写 `s.parse::<IpCidr>()`；缺这个实现会逼每个调用点手写 map_err
        let c: IpCidr = "198.18.0.0/15".parse().unwrap();
        assert_eq!(c.prefix, 15);
        assert_eq!(c.to_string(), "198.18.0.0/15");
        assert_eq!("fd53::/48".parse::<IpCidr>().unwrap().display(), "fd53::/48");
        assert!("198.18.0.0/33".parse::<IpCidr>().is_err());
        assert!("nope".parse::<IpCidr>().is_err());
    }

    /// fakeip 分配器靠这两个方法做「第 n 个地址」寻址，语义必须钉死：
    /// v4 跳过网络地址、v6 用基址，且绝不越出段外。
    #[test]
    fn first_and_nth_usable_enumerate_the_segment() {
        let c = IpCidr::parse("198.18.0.0/15").unwrap();
        assert_eq!(c.first_usable().to_string(), "198.18.0.1", "v4 必须跳过网络地址");
        assert_eq!(c.nth_usable(0).unwrap().to_string(), "198.18.0.1");
        assert_eq!(c.nth_usable(1).unwrap().to_string(), "198.18.0.2");
        assert_eq!(c.nth_usable(254).unwrap().to_string(), "198.18.0.255");
        assert_eq!(c.nth_usable(255).unwrap().to_string(), "198.18.1.0");
        // 段内最后一个可分配地址（198.18.0.0/15 = 198.18.0.0 ~ 198.19.255.255，扣网络/广播）
        let last = c.usable_hosts() - 1;
        assert_eq!(c.nth_usable(last).unwrap().to_string(), "198.19.255.254");
        assert_eq!(c.nth_usable(c.usable_hosts()), None, "越界必须 None 而不是回绕");
        assert_eq!(c.nth_usable(u128::MAX), None);

        let c24 = IpCidr::parse("192.168.7.0/24").unwrap();
        assert_eq!(c24.first_usable().to_string(), "192.168.7.1");
        assert_eq!(c24.nth_usable(253).unwrap().to_string(), "192.168.7.254");
        assert_eq!(c24.nth_usable(254), None, "广播地址不可分配");

        // /31 点对点与 /32 单地址没有「网络地址」可跳
        assert_eq!(IpCidr::parse("10.0.0.0/31").unwrap().first_usable().to_string(), "10.0.0.0");
        assert_eq!(IpCidr::parse("10.0.0.5/32").unwrap().first_usable().to_string(), "10.0.0.5");

        let c6 = IpCidr::parse("fd53::/48").unwrap();
        assert_eq!(c6.first_usable().to_string(), "fd53::1", "v6 跳过段基址 fd53::");
        assert_eq!(c6.nth_usable(0).unwrap().to_string(), "fd53::1");
        assert_eq!(c6.nth_usable(7).unwrap().to_string(), "fd53::8");
        let last6 = c6.usable_hosts() - 1;
        assert_eq!(
            c6.nth_usable(last6).unwrap().to_string(),
            "fd53::ffff:ffff:ffff:ffff:ffff",
            "v6 段末尾仍可寻址（80 位主机位全 1）"
        );
        assert_eq!(c6.nth_usable(c6.usable_hosts()), None, "越出 /48 必须 None");
        // /126 之类的小段也必须能枚举，且不含基址
        let tiny = IpCidr::parse("fd53::/126").unwrap();
        assert_eq!(tiny.usable_hosts(), 3);
        assert_eq!(tiny.nth_usable(0).unwrap().to_string(), "fd53::1");
        assert_eq!(tiny.nth_usable(2).unwrap().to_string(), "fd53::3");
        assert_eq!(tiny.nth_usable(3), None);
    }
}

