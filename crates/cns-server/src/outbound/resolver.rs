use crate::config::FamilyPreference;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::task::JoinSet;
use tokio::time::timeout;

/// 单条缓存记录（**按族分开存**，见 `Resolver::lookup_grouped` 的注释）
#[derive(Clone, Debug)]
struct CacheEntry {
    addrs: Vec<IpAddr>,
    /// 该族应答里的最小 TTL（秒），用于把 `lookup_grouped` 的 ttl 一并带出来
    ttl: u64,
    expires: Instant,
    /// 解析失败也缓存一小段时间，避免上游挂了被疯狂重试打爆
    negative: bool,
}

/// 纯异步 DNS 解析器（自建报文，不依赖 getaddrinfo 的 blocking 线程池）。
///
/// 原版服务端用 `tokio::net::lookup_host`，它跑在 blocking pool 上：
/// 高频域名回源会把 512 个阻塞线程吃光，进而整个服务僵死。这里改为
/// 非阻塞 UDP 查询 + 结果缓存 + 多上游竞速。
///
/// v0.3.0 的关键改动：**A 与 AAAA 分别成组、分别缓存、分别竞速**。
/// 旧实现把两种应答 `extend` 进同一个 `Vec<IpAddr>` 再 `sort_by_key(v4 优先)`，
/// 于是「双栈择优」在数据源头就丢了信息 —— 拿到的是一个已经排好序的混合列表，
/// 无法表达「v6 首发、v4 错峰」，也无法回答「这个域名到底有没有 AAAA」。
/// 现在 `lookup_grouped` 给出 `(v4, v6, ttl)`，`resolve_for_dial` 按族偏好排序候选，
/// 排序策略只在拨号层出现一处（`order_candidates`）。
#[derive(Clone)]
pub struct Resolver {
    upstreams: Arc<Vec<SocketAddr>>,
    cache: Arc<Mutex<HashMap<String, CacheEntry>>>,
    cache_limit: usize,
    query_timeout: Duration,
    min_ttl: u64,
    max_ttl: u64,
    negative_ttl: u64,
    socket_pool: Arc<Mutex<Vec<UdpSocket>>>,
}

/// 解析结果缓存策略
#[derive(Clone, Copy, Debug)]
pub struct ResolverOptions {
    pub cache_limit: usize,
    pub query_timeout: Duration,
    pub min_ttl: u64,
    pub max_ttl: u64,
    pub negative_ttl: u64,
}

impl Default for ResolverOptions {
    fn default() -> Self {
        Self {
            cache_limit: 4096,
            query_timeout: Duration::from_secs(3),
            min_ttl: 30,
            max_ttl: 3600,
            negative_ttl: 5,
        }
    }
}

/// 缓存键分隔符：一个 host 的 A 与 AAAA 各占一条缓存条目。
///
/// 为什么不是一条记录里存两个列表：NODATA 是**逐族**的（`example.com` 有 A 无 AAAA
/// 太常见），合成一条就得引入「哪一族是负的」的复合状态，驱逐与续期都要特判；
/// 拆成 `host\u{1}A` / `host\u{1}AAAA` 两个键后，负缓存、TTL、上限淘汰全走同一条老路径。
const FAMILY_KEY_SEP: char = '\u{1}';

fn family_key(host: &str, want_v6: bool) -> String {
    format!("{host}{FAMILY_KEY_SEP}{}", if want_v6 { "AAAA" } else { "A" })
}

impl Resolver {
    pub fn new(upstreams: &[String], opts: ResolverOptions) -> Self {
        let mut parsed: Vec<SocketAddr> = Vec::new();
        for up in upstreams {
            // 已带端口（含 [v6]:port 形式）原样使用，否则补 :53
            let with_port = if up.contains(':') { up.clone() } else { format!("{up}:53") };
            match with_port.parse::<SocketAddr>() {
                Ok(addr) => parsed.push(addr),
                Err(e) => {
                    tracing::warn!("ignoring invalid dns_upstream {up}: {e}");
                }
            }
        }
        if parsed.is_empty() {
            // 兜底：公共 DNS，避免配置写错导致完全无法解析
            parsed.push("223.5.5.5:53".parse().unwrap());
            parsed.push("8.8.8.8:53".parse().unwrap());
        }
        Self {
            upstreams: Arc::new(parsed),
            cache: Arc::new(Mutex::new(HashMap::new())),
            cache_limit: opts.cache_limit.max(16),
            query_timeout: opts.query_timeout,
            min_ttl: opts.min_ttl,
            max_ttl: opts.max_ttl,
            negative_ttl: opts.negative_ttl,
            socket_pool: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn upstreams(&self) -> &[SocketAddr] {
        &self.upstreams
    }

    /// 命中返回 `(地址, 观测到的最小 TTL)`；TTL 原样存，不被缓存过期用的 clamp 污染
    /// （`lookup_grouped` 要把真实 TTL 交给调用方，客户端 fakeip 与 httpDNS 都靠它）。
    fn cache_get(&self, key: &str) -> Option<(Vec<IpAddr>, u64)> {
        let guard = self.cache.lock().ok()?;
        let entry = guard.get(key)?;
        if entry.expires > Instant::now() {
            if entry.negative {
                // 负缓存：以空列表表达「暂时别再查」
                return Some((Vec::new(), 0));
            }
            Some((entry.addrs.clone(), entry.ttl))
        } else {
            None
        }
    }

    fn cache_put(&self, key: &str, addrs: Vec<IpAddr>, ttl: u64, negative: bool) {
        if let Ok(mut guard) = self.cache.lock() {
            if guard.len() >= self.cache_limit {
                // 简单驱逐：先清过期项，仍超限则整体清空（避免实现完整 LRU 的复杂度）
                let now = Instant::now();
                guard.retain(|_, e| e.expires > now);
                if guard.len() >= self.cache_limit {
                    guard.clear();
                }
            }
            let hold =
                if negative { self.negative_ttl } else { ttl.clamp(self.min_ttl, self.max_ttl) };
            guard.insert(
                key.to_string(),
                CacheEntry {
                    addrs,
                    ttl: if negative { 0 } else { ttl },
                    expires: Instant::now() + Duration::from_secs(hold),
                    negative,
                },
            );
        }
    }

    /// 解析主机会名为 IP 列表（带缓存）。`host` 不含端口。
    ///
    /// 兼容层：内部走 [Resolver::lookup_grouped]，展平顺序保持旧的「v4 在前」，
    /// 这样 httpDNS（`dn=`）里 `addrs.iter().find(|ip| ip.is_ipv6()==want)` 的
    /// 语义与 v0.2.x 完全一致，不改协议行为。
    pub async fn lookup(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        let (v4, v6, _) = self.lookup_grouped(host).await?;
        let mut out: Vec<IpAddr> = Vec::with_capacity(v4.len() + v6.len());
        out.extend(v4.into_iter().map(IpAddr::V4));
        out.extend(v6.into_iter().map(IpAddr::V6));
        Ok(out)
    }

    /// 按族分组解析（双栈择优的唯一数据入口）。
    ///
    /// 返回 `(v4, v6, ttl)`；两族**都为空**才报错。单族缺失不是错误 ——
    /// 域名只有 A 记录是常态，把它当失败会导致「有 v4 却整个域名解析失败」。
    /// `ttl` 取两族里**最小**的那个：调用方要的是「这份结果最多还能信多久」，
    /// 取大值会让过期那一族的候选继续被复用。
    ///
    /// 两族并发查询（各走自己的多上游竞速），所以「v6 侧上游被黑洞」不会拖慢 v4：
    /// 最坏耗时 = 单族 query_timeout，而不是旧实现的两倍。
    pub async fn lookup_grouped(
        &self,
        host: &str,
    ) -> io::Result<(Vec<Ipv4Addr>, Vec<Ipv6Addr>, u32)> {
        let key = host.to_ascii_lowercase();

        // 字面 IP 直接返回（族由地址本身决定，不需要任何查询）
        if let Ok(ip) = key.parse::<IpAddr>() {
            return Ok(group_two(vec![ip], 0));
        }

        let mut v4: Option<(Vec<IpAddr>, u64)> = self.cache_get(&family_key(&key, false));
        let mut v6: Option<(Vec<IpAddr>, u64)> = self.cache_get(&family_key(&key, true));

        // 缺哪族补哪族：两族并发，但只对未命中的族发查询
        if v4.is_none() || v6.is_none() {
            let need_v4 = v4.is_none();
            let need_v6 = v6.is_none();
            let host_str = key.clone();
            let this = self.clone();
            let (r4, r6) = tokio::join!(
                async {
                    if need_v4 {
                        this.query_family(&host_str, false).await
                    } else {
                        Ok((Vec::new(), 0u64))
                    }
                },
                async {
                    if need_v6 {
                        this.query_family(&host_str, true).await
                    } else {
                        Ok((Vec::new(), 0u64))
                    }
                },
            );
            if need_v4 {
                // 注意：不能对 Result 调 clone（anyhow::Error / io::Error 都不实现 Clone），
                // 失败时直接落到 unwrap_or_else 给的默认元组。
                let (addrs, ttl) = match r4 {
                    Ok(pair) => pair,
                    Err(_) => (Vec::new(), 0u64),
                };
                // 空结果/失败按负缓存：NXDOMAIN、NODATA、上游全挂 归一类，
                // 代价是「split-horizon 时换个上游可能就有」—— 用 negative_ttl(5s) 兜住。
                self.cache_put(&family_key(&key, false), addrs.clone(), ttl, addrs.is_empty());
                v4 = Some((addrs, ttl));
            }
            if need_v6 {
                let (addrs, ttl) = match r6 {
                    Ok(pair) => pair,
                    Err(_) => (Vec::new(), 0u64),
                };
                self.cache_put(&family_key(&key, true), addrs.clone(), ttl, addrs.is_empty());
                v6 = Some((addrs, ttl));
            }
        }

        let (flat4, t4) = v4.unwrap_or_default();
        let (flat6, t6) = v6.unwrap_or_default();
        if flat4.is_empty() && flat6.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("no A/AAAA record for {host}"),
            ));
        }
        // 单族缺失时别把它的 0 当成「ttl=0」，否则调用方会认为结果立刻过期
        let ttl = match (flat4.is_empty(), flat6.is_empty()) {
            (true, false) => t6,
            (false, true) => t4,
            _ => t4.min(t6),
        };
        let (g4, g6, _) = group_two([flat4.clone(), flat6.clone()].concat(), ttl);
        debug_assert!(g4.len() >= flat4.len(), "分组只会把 mapped 归并进 v4，不会丢地址");
        Ok((g4, g6, ttl.min(u32::MAX as u64) as u32))
    }

    /// 按族偏好产出**有序**拨号候选（不 dial，只排序）。
    ///
    /// * `auto` -> v6/v4 交错且 **v6 在前**（RFC 8305 的 attempt-target list）
    /// * `ipv4` / `ipv6` -> 只留该族；若该族为空返回空列表，由拨号层明确报错
    ///   （绝不悄悄改用另一族 —— 运维写死族偏好就是因为那一族有问题）
    ///
    /// `spec` 允许 `host`、`host:port`、`[v6]:port`、裸字面 IPv6；无端口按 80
    /// （与 `cns_core::protocol::normalize_target_host` 的缺省口径一致）。
    pub async fn resolve_for_dial(
        &self,
        spec: &str,
        prefer: FamilyPreference,
    ) -> io::Result<Vec<SocketAddr>> {
        let (host, port) = split_host_port(spec).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("bad target spec: {spec}"))
        })?;

        // 字面 IP：不查询、不排序，族偏好**不覆盖**字面目标。
        // 客户端既然把 IP 写死在目标串里，那就是目标本身，没有择路余地；
        // 在这里改族会把 1.1.1.1:443 拨到别的地址上，属于语义错误。
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }

        let (mut v4, mut v6, _) = self.lookup_grouped(host.as_str()).await?;
        // prefer 明确指定族时，另一族整个丢掉：这是运维的下沉开关，不是建议
        match prefer.first_family() {
            Some(true) => v4.clear(),
            Some(false) => v6.clear(),
            None => {}
        }
        // auto -> v6 首发；显式族 -> 该族首发（列表里已只剩一族，顺序只影响交错）
        let first_v6 = prefer.first_family().unwrap_or(true);
        Ok(order_candidates(
            v4.into_iter().map(IpAddr::V4).collect(),
            v6.into_iter().map(IpAddr::V6).collect(),
            port,
            first_v6,
        ))
    }

    /// 单族多上游**真竞速**：并发发出，第一个带答案的应答胜出，其余 abort。
    ///
    /// 两处旧语义被去掉：
    /// 1. 旧代码 `for task in tasks { task.await }` 是**顺序等待**，排在第一位的
    ///    慢上游会把总延迟拖到 query_timeout，即使第二个上游 5ms 就答完了；
    /// 2. 旧代码「A/AAAA 任一成功即可」把两族结果混进同一个 Vec，见类型注释。
    async fn query_family(&self, host: &str, want_v6: bool) -> io::Result<(Vec<IpAddr>, u64)> {
        let query = build_dns_query(host, want_v6)?;
        let mut set = JoinSet::new();
        for up in self.upstreams.iter() {
            let pkt = query.clone();
            let up = *up;
            let to = self.query_timeout;
            let pool = Arc::clone(&self.socket_pool);
            set.spawn(async move {
                let resp = exchange_once(pool, up, &pkt, to).await.ok()?;
                parse_dns_response(&resp, want_v6)
            });
        }

        let mut last_err = None;
        let mut got: (Vec<IpAddr>, u64) = (Vec::new(), 0);
        while let Some(join) = set.join_next().await {
            match join {
                Ok(Some(pair)) if !pair.0.is_empty() => {
                    // 第一个有答案的胜出：落败任务连同其 socket 一起 abort/释放
                    got = pair;
                    break;
                }
                Ok(_) => {
                    // 该上游超时/无对应类型记录：继续等其它上游，别当成权威 NODATA
                    // （split-horizon 下换个上游可能有答案，5s 负缓存兜住放大风险）
                }
                Err(e) => {
                    last_err = Some(io::Error::other(format!("resolver task: {e}")));
                }
            }
        }
        // 竞速完成：落败方必须 abort，否则其 socket 与 task 会一直挂到超时
        set.abort_all();

        if got.0.is_empty() {
            return Err(last_err.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    format!("no {} answer for {host}", if want_v6 { "AAAA" } else { "A" }),
                )
            }));
        }
        Ok(got)
    }
}

/// 把扁平 IP 列表按族拆开（保持原始顺序，不做「v4 优先」硬排序）。
fn group_two(addrs: Vec<IpAddr>, ttl: u64) -> (Vec<Ipv4Addr>, Vec<Ipv6Addr>, u32) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for ip in addrs {
        match ip {
            IpAddr::V4(x) => v4.push(x),
            IpAddr::V6(x) => {
                // IPv4-mapped 归到 v4 组：拨号时对 v6 socket 发 ::ffff:x 是自寻死路，
                // 内核会按 v4 目的处理，分组里混进它只会让「v6 候选」这个概念失真。
                if let Some(inner) = to_v4_mapped(x) {
                    v4.push(inner);
                } else {
                    v6.push(x);
                }
            }
        }
    }
    (v4, v6, ttl.min(u32::MAX as u64) as u32)
}

/// `::ffff:a.b.c.d` -> `a.b.c.d`
fn to_v4_mapped(x: Ipv6Addr) -> Option<Ipv4Addr> {
    let o = x.octets();
    if o[..10] == [0u8; 10] && o[10..12] == [0xff, 0xff] {
        Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]))
    } else {
        None
    }
}

/// RFC 8305 风格的候选排序：交错两族、首发族占位在前。
///
/// 独立成函数（而不是埋在 dial 里）的原因：这是「择优」的全部策略，必须能被
/// 单测直接断言，而不必真去构造一个双栈可达的域名。
pub(crate) fn order_candidates(
    v4: Vec<IpAddr>,
    v6: Vec<IpAddr>,
    port: u16,
    first_v6: bool,
) -> Vec<SocketAddr> {
    let (head, tail) = if first_v6 { (v6, v4) } else { (v4, v6) };
    let head: Vec<IpAddr> = head.into_iter().filter(|ip| ip.is_ipv6() == first_v6).collect();
    let tail: Vec<IpAddr> = tail.into_iter().filter(|ip| ip.is_ipv6() != first_v6).collect();
    let mut out = Vec::with_capacity(head.len() + tail.len());
    // 交错而非「先穷一族」：v6 首发但第二个候选就让 v4 排队，
    // 这样 dial 层错峰并发时两族的候选都已就位（RFC 8305 Attempt Target List）。
    let n = head.len().max(tail.len());
    for i in 0..n {
        if let Some(ip) = head.get(i) {
            out.push(SocketAddr::new(*ip, port));
        }
        if let Some(ip) = tail.get(i) {
            out.push(SocketAddr::new(*ip, port));
        }
    }
    out
}

/// 拆 `host:port` / `[v6]:port` / 裸 IPv6 / 仅 host。返回 `(host_without_brackets, port)`
pub(crate) fn split_host_port(spec: &str) -> Option<(String, u16)> {
    let s = spec.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        if host.is_empty() {
            return None;
        }
        let port = match tail {
            "" => 80,
            other => other.strip_prefix(':')?.parse::<u16>().ok()?,
        };
        return Some((host.to_string(), port));
    }
    // 无方括号：IPv6 字面量（多冒号）或 host:port
    if let Some((h, p)) = s.rsplit_once(':') {
        if !h.contains(':') {
            if let Ok(port) = p.parse::<u16>() {
                return Some((h.to_string(), port));
            }
            return None; // `host:非数字` 一律视为非法目标串
        }
    }
    if s.matches(':').count() >= 2 {
        // 裸 IPv6（无端口）
        return Some((s.to_string(), 80));
    }
    Some((s.to_string(), 80))
}

async fn exchange_once(
    pool: Arc<Mutex<Vec<UdpSocket>>>,
    up: SocketAddr,
    query: &[u8],
    to: Duration,
) -> io::Result<Vec<u8>> {
    let socket = take_socket(&pool, up).await?;
    let mut buf = vec![0u8; 4096];

    let result = async {
        socket.send_to(query, up).await?;
        let (n, peer) = timeout(to, socket.recv_from(&mut buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream DNS timeout"))??;
        // 只接受来自该上游的应答，防串包/伪造
        if peer != up {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("dns response from unexpected peer {peer}"),
            ));
        }
        buf.truncate(n);
        Ok::<(), io::Error>(())
    }
    .await;

    if result.is_ok() {
        // 成功才归还池；失败让 socket 随 drop 释放
        if let Ok(mut guard) = pool.lock() {
            if guard.len() < 16 {
                guard.push(socket);
            }
        }
    }
    result.map(|_| buf)
}

/// 取得一个与上游同族的 UDP socket（优先复用池中空闲的）
async fn take_socket(pool: &Arc<Mutex<Vec<UdpSocket>>>, up: SocketAddr) -> io::Result<UdpSocket> {
    if let Ok(mut guard) = pool.lock() {
        if let Some(idx) = guard
            .iter()
            .position(|s| s.local_addr().map(|a| a.is_ipv4() == up.is_ipv4()).unwrap_or(false))
        {
            return Ok(guard.remove(idx));
        }
    }
    let bind: SocketAddr =
        if up.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
    cns_core::transport::create_tuned_udp_socket(bind)
}

fn build_dns_query(host: &str, ipv6: bool) -> io::Result<Vec<u8>> {
    let mut pkt = Vec::with_capacity(32 + host.len());
    let id = rand_id();
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&[0x01, 0x00]); // flags: RD
    pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00]);

    for label in host.split('.') {
        if label.is_empty() {
            continue;
        }
        if label.len() > 63 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "DNS label too long"));
        }
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0);
    let qtype = if ipv6 { 28u16 } else { 1u16 };
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01]); // IN
    Ok(pkt)
}

fn rand_id() -> u16 {
    // 无 rand crate 依赖：用时钟 + 进程 id + 原子计数混出足够随机的事务 id
    static COUNTER: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);
    let c = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u16)
        .unwrap_or(0);
    c ^ nanos ^ (std::process::id() as u16)
}

/// 解析应答，返回 (地址列表, 最小 TTL)。`want_v6` 决定取 AAAA 还是 A。
pub fn parse_dns_response(resp: &[u8], want_v6: bool) -> Option<(Vec<IpAddr>, u64)> {
    if resp.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    let rcode = resp[3] & 0x0f;
    if rcode != 0 || ancount == 0 {
        return None;
    }

    let want_type = if want_v6 { 28u16 } else { 1u16 };
    let mut pos = 12usize;

    // 跳过 Question 段
    for _ in 0..qdcount {
        pos = skip_name(resp, pos)?;
        pos += 4; // QTYPE + QCLASS
        if pos > resp.len() {
            return None;
        }
    }

    let mut addrs = Vec::new();
    let mut min_ttl = u64::MAX;
    for _ in 0..ancount {
        pos = skip_name(resp, pos)?;
        if pos + 10 > resp.len() {
            break;
        }
        let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        let ttl = u32::from_be_bytes([resp[pos + 4], resp[pos + 5], resp[pos + 6], resp[pos + 7]]);
        let data_start = pos + 10;
        let data_end = data_start.checked_add(rdlen)?;
        if data_end > resp.len() {
            break;
        }
        let data = &resp[data_start..data_end];

        if rtype == want_type {
            let ip = if want_v6 && rdlen == 16 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(data);
                Some(IpAddr::V6(Ipv6Addr::from(octets)))
            } else if !want_v6 && rdlen == 4 {
                Some(IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])))
            } else {
                None
            };
            if let Some(ip) = ip {
                min_ttl = min_ttl.min(ttl as u64);
                addrs.push(ip);
            }
        }
        pos = data_end;
    }

    if addrs.is_empty() {
        None
    } else {
        Some((addrs, if min_ttl == u64::MAX { 0 } else { min_ttl }))
    }
}

/// 跳过 DNS 名称，处理压缩指针（0b11 前缀）
fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= msg.len() {
            return None;
        }
        let len = msg[pos] as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xc0 == 0xc0 {
            // 压缩指针：2 字节，后续名称在指针处结束
            if pos + 2 > msg.len() {
                return None;
            }
            return Some(pos + 2);
        }
        pos += 1 + len;
    }
}

/// 测试专用 fixture：假 DNS 上游。
///
/// 放在 crate 内（`pub(crate)` + `#[cfg(test)]`）而不是埋在 `tests` 模块里，
/// 是因为 `outbound::direct` 的单测要用**同一份**假上游验证「显式族偏好下零候选」
/// —— 两处各写一份就会各测各的，真解析器的分组语义反而没人守。
#[cfg(test)]
pub(crate) mod test_fixtures {
    use super::*;

    pub(crate) async fn fake_dns(
        records: Vec<(u16, Vec<u8>, u32)>,
        dropforever: bool,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        fake_dns_answering(records, dropforever).await
    }

    /// 假上游，可指定「只回答哪些 qtype」。
    ///
    /// `only_answer` 为空表示两种都答。用来构造「上游 A 只有 A、上游 B 只有 AAAA」
    /// 这类分裂场景 —— 旧实现的「任一成功即可 + break」在这种上游组合下会**丢族**。
    pub(crate) async fn fake_dns_answering(
        records: Vec<(u16, Vec<u8>, u32)>,
        dropforever: bool,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        fake_dns_inner(records, dropforever, Vec::new()).await
    }

    pub(crate) async fn fake_dns_qtypes(
        records: Vec<(u16, Vec<u8>, u32)>,
        only_answer: Vec<u16>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        fake_dns_inner(records, false, only_answer).await
    }

    pub(crate) async fn fake_dns_inner(
        records: Vec<(u16, Vec<u8>, u32)>,
        dropforever: bool,
        only_answer: Vec<u16>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = sock.local_addr().unwrap();
        let handle = tokio::spawn({
            let sock = Arc::clone(&sock);
            async move {
                let mut buf = [0u8; 512];
                loop {
                    let Ok((n, peer)) = sock.recv_from(&mut buf).await else { return };
                    if dropforever {
                        continue; // 黑洞：收了不答（模拟被中间设备丢弃的 AAAA）
                    }
                    let query = buf[..n].to_vec();
                    let Some(q) = cns_core::dns::parse_question(&query) else { continue };
                    if !only_answer.is_empty() && !only_answer.contains(&q.qtype) {
                        continue; // 该族在本上游无解：静默，让另一个上游补全
                    }
                    let mut resp = Vec::new();
                    resp.extend_from_slice(&query[0..2]); // 回显 id
                    resp.extend_from_slice(&[0x81, 0x80]); // QR+AA+RD
                    resp.extend_from_slice(&[0x00, 0x01]); // QD=1
                    resp.extend_from_slice(&(records.len() as u16).to_be_bytes()); // ANCOUNT
                    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NSCOUNT + ARCOUNT
                                                                       // 问题段原样回显（q.end 是问题段结束偏移）
                    resp.extend_from_slice(&query[12..q.end]);
                    for (rtype, rdata, ttl) in &records {
                        resp.extend_from_slice(&[0xc0, 0x0c]);
                        resp.extend_from_slice(&rtype.to_be_bytes());
                        resp.extend_from_slice(&[0x00, 0x01]); // IN
                        resp.extend_from_slice(&ttl.to_be_bytes());
                        resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
                        resp.extend_from_slice(rdata);
                    }
                    let _ = sock.send_to(&resp, peer).await;
                }
            }
        });
        (addr, handle)
    }

    pub(crate) fn v4_bytes(s: &str) -> Vec<u8> {
        s.parse::<Ipv4Addr>().unwrap().octets().to_vec()
    }
    pub(crate) fn v6_bytes(s: &str) -> Vec<u8> {
        s.parse::<Ipv6Addr>().unwrap().octets().to_vec()
    }

    /// 只回答 A 的上游（AAAA 静默不回）—— 构造「这个域名只有 v4」的确定性场景
    pub(crate) async fn v4_only_upstream(ip: &str) -> SocketAddr {
        let (addr, _h) = fake_dns_qtypes(vec![(1u16, v4_bytes(ip), 60)], vec![1]).await;
        // handle 不回收无妨：tokio::test 结束时整个 runtime 一起消失
        addr
    }
}

#[cfg(test)]
mod tests {
    use super::test_fixtures::*;
    use super::*;

    fn sample_answer() -> Vec<u8> {
        // id=0x1234 flags=8180 QD=1 AN=1
        // qname: 7example 3com 0, qtype A
        // answer: ptr 0x0c, type A, class IN, ttl 60, rdlen 4, 93.184.216.34
        vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // header
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, // qname
            0x00, 0x01, 0x00, 0x01, // qtype A qclass IN
            0xc0, 0x0c, // name ptr
            0x00, 0x01, // type A
            0x00, 0x01, // class IN
            0x00, 0x00, 0x00, 0x3c, // ttl 60
            0x00, 0x04, // rdlen
            93, 184, 216, 34,
        ]
    }

    #[test]
    fn parses_a_record_with_compressed_name() {
        let msg = sample_answer();
        let (addrs, ttl) = parse_dns_response(&msg, false).unwrap();
        assert_eq!(addrs, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
        assert_eq!(ttl, 60);
    }

    #[test]
    fn ignores_wrong_record_type() {
        let msg = sample_answer();
        assert!(parse_dns_response(&msg, true).is_none()); // 只要 AAAA，应答里只有 A
    }

    #[test]
    fn rejects_truncated_and_error_responses() {
        assert!(parse_dns_response(&[0x12, 0x34], false).is_none());
        let mut msg = sample_answer();
        msg[3] |= 3; // rcode=3 NXDOMAIN
        assert!(parse_dns_response(&msg, false).is_none());
        let mut msg2 = sample_answer();
        msg2.truncate(13); // 截断
        assert!(parse_dns_response(&msg2, false).is_none());
    }

    #[test]
    fn parses_aaaa() {
        let mut msg: Vec<u8> = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 3, b'f', b'o',
            b'o', 0, 0x00, 0x1c, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01,
        ];
        msg.extend_from_slice(&[0x00, 0x00, 0x0e, 0x10]); // ttl 3600
        msg.extend_from_slice(&[0x00, 0x10]); // rdlen 16
        let mut ip = [0u8; 16];
        ip[0] = 0x20;
        ip[1] = 0x01;
        ip[15] = 0x07;
        msg.extend_from_slice(&ip);
        let (addrs, ttl) = parse_dns_response(&msg, true).unwrap();
        assert_eq!(addrs.len(), 1);
        assert!(addrs[0].is_ipv6());
        assert_eq!(ttl, 3600);
    }

    #[test]
    fn build_query_shape() {
        let q = build_dns_query("example.com", false).unwrap();
        assert_eq!(&q[4..6], &[0x00, 0x01]);
        assert_eq!(q[12], 7);
        assert_eq!(q[q.len() - 4..], [0x00, 0x01, 0x00, 0x01]);
        assert!(build_dns_query(&"a".repeat(64), false).is_err());
    }

    #[tokio::test]
    async fn literal_ip_skips_network() {
        let r = Resolver::new(&["127.0.0.1:53".to_string()], ResolverOptions::default());
        let got = r.lookup("1.1.1.1").await.unwrap();
        assert_eq!(got, vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
        let got6 = r.lookup("2001:4860:4860::8888").await.unwrap();
        assert!(got6[0].is_ipv6());
        // 兼容层展平顺序仍是 v4 在前
        assert_eq!(got6, vec![IpAddr::V6("2001:4860:4860::8888".parse().unwrap())]);
    }

    #[tokio::test]
    async fn negative_cache_short_circuits() {
        // 上游不可达 → 报错并被负缓存，第二次立即失败而不再发网络包
        let r = Resolver::new(
            &["127.0.0.1:1".to_string()],
            ResolverOptions { query_timeout: Duration::from_millis(120), ..Default::default() },
        );
        let t0 = Instant::now();
        assert!(r.lookup("definitely-not-resolvable.invalid").await.is_err());
        let first = t0.elapsed();
        let t1 = Instant::now();
        assert!(r.lookup("definitely-not-resolvable.invalid").await.is_err());
        let second = t1.elapsed();
        assert!(second < first, "cached negative should be faster: {first:?} vs {second:?}");
    }

    #[test]
    fn skip_name_handles_labels_and_pointers() {
        let msg = vec![3, b'f', b'o', b'o', 0, 0xc0, 0x04];
        assert_eq!(skip_name(&msg, 0), Some(5));
        assert_eq!(skip_name(&msg, 5), Some(7));
        assert_eq!(skip_name(&msg, 100), None);
    }

    #[test]
    fn invalid_upstream_strings_are_dropped_not_fatal() {
        let r = Resolver::new(
            &["not an address".to_string(), "1.0.0.1:53".to_string()],
            ResolverOptions::default(),
        );
        assert_eq!(r.upstreams().len(), 1);
        let r2 = Resolver::new(&["".to_string()], ResolverOptions::default());
        assert_eq!(r2.upstreams().len(), 2, "should fall back to public DNS");
    }

    // -----------------------------------------------------------------
    // v0.3.0：分组 / 排序 / 按族竞速
    // -----------------------------------------------------------------

    /// 造一个假 DNS 上游：读查询，按 `records` 手搓应答。
    ///
    /// 故意不用 `cns_core::dns::build_response`：它会拒绝「记录类型与 qtype 不符」，
    /// 而这里要测的正是**真实世界里会发生的脏应答**（A 查询的应答里同时带 A 与
    /// AAAA，例如 CNAME 链/额外段）。分组实现必须只取本族的那条。
    #[tokio::test]
    async fn lookup_grouped_separates_families_from_mixed_answer() {
        // A 查询与 AAAA 查询都回同一份「A + AAAA」混合应答
        let mixed = vec![
            (1u16, v4_bytes("93.184.216.34"), 70u32),
            (28u16, v6_bytes("2001:4860:4860::8888"), 40u32),
        ];
        let (up, _h) = fake_dns(mixed, false).await;
        let r = Resolver::new(
            &[up.to_string()],
            ResolverOptions { query_timeout: Duration::from_millis(500), ..Default::default() },
        );

        let (v4, v6, ttl) = r.lookup_grouped("example.com").await.unwrap();
        assert_eq!(v4, vec![Ipv4Addr::new(93, 184, 216, 34)], "v4 组只能有 A");
        assert_eq!(v6, vec!["2001:4860:4860::8888".parse::<Ipv6Addr>().unwrap()]);
        // ttl 取两族最小（旧实现把 ttl 覆盖成「最后一条应答的 ttl」，这里按契约取最小）
        assert_eq!(ttl, 40);

        // 兼容层展平：v4 在前（httpDNS 的 find/or-first 语义不变）
        let flat = r.lookup("example.com").await.unwrap();
        assert!(flat[0].is_ipv4() && flat[1].is_ipv6(), "{flat:?}");
    }

    /// 只有 A 没有 AAAA（真实常态）：单族缺失不算失败，v6 组为空
    #[tokio::test]
    async fn lookup_grouped_tolerates_missing_family() {
        let (up, _h) = fake_dns(vec![(1u16, v4_bytes("192.0.2.7"), 60)], false).await;
        let r = Resolver::new(
            &[up.to_string()],
            ResolverOptions { query_timeout: Duration::from_millis(400), ..Default::default() },
        );
        let (v4, v6, _) = r.lookup_grouped("v4only.test").await.unwrap();
        assert_eq!(v4.len(), 1);
        assert!(v6.is_empty(), "只有 A 记录时 v6 必须为空而不是报错");
        // IPv4-mapped 落到 v4 组（不该冒充 v6 候选）
        let (v4b, v6b, _) =
            group_two(vec![IpAddr::V6("::ffff:203.0.113.9".parse::<Ipv6Addr>().unwrap())], 30);
        assert_eq!(v4b, vec![Ipv4Addr::new(203, 0, 113, 9)]);
        assert!(v6b.is_empty());
    }

    /// 一族的应答被黑洞时，另一族仍要拿全（旧「任一成功即可」+ 顺序 await 会短路/拖慢）
    #[tokio::test]
    async fn lookup_grouped_survives_blackholed_family() {
        let (dead, _hd) = fake_dns(vec![], true).await; // 收了不答：v6 黑洞
        let (good, _hg) = fake_dns(vec![(1u16, v4_bytes("198.51.100.4"), 55)], false).await;
        // 上游顺序刻意把黑洞放第一位
        let r = Resolver::new(
            &[dead.to_string(), good.to_string()],
            ResolverOptions { query_timeout: Duration::from_millis(300), ..Default::default() },
        );
        let t0 = Instant::now();
        let (v4, v6, _) = r.lookup_grouped("halfdead.test").await.unwrap();
        assert_eq!(v4, vec![Ipv4Addr::new(198, 51, 100, 4)], "v4 必须仍拿得到");
        assert!(v6.is_empty());
        // 两族并发 + 竞速 break：总耗时应接近一个 query_timeout，而不是两倍
        assert!(
            t0.elapsed() < Duration::from_millis(900),
            "blackholed family took {:?}",
            t0.elapsed()
        );
    }

    #[tokio::test]
    async fn resolve_for_dial_orders_v6_first_under_auto() {
        let mixed = vec![
            (1u16, v4_bytes("93.184.216.34"), 60),
            (28u16, v6_bytes("2001:4860:4860::8888"), 60),
        ];
        let (up, _h) = fake_dns(mixed, false).await;
        let r = Resolver::new(
            &[up.to_string()],
            ResolverOptions { query_timeout: Duration::from_millis(400), ..Default::default() },
        );
        let auto = r.resolve_for_dial("example.com:443", FamilyPreference::Auto).await.unwrap();
        assert_eq!(auto.len(), 2);
        assert!(auto[0].is_ipv6(), "auto 必须 v6 首发: {auto:?}");
        assert!(auto[1].is_ipv4());
        assert_eq!(auto[0].port(), 443);

        let only4 = r.resolve_for_dial("example.com:443", FamilyPreference::Ipv4).await.unwrap();
        assert!(only4.iter().all(|a| a.is_ipv4()), "{only4:?}");
        let only6 = r.resolve_for_dial("example.com:443", FamilyPreference::Ipv6).await.unwrap();
        assert!(only6.iter().all(|a| a.is_ipv6()), "{only6:?}");
    }

    #[tokio::test]
    async fn resolve_for_dial_uses_literal_target_verbatim() {
        let r = Resolver::new(&["127.0.0.1:1".to_string()], ResolverOptions::default());
        // 字面 IP 不查询（无网络），且 prefer 不覆盖字面目标
        let got = r.resolve_for_dial("203.0.113.7:8080", FamilyPreference::Ipv6).await.unwrap();
        assert_eq!(got, vec!["203.0.113.7:8080".parse::<SocketAddr>().unwrap()]);
        let bracketed =
            r.resolve_for_dial("[2001:db8::1]:8443", FamilyPreference::Ipv4).await.unwrap();
        assert_eq!(bracketed, vec!["[2001:db8::1]:8443".parse::<SocketAddr>().unwrap()]);
        assert!(r.resolve_for_dial("", FamilyPreference::Auto).await.is_err());
        assert!(r.resolve_for_dial("host:notaport", FamilyPreference::Auto).await.is_err());
    }

    #[test]
    fn order_candidates_interleaves_and_respects_first_family() {
        let v4: Vec<IpAddr> =
            ["1.1.1.1", "1.1.1.2", "1.1.1.3"].iter().map(|s| s.parse().unwrap()).collect();
        let v6: Vec<IpAddr> =
            ["2001:db8::1", "2001:db8::2"].iter().map(|s| s.parse().unwrap()).collect();

        let both = order_candidates(v4.clone(), v6.clone(), 443, true);
        assert_eq!(
            both.iter().map(|a| a.ip().to_string()).collect::<Vec<_>>(),
            vec!["2001:db8::1", "1.1.1.1", "2001:db8::2", "1.1.1.2", "1.1.1.3"],
            "交错且 v6 首发"
        );
        let v4first = order_candidates(v4.clone(), v6.clone(), 443, false);
        assert!(v4first[0].is_ipv4());
        assert_eq!(v4first.len(), 5);
        // 只有一族时也必须能排序
        // 只有一族时，首发族为空也要把另一族排出来（否则「有 v4 却无候选」）
        let lonely = order_candidates(v4.clone(), Vec::new(), 80, true);
        assert_eq!(
            lonely,
            vec![
                "1.1.1.1:80".parse::<SocketAddr>().unwrap(),
                "1.1.1.2:80".parse::<SocketAddr>().unwrap(),
                "1.1.1.3:80".parse::<SocketAddr>().unwrap()
            ]
        );
        assert!(order_candidates(Vec::new(), Vec::new(), 80, true).is_empty());
        // 放进错误槽位的地址必须被过滤掉，不能冒充另一族候选（v6 槽里塞 v4 = 脏数据）
        let dirty =
            order_candidates(Vec::new(), vec!["1.1.1.1".parse::<IpAddr>().unwrap()], 80, true);
        assert!(dirty.is_empty(), "v6 槽里的 v4 地址不该成为 v6 候选: {dirty:?}");
        // 首发族为空时另一族仍要全部排出（否则「有 v4 却零候选」= 自己把自己饿死）
        let fallback =
            order_candidates(vec!["1.1.1.1".parse::<IpAddr>().unwrap()], Vec::new(), 80, true);
        assert_eq!(fallback, vec!["1.1.1.1:80".parse::<SocketAddr>().unwrap()]);
    }

    #[test]
    fn split_host_port_accepts_all_spellings() {
        assert_eq!(split_host_port("example.com:443"), Some(("example.com".into(), 443)));
        assert_eq!(split_host_port("example.com"), Some(("example.com".into(), 80)));
        assert_eq!(split_host_port("[2001:db8::1]:8443"), Some(("2001:db8::1".into(), 8443)));
        assert_eq!(split_host_port("2001:db8::1"), Some(("2001:db8::1".into(), 80)));
        assert_eq!(split_host_port("1.2.3.4:53"), Some(("1.2.3.4".into(), 53)));
        assert_eq!(split_host_port("[]:443"), None);
        assert_eq!(split_host_port("[2001:db8::1"), None);
        assert_eq!(split_host_port("host:99999"), None);
        assert_eq!(split_host_port("   "), None);
    }

    /// 缓存必须按族分离：只有 v4 命中时不该再查 v6 之外的东西，
    /// 也不该因为「有一条缓存」就把另一族短路掉
    /// 「A/AAAA 任一成功即可」的短路语义必须**不存在**：
    /// 上游1 只答 A、上游2 只答 AAAA，分组结果必须两族都齐全。
    #[tokio::test]
    async fn per_family_queries_complete_across_split_upstreams() {
        let (up_a, _ha) =
            fake_dns_qtypes(vec![(1u16, v4_bytes("93.184.216.34"), 60)], vec![1]).await;
        let (up_b, _hb) = fake_dns_qtypes(
            vec![(28u16, v6_bytes("2606:2800:220:1:241:200c:4152:803"), 60)],
            vec![28],
        )
        .await;
        let r = Resolver::new(
            &[up_a.to_string(), up_b.to_string()],
            ResolverOptions { query_timeout: Duration::from_millis(400), ..Default::default() },
        );
        let (v4, v6, _) = r.lookup_grouped("split.test").await.unwrap();
        assert_eq!(v4.len(), 1, "A 必须从上游1 拿到: {v4:?}");
        assert_eq!(v6.len(), 1, "AAAA 必须从上游2 拿到（旧短路语义会在这里丢 v6）: {v6:?}");

        // 择优候选：两族都在，且 v6 首发
        let cands = r.resolve_for_dial("split.test:443", FamilyPreference::Auto).await.unwrap();
        assert_eq!(cands.len(), 2, "{cands:?}");
        assert!(cands[0].is_ipv6(), "auto 必须 v6 首发: {cands:?}");
        assert!(cands[1].is_ipv4());
    }

    /// 竞速层计时：第一个上游是黑洞（收了不回），第二个秒答。
    /// 必须拿到答案且**几乎不等**第一个上游的 query_timeout。
    #[tokio::test]
    async fn good_upstream_answer_is_not_blocked_by_blackholed_upstream() {
        let (dead, _hd) = fake_dns(vec![], true).await;
        let (good, _hg) = fake_dns(vec![(1u16, v4_bytes("198.51.100.9"), 60)], false).await;
        let r = Resolver::new(
            &[dead.to_string(), good.to_string()],
            ResolverOptions { query_timeout: Duration::from_secs(5), ..Default::default() },
        );
        let t0 = Instant::now();
        let addrs = r.query_family("timing.test", false).await.unwrap();
        let took = t0.elapsed();
        assert_eq!(addrs.0.len(), 1, "{addrs:?}");
        assert!(took < Duration::from_millis(300), "不该等黑洞上游的 5s 超时: {took:?}");
    }

    /// 全部上游都是黑洞时，必须**有界**失败（而不是挂到 timeout 之外）
    #[tokio::test]
    async fn all_blackholed_upstreams_fail_bounded() {
        let (dead, _h) = fake_dns(vec![], true).await;
        let r = Resolver::new(
            &[dead.to_string(), dead.to_string()],
            ResolverOptions { query_timeout: Duration::from_millis(150), ..Default::default() },
        );
        let t0 = Instant::now();
        let e = r.query_family("dead.test", true).await.unwrap_err();
        assert!(t0.elapsed() < Duration::from_millis(900), "{:?}", t0.elapsed());
        assert!(e.to_string().contains("AAAA"), "{e}");
    }

    #[tokio::test]
    async fn cache_is_per_family() {
        let (up, _h) = fake_dns(vec![(1u16, v4_bytes("192.0.2.1"), 60)], false).await;
        let r = Resolver::new(
            &[up.to_string()],
            ResolverOptions { query_timeout: Duration::from_millis(300), ..Default::default() },
        );
        let _ = r.lookup_grouped("perfamily.test").await.unwrap();
        assert!(r.cache_get(&family_key("perfamily.test", false)).is_some());
        assert!(r.cache_get(&family_key("perfamily.test", true)).is_some());
        assert_ne!(family_key("a.test", false), family_key("a.test", true));
    }
}
