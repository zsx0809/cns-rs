use crate::config::DialPolicy;
use crate::outbound::resolver::Resolver;
use cns_core::transport::{apply_mss_before_connect, connect_tfo, tcp_maxseg, tune_tcp_stream};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::task::JoinSet;
use tokio::time::Instant;

/// fakeip 泄漏的错误文案（契约 §5 指定，运维靠这句话区分「目标不可达」与「解析环」）
pub const FAKEIP_LEAK_MSG: &str = "目标落在客户端 fakeip 段（疑似回环解析）";

/// 回源守卫：拒绝把流量代理到本机、内网、云元数据等非公网地址，
/// 并且**无条件**拒绝客户端 fakeip 段。
///
/// CNS 的协议设计是「客户端在 HTTP 头里指定任意目标」，服务端无守卫即成为
/// 面向内网的 SSRF 跳板（打路由器、打 169.254.169.254 偷实例凭据）。
///
/// v0.3.0 起带 fakeip 段表，因此**不再是 `Copy`**（`Arc<Vec<IpCidr>>`），改成 `Clone`
/// —— 段表是 `Arc`，clone 只涨一次引用计数，热路径成本可忽略。
#[derive(Clone, Debug)]
pub struct Guard {
    pub allow_private: bool,
    /// 客户端 fakeip 段（空 = 关闭这层守卫）。
    ///
    /// 用 `Arc` 而非 `Vec`：`Guard` 是 `Copy` 的，每会话复制一份不能复制段表。
    fakeip: Arc<Vec<cns_core::net_addr::IpCidr>>,
}

impl Guard {
    /// 既有构造方式保持不变：`tunnel/dns.rs` 与其测试都按 `Guard::new(bool)` 调用，
    /// 不传 fakeip 段即关闭该层守卫（保持 v0.2.x 语义）。
    pub fn new(allow_private: bool) -> Self {
        Self { allow_private, fakeip: Arc::new(Vec::new()) }
    }

    /// 挂上 fakeip 段表（由 `DialPolicy::apply_to` 从配置注入）。
    pub fn with_fakeip_guard(mut self, cidrs: Arc<Vec<cns_core::net_addr::IpCidr>>) -> Self {
        self.fakeip = cidrs;
        self
    }

    pub fn fakeip_guard_len(&self) -> usize {
        self.fakeip.len()
    }

    /// 目标是否落在客户端 fakeip 段内。
    ///
    /// 语义：客户端启用 fakeip 后，隧道里送来的目标**理论上全是域名**（客户端 tproxy
    /// 先把 fakeip 反查回域名再发目标串）。这一层只挡「客户端反查失败、把 fakeip 原样
    /// 当目标送来」的情况 —— 那时真去回源就是解析环，必须明确报错而不是静默超时。
    pub fn is_fakeip_leak(&self, ip: IpAddr) -> bool {
        // IpCidr::contains 内部先 canonicalize_ip，所以 ::ffff:198.18.0.77 也会命中
        // v4 段；这是双栈监听上 local_addr 的真实形态，漏掉它守卫就形同虚设。
        self.fakeip.iter().any(|c| c.contains(ip))
    }

    pub fn check_ip(&self, ip: IpAddr) -> io::Result<()> {
        // fakeip 检查**先于** allow_private：段内地址不是「私网放行」能豁免的东西，
        // 它是回环信号本身。allow_private_targets=true 的调试机上，泄漏照样得炸出来。
        if self.is_fakeip_leak(ip) {
            let segs: Vec<String> = self.fakeip.iter().map(|c| c.display()).collect();
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("{FAKEIP_LEAK_MSG}: target {ip} in [{}]", segs.join(",")),
            ));
        }
        if self.allow_private {
            return Ok(());
        }
        if crate::config::is_restricted_ip(ip) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "target {ip} is restricted (loopback/private/link-local/metadata); \
                         enable allow_private_targets or allow_target_cidrs to permit it"
                ),
            ));
        }
        Ok(())
    }

    /// 域名目标必须先解析再校验：否则 `http://internal-host/` 会绕过 IP 检查。
    ///
    /// 保留兼容路径（旧签名 + 系统解析器）；新的双栈择优走
    /// [Resolver::resolve_for_dial] + [DirectOutbound::dial_tcp]。
    pub async fn resolve_and_check(&self, target: &str) -> io::Result<Vec<SocketAddr>> {
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(target).await?.collect();
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("no address resolved for {target}"),
            ));
        }
        if self.allow_private && self.fakeip.is_empty() {
            return Ok(addrs);
        }
        let ok: Vec<SocketAddr> =
            addrs.iter().filter(|a| self.check_ip(a.ip()).is_ok()).copied().collect();
        if ok.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("all resolved addresses for {target} are restricted"),
            ));
        }
        Ok(ok)
    }
}

/// 单个拨号尝试的结果（带候选下标，便于失败时定位是哪一族掉的）
type Attempt = (usize, SocketAddr, io::Result<TcpStream>);

pub struct DirectOutbound;

impl DirectOutbound {
    /// 回源拨号：RFC 8305 风格双栈竞速 + 用户态 MSS + 两段守卫。
    ///
    /// 流程（顺序是刻意的）：
    /// 1. 目标串 -> 有序候选（字面 IP 直通不查 DNS；域名走 [Resolver::resolve_for_dial]，
    ///    `auto` 得到「v6 首发、两族交错」的 attempt-target list）；
    /// 2. **连接前**逐候选过 Guard（含 fakeip 段）：一个 SYN 都不该发给 fakeip；
    /// 3. 竞速建连（见 [DirectOutbound::race_connect]）；
    /// 4. 胜者 socket 上**二次校验** `peer_addr`：解析结果与真实对端可能不一致
    ///    （DNS rebinding、CDN 返回另一族、`::ffff:` 形态），这是 SSRF 的最后闸门。
    pub async fn dial_tcp(
        target: &str,
        guard: &Guard,
        resolver: &Resolver,
        policy: &DialPolicy,
        enable_tfo: bool,
    ) -> io::Result<TcpStream> {
        // fakeip 段表以 **policy 为权威**：serve.rs 正常路径已经把表注入到 ctx.guard，
        // 但任何调用方传入一个「没挂段的 Guard」（例如自己 Guard::new(false)）都不该
        // 让这层守卫静默失效 —— 漏掉的后果是解析环，表现是随机超时，事后极难归因。
        let guard = policy.apply_to(guard.clone());
        let guard = &guard;

        let mut candidates =
            resolver.resolve_for_dial(target, policy.prefer).await.map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("resolve {target} failed (prefer={}): {e}", policy.prefer),
                )
            })?;

        if candidates.is_empty() {
            // 显式族偏好下该族无地址：明确报错，**绝不**偷偷回落到另一族。
            // 运维写死 ipv4/ipv6 就是因为另一族在现场有问题，静默换族会把故障藏起来。
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("no {prefer} candidate for {target}", prefer = policy.prefer),
            ));
        }

        // 每族限量：候选来自 DNS 应答，CDN 一条 A 可以挂 20+ 地址；
        // 不限并发就是自己 DoS 自己（同时打光 fd 与上游连接表）。
        candidates = cap_per_family(&candidates, policy.probe_count);

        // 守卫预筛与 fakeip 判定都在 race_connect 里做（唯一真源），
        // 这里只负责把目标串变成候选。
        Self::race_connect(&candidates, policy, guard, enable_tfo).await.map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "dial {target} failed ({} candidates, prefer={}): {e}",
                    candidates.len(),
                    policy.prefer
                ),
            )
        })
    }

    /// 竞速核心：先过守卫筛候选，再让第一个成功的尝试胜出，其余立刻 abort 并释放 socket。
    ///
    /// 为什么不是「串行试完」（v0.2.x 的 `connect_any`）：蜂窝/VPS 上 IPv6 黑洞
    /// 不返回 RST 而是**不回包**，串行就要把整段 connect 超时付一遍，
    /// 表现为「每个新连接都慢几秒」，用户以为代理挂了。
    ///
    /// 调度规则（RFC 8305 §5）：
    /// * 候选 0（首发族）立即开拨；
    /// * 之后每个候选的**最晚**开拨时刻 = 上一个开拨时刻 + `happy_eyeballs_ms`
    ///   —— 错峰而不是同时，给 v6 一个「不花 v4 的钱也能赢」的窗口；
    /// * 但只要有在途尝试**失败**，下一个候选立刻开拨，不等窗口
    ///   （v6 被 RST 拒绝时白等 200ms 是把慢送给用户）；
    /// * 全部候选开完且无在途尝试 -> 返回最后一次的连接错误；
    /// * 整体还有 `dial_timeout` 硬预算，防止黑洞把 task 挂到天荒地老。
    pub(crate) async fn race_connect(
        candidates: &[SocketAddr],
        policy: &DialPolicy,
        guard: &Guard,
        enable_tfo: bool,
    ) -> io::Result<TcpStream> {
        // 连接前守卫：一个 SYN 都不该发给 fakeip 或被禁网段。
        // 全部被拦时把**第一个**候选的守卫错误原样抛出 —— 这样 fakeip 泄漏的
        // 契约文案能透到会话日志里，而不是被 "all blocked" 这种废话盖掉。
        let Some(first) = candidates.first().copied() else {
            // 零候选：调用方（dial_tcp）已经处理了「prefer 下无地址」，这里兜底
            return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "no dial candidate"));
        };

        let permitted: Vec<SocketAddr> =
            candidates.iter().copied().filter(|a| guard.check_ip(a.ip()).is_ok()).collect();
        if permitted.is_empty() {
            // 全部被拦：把**第一个**候选的守卫错误原样抛出，这样 fakeip 泄漏的契约
            // 文案能透到会话日志里，而不是被 "all blocked" 这种废话盖掉。
            guard.check_ip(first.ip())?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("all {} candidates blocked by guard", candidates.len()),
            ));
        }

        let budget = policy.dial_timeout.max(Duration::from_millis(1));
        let overall_deadline = Instant::now() + budget;

        let mut set: JoinSet<Attempt> = JoinSet::new();
        let mut next = 0usize;
        // launch_at = 下一个候选的最晚开拨时刻；None = 已全部开拨。
        // 首发族立刻开拨，其余进入错峰队列。
        let mut launch_at = launch_one(&mut set, &permitted, &mut next, policy, enable_tfo);

        let mut last_err: Option<io::Error> = None;

        loop {
            if set.is_empty() && launch_at.is_none() {
                break; // 没有候选可开、也没有在途尝试
            }

            tokio::select! {
                biased;

                // 1) 有尝试落回（成功或失败）
                maybe = set.join_next(), if !set.is_empty() => {
                    match maybe {
                        None => {}
                        Some(Err(join_err)) => {
                            // task panic / 被 abort：记下但不当成连接失败
                            tracing::debug!("dial task join error: {join_err}");
                        }
                        Some(Ok((idx, addr, result))) => match result {
                            Ok(stream) => {
                                // 胜者确定：落败方连同其未连接的 socket 一起 abort 释放
                                set.abort_all();
                                // 二次校验：peer_addr 可能与解析结果不同
                                // （DNS rebinding / CDN 换族 / IPv4-mapped 形态）
                                if let Ok(peer) = stream.peer_addr() {
                                    if let Err(e) = guard.check_ip(peer.ip()) {
                                        tracing::warn!(
                                            "post-connect guard trip: candidate={addr} peer={peer} {e}"
                                        );
                                        return Err(e);
                                    }
                                }
                                if policy.outbound_mss != 0 {
                                    tracing::debug!(
                                        "dial winner {addr} (attempt #{}) mss_target={} actual={:?}",
                                        idx,
                                        policy.outbound_mss,
                                        tcp_maxseg(fd_of(&stream))
                                    );
                                } else {
                                    tracing::debug!("dial winner {addr} (attempt #{idx})");
                                }
                                return Ok(stream);
                            }
                            Err(e) => {
                                tracing::debug!("dial attempt #{idx} {addr} failed: {e}");
                                last_err = Some(e);
                                // 失败即加速：不等错峰窗口，下一个候选立刻开拨
                                launch_at =
                                    launch_one(&mut set, &permitted, &mut next, policy, enable_tfo);
                            }
                        },
                    }
                }

                // 2) 错峰窗口到点 -> 开拨下一个候选
                _ = tokio::time::sleep_until(
                    launch_at.unwrap_or_else(|| Instant::now() + budget)
                ), if launch_at.is_some() => {
                    launch_at = launch_one(&mut set, &permitted, &mut next, policy, enable_tfo);
                }

                // 3) 总预算耗尽
                _ = tokio::time::sleep_until(overall_deadline) => {
                    tracing::debug!(
                        "dial budget {budget:?} exhausted with {} attempts in flight",
                        set.len()
                    );
                    break;
                }
            }
        }

        set.abort_all();
        drop(set);
        Err(last_err.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("dial timed out after {budget:?} ({} candidates)", permitted.len()),
            )
        }))
    }

    /// 创建用于转发 UDP/DNS 的本地套接字。
    ///
    /// `prefer_v6` 时绑定 v6 双栈 socket；否则绑定 v4。旧实现固定 `[::]:0`，
    /// 在禁用 IPv6 的容器/小鸡上直接失败导致 UDP 隧道全灭。
    pub async fn bind_udp(prefer_v6: bool) -> io::Result<UdpSocket> {
        let v6: SocketAddr = "[::]:0".parse().unwrap();
        let v4: SocketAddr = "0.0.0.0:0".parse().unwrap();

        let first = if prefer_v6 { v6 } else { v4 };
        let second = if prefer_v6 { v4 } else { v6 };

        match cns_core::transport::create_tuned_udp_socket(first) {
            Ok(sock) => Ok(sock),
            Err(e1) => cns_core::transport::create_tuned_udp_socket(second).map_err(|e2| {
                io::Error::other(format!("udp bind failed: primary={e1}, fallback={e2}"))
            }),
        }
    }
}

/// `tokio::net::TcpStream` 的 fd（`TCP_MAXSEG` 读写与诊断都要拿到裸 fd）。
pub(crate) fn fd_of(stream: &TcpStream) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        stream.as_raw_fd()
    }
    #[cfg(not(unix))]
    {
        let _ = stream;
        -1
    }
}

/// 发起一次尝试：建 socket -> （**connect 前**）设 MSS -> connect -> 调优 -> 超时封装。
/// 开拨下一个候选，返回「再下一个」的最晚开拨时刻（`None` = 已无候选）。
///
/// 每次开拨都把错峰窗口从「本次开拨时刻」起算 —— 这就是 RFC 8305 的 staggered
/// 语义，而不是「所有非首发族一起并发」，否则 v6 永远没有不花钱的优先窗口。
fn launch_one(
    set: &mut JoinSet<Attempt>,
    permitted: &[SocketAddr],
    next: &mut usize,
    policy: &DialPolicy,
    enable_tfo: bool,
) -> Option<Instant> {
    if *next >= permitted.len() {
        return None;
    }
    let addr = permitted[*next];
    spawn_attempt(set, *next, addr, policy, enable_tfo);
    *next += 1;
    if *next < permitted.len() {
        Some(Instant::now() + policy.happy_eyeballs)
    } else {
        None
    }
}

fn spawn_attempt(
    set: &mut JoinSet<Attempt>,
    idx: usize,
    addr: SocketAddr,
    policy: &DialPolicy,
    enable_tfo: bool,
) {
    let mss = policy.outbound_mss;
    let budget = policy.dial_timeout;
    set.spawn(async move { (idx, addr, connect_one(addr, mss, enable_tfo, budget).await) });
}

/// 单次连接。
///
/// **MSS 必须在 connect 之前设置**：本机实测 connect 之后再 `setsockopt(TCP_MAXSEG)`
/// 会被内核按已建立的路由**再夹一次**（设 1310 读回 1288），等于钳制没生效。
/// 这台内核没有 `xt_TCPMSS`（`iptables -j TCPMSS` 报 No chain/target/match），
/// 用户态 socket option 是唯一落点，见 `cns_core::transport::mss` 的模块注释。
async fn connect_one(
    addr: SocketAddr,
    mss: u16,
    enable_tfo: bool,
    budget: Duration,
) -> io::Result<TcpStream> {
    if mss == 0 {
        // 不钳 MSS 时直接复用 core 的 TFO 连接，保留 v0.2.x 的 0-RTT 行为
        let inner = connect_tfo(addr, enable_tfo);
        return match tokio::time::timeout(budget, inner).await {
            Ok(res) => res,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("connect {addr} timed out after {budget:?}"),
            )),
        };
    }

    let sock = if addr.is_ipv6() { TcpSocket::new_v6()? } else { TcpSocket::new_v4()? };
    let _ = sock.set_nodelay(true);
    let _ = sock.set_reuseaddr(true);

    if let Err(e) = apply_mss_before_connect(fd_of_sock(&sock), mss) {
        // 不是致命错误：内核不支持时仍要连出去，黑洞交给上层 tcp_mtu_probing/分段兜底，
        // 但必须留痕 —— 静默失败正是旧脚本把「规则从未生效」藏成玄学 bug 的方式。
        tracing::debug!("TCP_MAXSEG={mss} unavailable on {addr}: {e}");
    }
    if enable_tfo {
        // 竞速路径刻意不开 `TCP_FASTOPEN_CONNECT`：开了之后 connect() 立刻返回
        // ENOTCONN，握手成功与否要推迟到首次 write 才知道，而「第一个成功者胜出」
        // 的判定依赖 connect() 的即时结果。两者语义互斥时优先保竞速 + pre-connect MSS
        // （要 TFO 且不需要钳 MSS，把 outbound_mss 设成 0 即走上面的 core 路径）。
        tracing::debug!("TFO skipped on mss-clamped dial {addr} (incompatible with racing)");
    }

    match tokio::time::timeout(budget, sock.connect(addr)).await {
        Ok(Ok(stream)) => {
            tune_tcp_stream(&stream);
            Ok(stream)
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("connect {addr} timed out after {budget:?}"),
        )),
    }
}

/// 取 `TcpSocket` 的 fd（与 [fd_of] 分开：一个在 connect 前、一个在 connect 后）
fn fd_of_sock(sock: &TcpSocket) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        sock.as_raw_fd()
    }
    #[cfg(not(unix))]
    {
        let _ = sock;
        -1
    }
}

/// 按族限量，**保持入参顺序**（顺序里已经编码了「v6 首发 + 交错」）。
///
/// 从前往后扫而不是先分组再拼接：分组重排会丢掉 `resolve_for_dial` 给出的交错次序。
pub(crate) fn cap_per_family(cands: &[SocketAddr], per_family: usize) -> Vec<SocketAddr> {
    let mut v4 = 0usize;
    let mut v6 = 0usize;
    let mut out = Vec::with_capacity(cands.len().min(per_family.saturating_mul(2)));
    for a in cands {
        if a.is_ipv6() {
            if v6 >= per_family {
                continue;
            }
            v6 += 1;
        } else {
            if v4 >= per_family {
                continue;
            }
            v4 += 1;
        }
        out.push(*a);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn policy(list: &[&str]) -> DialPolicy {
        let cfg = Config {
            fakeip_guard_cidrs: list.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        };
        DialPolicy::from_config(&cfg).unwrap()
    }

    /// 一个立刻 accept 并回显的本地 v4 目标端
    async fn echo4() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let h = tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut b = [0u8; 1024];
                    loop {
                        match s.read(&mut b).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&b[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        (addr, h)
    }

    #[test]
    fn guard_blocks_private_allows_public() {
        let g = Guard::new(false);
        assert!(g.check_ip("127.0.0.1".parse().unwrap()).is_err());
        assert!(g.check_ip("169.254.169.254".parse().unwrap()).is_err());
        assert!(g.check_ip("10.0.0.5".parse().unwrap()).is_err());
        assert!(g.check_ip("1.1.1.1".parse().unwrap()).is_ok());

        let open = Guard::new(true);
        assert!(open.check_ip("127.0.0.1".parse().unwrap()).is_ok());
    }

    /// fakeip 守卫：**无条件**拦截（连 allow_private_targets 都不能豁免），
    /// 且错误文案必须是契约指定的那句（运维要能一眼区分「不可达」与「解析环」）
    #[test]
    fn guard_blocks_fakeip_even_when_private_allowed() {
        let p = policy(&["198.18.0.0/15", "fd53::/48"]);
        let g = p.apply_to(Guard::new(true));
        assert_eq!(g.fakeip_guard_len(), 2);

        for leak in ["198.18.0.77", "198.19.255.254", "fd53::1"] {
            let e = g.check_ip(leak.parse().unwrap()).unwrap_err();
            assert!(e.to_string().contains(FAKEIP_LEAK_MSG), "{leak}: {e}");
            assert!(e.to_string().contains(leak), "错误里要带上被拦的地址: {e}");
        }
        // mapped 形态同样命中（双栈 socket 上 local_addr 就是 ::ffff:x）
        let e = g.check_ip("::ffff:198.18.0.77".parse().unwrap()).unwrap_err();
        assert!(e.to_string().contains(FAKEIP_LEAK_MSG), "{e}");

        // 段外地址不受影响
        assert!(g.check_ip("198.17.0.1".parse().unwrap()).is_ok());
        assert!(g.check_ip("1.1.1.1".parse().unwrap()).is_ok());

        // 空列表 = 关闭；旧 `Guard::new` 语义保持不变
        let off = policy(&[]).apply_to(Guard::new(false));
        assert!(off.check_ip("198.18.0.77".parse().unwrap()).is_err(), "仍受 restricted 约束");
        assert!(Guard::new(true).is_fakeip_leak("198.18.0.77".parse().unwrap()) == false);
    }

    #[tokio::test]
    async fn dial_refuses_loopback_before_connecting() {
        let g = Guard::new(false);
        let p = policy(&[]);
        let r = Resolver::new(&["127.0.0.1:1".to_string()], Default::default());
        let err = DirectOutbound::dial_tcp("127.0.0.1:9", &g, &r, &p, false).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    /// 目标串就是 fakeip：必须在**发出任何 SYN 之前**失败，且报契约文案
    #[tokio::test]
    async fn dial_refuses_fakeip_target_with_contract_message() {
        let g = Guard::new(true); // 就算放开了私网，fakeip 也得拦
        let p = policy(&["198.18.0.0/15", "fd53::/48"]);
        let r = Resolver::new(&["127.0.0.1:1".to_string()], Default::default());
        let err = DirectOutbound::dial_tcp("198.18.0.77:443", &g, &r, &p, false).await.unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains(FAKEIP_LEAK_MSG), "{msg}");
        assert_eq!(err.kind(), io::ErrorKind::AddrNotAvailable);

        let err6 = DirectOutbound::dial_tcp("[fd53::77]:443", &g, &r, &p, false).await.unwrap_err();
        assert!(format!("{err6}").contains(FAKEIP_LEAK_MSG), "{err6}");
    }

    /// 字面 IP 目标：不过 DNS、不查询上游（离线可跑），连通即回显
    #[tokio::test]
    async fn dial_connects_literal_ip_without_dns() {
        let (target, _h) = echo4().await;
        let g = Guard::new(true);
        let p = policy(&[]);
        let r = Resolver::new(&["127.0.0.1:1".to_string()], Default::default());
        let s = DirectOutbound::dial_tcp(&target.to_string(), &g, &r, &p, false).await.unwrap();
        assert_eq!(s.peer_addr().unwrap(), target);
    }

    /// 显式族偏好不覆盖字面 IP 目标，但也不越权改族（写死 v6 偏好、目标是 v4 字面量
    /// 时，v0.3.0 的口径是「尊重字面目标」，由调用方决定要不要连）
    #[tokio::test]
    async fn dial_honours_literal_target_regardless_of_preference() {
        let (target, _h) = echo4().await;
        let cfg = Config { prefer_family: "ipv6".into(), ..Default::default() };
        let p = DialPolicy::from_config(&cfg).unwrap();
        let r = Resolver::new(&["127.0.0.1:1".to_string()], Default::default());
        let s =
            DirectOutbound::dial_tcp(&target.to_string(), &Guard::new(true), &r, &p, false).await;
        assert!(s.is_ok(), "字面 v4 目标不该被 ipv6 偏好改族: {s:?}");
    }

    /// 核心场景：**v6 黑洞 + v4 正常**，竞速必须仍然成功（串行就白等一个超时）
    ///
    /// fixture 说明：这里不能用「bind [::1] 但不 accept」当作黑洞 —— loopback 上
    /// listen backlog 有 128，connect 会从 SYN 队列直接成功，测不出失败路径。
    /// 用文档前缀 `2001:db8::1`（无路由）得到真实的 connect 失败/超时，
    /// 语义上就是现场那种「SYN 出得去、回不来」的 v6 黑洞。
    #[tokio::test]
    async fn race_wins_v4_when_v6_is_blackhole() {
        let Some(_) = v6_dead_loopback().await else {
            eprintln!("skip: no usable IPv6 loopback on this host");
            return;
        };
        let (v4target, _h) = echo4().await;
        let blackhole: SocketAddr = "[2001:db8::dead]:1".parse().unwrap();
        // 首发族（v6）在前，交错出 v4
        let cands = vec![blackhole, v4target];

        let p = DialPolicy::from_config(&Config {
            happy_eyeballs_ms: 30,
            dial_timeout: 2,
            ..Default::default()
        })
        .unwrap();
        let g = Guard::new(true);

        let t0 = std::time::Instant::now();
        let s = DirectOutbound::race_connect(&cands, &p, &g, false).await.unwrap();
        // 胜者必须是那个真的在 accept 的 v4 目标
        assert_eq!(s.peer_addr().unwrap(), v4target);
        let took = t0.elapsed();
        assert!(took < Duration::from_secs(2), "不该把预算耗光才赢: {took:?}");

        // 真的能收发数据
        let mut buf = [0u8; 4];
        s.writable().await.unwrap();
        let (r, mut w) = s.into_split();
        w.write_all(b"ping").await.unwrap();
        let mut rr = tokio::io::BufReader::new(r);
        rr.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    /// 错峰是真的存在（RFC 8305 §3 的 sequential fallback 而非纯并发）：
    /// 首发 v6 黑洞不返回 RST（不可路由 = 静默丢包），v4 只在 `happy_eyeballs_ms`
    /// 之后才被开拨 —— 所以胜者出现在 ~窗口时刻，既不是 0ms（并发）也不是预算耗尽。
    #[tokio::test]
    async fn race_staggers_second_family_by_happy_eyeballs() {
        // 本机没有 v6 栈时，v6 尝试会以 "unsupported" **立刻**失败，错峰窗口根本不会
        // 被走到 —— 那不是竞速错了，是环境不具备，必须显式跳过而不是假失败。
        let Some(_) = v6_dead_loopback().await else {
            eprintln!("skip: no usable IPv6 loopback on this host");
            return;
        };
        let (v4target, _h) = echo4().await;
        let blackhole: SocketAddr = "[2001:db8::cafe]:1".parse().unwrap();
        let p = DialPolicy::from_config(&Config {
            happy_eyeballs_ms: 300,
            dial_timeout: 5,
            ..Default::default()
        })
        .unwrap();

        let t0 = std::time::Instant::now();
        let s = DirectOutbound::race_connect(&[blackhole, v4target], &p, &Guard::new(true), false)
            .await
            .unwrap();
        let took = t0.elapsed();
        assert_eq!(s.peer_addr().unwrap(), v4target);
        assert!(
            took >= Duration::from_millis(250),
            "v4 不该和 v6 同时开拨（并发就没有优先窗口了）: {took:?}"
        );
        assert!(took < Duration::from_secs(2), "更不该等满 dial 预算: {took:?}");
    }

    /// 首发族**快速失败**（RST/ECONNREFUSED）时必须不等错峰窗口，立刻开拨下一个。
    /// 这是「错峰」与「白等」的分界：黑洞才值得等，被明确拒绝没必要等。
    #[tokio::test]
    async fn race_skips_stagger_when_first_attempt_fails_fast() {
        let (v4target, _h) = echo4().await;
        // ::1 上一个没人监听的端口 -> 立刻 ECONNREFUSED
        let Some(refused) = v6_dead_loopback().await else {
            eprintln!("skip: no usable IPv6 loopback on this host");
            return; // v6 不可用时该尝试会立刻以 "unsupported" 失败，测不到 refused 语义
        };
        // 上面的 helper 已 drop 监听器，连它只会得到 ECONNREFUSED（快速失败）
        let p = DialPolicy::from_config(&Config {
            happy_eyeballs_ms: 600,
            dial_timeout: 5,
            ..Default::default()
        })
        .unwrap();

        let t0 = std::time::Instant::now();
        let s = DirectOutbound::race_connect(&[refused, v4target], &p, &Guard::new(true), false)
            .await
            .unwrap();
        let took = t0.elapsed();
        assert_eq!(s.peer_addr().unwrap(), v4target);
        assert!(
            took < Duration::from_millis(500),
            "失败后还死等 600ms 错峰窗口 = 把慢送给用户: {took:?}"
        );
    }

    /// 全是黑洞时**有界**失败：不能把 task 挂住，也不能悄悄改族
    #[tokio::test]
    async fn race_fails_bounded_when_every_candidate_is_a_blackhole() {
        if v6_dead_loopback().await.is_none() {
            // 无 v6 栈时这些候选会瞬间失败，"有界"仍然成立，只是不再经过黑洞路径；
            // 保留断言（更快），只在完全拿不到 v6 socket 时跳过
            eprintln!("skip: no usable IPv6 loopback on this host");
            return;
        }
        let holes: Vec<SocketAddr> =
            vec!["[2001:db8::1]:1".parse().unwrap(), "[2001:db8::2]:1".parse().unwrap()];
        let p = DialPolicy::from_config(&Config {
            happy_eyeballs_ms: 20,
            dial_timeout: 1,
            ..Default::default()
        })
        .unwrap();
        let t0 = std::time::Instant::now();
        let e =
            DirectOutbound::race_connect(&holes, &p, &Guard::new(true), false).await.unwrap_err();
        let took = t0.elapsed();
        assert!(took < Duration::from_secs(4), "必须受预算约束: {took:?} ({e})");
        // 返回的是最后一个候选的失败原因（connect 超时/网络不可达），不是 panic 也不是悬挂
        tracing::debug!("all-blackhole dial error: {e}");
    }

    /// `prefer_family` 显式指定时绝不越族：域名只有 A 记录 + 偏好 ipv6 -> 明确报错。
    ///
    /// 这条断言防的是「静默改用另一族」：运维写死 ipv6/ipv4 是因为现场那一族有问题，
    /// 悄悄换族会把故障藏起来，表现成「偏好没生效」的玄学。
    #[tokio::test]
    async fn dial_never_falls_back_across_explicit_preference() {
        use crate::outbound::resolver::test_fixtures::v4_only_upstream;
        let up = v4_only_upstream("93.184.216.34").await;
        let r = Resolver::new(
            &[up.to_string()],
            crate::outbound::resolver::ResolverOptions {
                query_timeout: Duration::from_millis(400),
                ..Default::default()
            },
        );
        let cfg = Config { prefer_family: "ipv6".into(), dial_timeout: 1, ..Default::default() };
        let p = DialPolicy::from_config(&cfg).unwrap();

        let err = DirectOutbound::dial_tcp("v4only.test:443", &Guard::new(true), &r, &p, false)
            .await
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("no ipv6 candidate"), "显式偏好无候选必须点名族: {msg}");

        // 同一目标在 auto 下有候选（v4），并且能真连上本地 echo（不依赖外网）
        let (target, _h) = echo4().await;
        let auto =
            DialPolicy::from_config(&Config { prefer_family: "auto".into(), ..Default::default() })
                .unwrap();
        let cands = r.resolve_for_dial("v4only.test:443", auto.prefer).await.unwrap();
        assert!(cands.iter().all(|a| a.is_ipv4()), "只有 A 记录时 auto 也只能给 v4: {cands:?}");
        // 字面 v4 目标在 ipv6 偏好下仍按字面连（偏好不改写已指定的目标）
        let s = DirectOutbound::dial_tcp(&target.to_string(), &Guard::new(true), &r, &p, false)
            .await
            .unwrap();
        assert_eq!(s.peer_addr().unwrap(), target);
    }

    /// 取一个「刚刚关掉的 v6 loopback 监听地址」，用来判定本机 v6 栈是否可用。
    ///
    /// `bind` 成功不代表 `connect` 能走通（容器里 v6 可能被 sysctl 关掉），所以要实测
    /// 一次；实测失败就返回 `None`，让依赖 v6 的测试**显式跳过**而不是假失败。
    /// 返回的地址没有监听者，连它会立刻 ECONNREFUSED —— 正好是「快速失败」的 fixture。
    async fn v6_dead_loopback() -> Option<SocketAddr> {
        let l = TcpListener::bind("[::1]:0").await.ok()?;
        let a = l.local_addr().ok()?;
        drop(l);
        let sock = TcpSocket::new_v6().ok()?;
        match tokio::time::timeout(Duration::from_millis(500), sock.connect(a)).await {
            Ok(Ok(_)) => None, // 竟然连上了：说明监听器还没真关掉，判定不可信
            Ok(Err(_)) => Some(a),
            Err(_) => None,
        }
    }

    /// 两族都可达时，首发族（v6）胜出 —— 这就是 `auto` 的「优先 v6」
    #[tokio::test]
    async fn race_prefers_v6_when_both_reachable() {
        let Some(probe) = v6_dead_loopback().await else {
            eprintln!("skip: no usable IPv6 loopback on this host");
            return;
        };
        let _ = probe;
        let v6l = TcpListener::bind("[::1]:0").await.unwrap();
        let v6addr = v6l.local_addr().unwrap();
        let (v4addr, _h4) = echo4().await;
        tokio::spawn(async move {
            while let Ok((mut s, _)) = v6l.accept().await {
                let mut b = [0u8; 8];
                let _ = s.read(&mut b).await;
            }
        });
        let p = DialPolicy::from_config(&Config { happy_eyeballs_ms: 40, ..Default::default() })
            .unwrap();
        let cands = cap_per_family(&order_for_test(v6addr, v4addr), p.probe_count);
        let s = DirectOutbound::race_connect(&cands, &p, &Guard::new(true), false).await.unwrap();
        assert_eq!(s.peer_addr().unwrap(), v6addr, "v6 首发应胜出");
    }

    fn order_for_test(v6: SocketAddr, v4: SocketAddr) -> Vec<SocketAddr> {
        vec![v6, v4]
    }

    /// MSS 必须在 connect 前生效：胜者 socket 的 `TCP_MAXSEG` 不得高于配置值，
    /// 且必须仍在合法区间（内核只会往下夹）
    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "android"))]
    async fn race_applies_mss_before_connect() {
        use cns_core::transport::MIN_MSS;
        let (target, _h) = echo4().await;
        let want: u16 = 1288;
        let p =
            DialPolicy::from_config(&Config { outbound_mss: want, ..Default::default() }).unwrap();
        let s = DirectOutbound::dial_tcp(
            &target.to_string(),
            &Guard::new(true),
            &literal_resolver(),
            &p,
            false,
        )
        .await
        .unwrap();
        let got = tcp_maxseg(fd_of(&s)).expect("loopback 上应能读回 TCP_MAXSEG");
        assert!(got <= want, "connect 前设的 MSS 不该被抬高，实际 {got}");
        assert!(got >= MIN_MSS, "{got} 必须仍 >= RFC879 下限");
    }

    /// `outbound_mss = 0` 走 core 的 TFO 路径（保留 v0.2.x 行为，不改钳制）
    #[tokio::test]
    async fn dial_without_mss_clamp_still_connects() {
        let (target, _h) = echo4().await;
        let p = DialPolicy::from_config(&Config { outbound_mss: 0, ..Default::default() }).unwrap();
        let s = DirectOutbound::dial_tcp(
            &target.to_string(),
            &Guard::new(true),
            &literal_resolver(),
            &p,
            true,
        )
        .await
        .unwrap();
        assert_eq!(s.peer_addr().unwrap(), target);
    }

    fn literal_resolver() -> Resolver {
        // 上游指向一个不会应答的端口：所有测试目标都是字面 IP，绝不触发真实 DNS
        Resolver::new(&["127.0.0.1:1".to_string()], Default::default())
    }

    #[test]
    fn cap_per_family_keeps_order_and_limits_each_family() {
        let mk = |s: &str| s.parse::<SocketAddr>().unwrap();
        let cands = vec![
            mk("[2001:db8::1]:443"),
            mk("1.1.1.1:443"),
            mk("[2001:db8::2]:443"),
            mk("1.1.1.2:443"),
            mk("[2001:db8::3]:443"),
            mk("1.1.1.3:443"),
        ];
        let capped = cap_per_family(&cands, 2);
        assert_eq!(capped.len(), 4);
        // 交错顺序保持，且每族只取前 2 个
        assert!(capped[0].is_ipv6() && capped[1].is_ipv4());
        assert!(capped[2].is_ipv6() && capped[3].is_ipv4());
        assert_eq!(capped[2], mk("[2001:db8::2]:443"));
        assert_eq!(cap_per_family(&cands, 0).len(), 0);
        assert_eq!(cap_per_family(&[], 8).len(), 0);
    }

    #[tokio::test]
    async fn race_rejects_all_guarded_candidates() {
        let p = policy(&["198.18.0.0/15"]);
        let cands = vec!["198.18.0.1:80".parse().unwrap(), "198.18.9.9:80".parse().unwrap()];
        let g = Guard::new(false).with_fakeip_guard(Arc::clone(&p.fakeip_guard));
        let err = DirectOutbound::race_connect(&cands, &p, &g, false).await.unwrap_err();
        assert!(err.to_string().contains(FAKEIP_LEAK_MSG), "{err}");
    }

    #[tokio::test]
    async fn race_without_candidates_errors() {
        let p = policy(&[]);
        assert!(DirectOutbound::race_connect(&[], &p, &Guard::new(true), false)
            .await
            .unwrap_err()
            .to_string()
            .contains("no dial candidate"));
    }

    #[tokio::test]
    async fn bind_udp_fallback_succeeds() {
        // 无论是否支持 v6，两种偏好都必须能拿到一个可用 socket
        for prefer_v6 in [true, false] {
            let sock = DirectOutbound::bind_udp(prefer_v6).await.unwrap();
            assert!(sock.local_addr().is_ok());
        }
    }

    #[test]
    fn post_connect_guard_uses_same_fakeip_semantics() {
        // 二次校验走同一个 check_ip：这里确保文案一致
        let p = policy(&["fd53::/48"]);
        let g = p.apply_to(Guard::new(true));
        let peer: IpAddr = "fd53::abcd".parse().unwrap();
        assert!(g.check_ip(peer).unwrap_err().to_string().contains(FAKEIP_LEAK_MSG));
        assert!(!g.is_fakeip_leak(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }
}
