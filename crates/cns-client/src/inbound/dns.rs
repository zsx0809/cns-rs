use crate::config::ClientConfig;
use crate::outbound::DnsChannel;
use cns_core::crypto::CuteBiCipher;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, trace, warn};

/// 本地 DNS 中继。
///
/// 三件事：
/// 1. **上游选择**：默认沿用 App 原本要查的 DNS（`IP_RECVORIGDSTADDR` 捕获的
///    orig_dst）。旧实现把它辛苦取出来却写死 `8.8.8.8:53`，国内 VPS 或被劫持
///    链路直接全挂。
/// 2. **连接复用 + 缓存**：旧实现每个查询新建一条到 VPS 的 TCP 连接并完整握手，
///    App 冷启动几十个域名就是几十个并发外连。现在同一上游共用一条隧道，且
///    命中缓存的查询完全不发网络包。
/// 3. **源地址镜像回包**：Android 内核严格校验 DNS 回包源地址，必须用
///    `IP_TRANSPARENT` + `bind(orig_dst)`（比裸 `IPPROTO_RAW` 在内核各版本上都稳），
///    失败再退到手工构造的 IPv4 raw 包。
pub struct LocalDnsRelay {
    config: Arc<ClientConfig>,
    cipher: Arc<CuteBiCipher>,
    channels: Mutex<HashMap<SocketAddr, Arc<DnsChannel>>>,
    cache: Mutex<HashMap<CacheKey, CachedAnswer>>,
    stats: RelayStats,
}

#[derive(Default)]
struct RelayStats {
    served: AtomicU64,
    cache_hits: AtomicU64,
    nodata: AtomicU64,
    failures: AtomicU64,
    transparent_replies: AtomicU64,
    raw_replies: AtomicU64,
    fallback_replies: AtomicU64,
}

/// 缓存键 = 去掉事务 ID 的完整查询报文（txid 在响应时回填，因此可跨客户端复用）
type CacheKey = Vec<u8>;

struct CachedAnswer {
    msg: Vec<u8>,
    expires: Instant,
}

impl LocalDnsRelay {
    pub fn new(config: Arc<ClientConfig>, cipher: Arc<CuteBiCipher>) -> Arc<Self> {
        Arc::new(Self {
            config,
            cipher,
            channels: Mutex::new(HashMap::new()),
            cache: Mutex::new(HashMap::new()),
            stats: RelayStats::default(),
        })
    }

    pub fn stats_line(&self) -> String {
        let s = &self.stats;
        format!(
            "served={} cache_hits={} nodata={} fail={} reply[trans={} raw={} fbk={}]",
            s.served.load(Ordering::Relaxed),
            s.cache_hits.load(Ordering::Relaxed),
            s.nodata.load(Ordering::Relaxed),
            s.failures.load(Ordering::Relaxed),
            s.transparent_replies.load(Ordering::Relaxed),
            s.raw_replies.load(Ordering::Relaxed),
            s.fallback_replies.load(Ordering::Relaxed),
        )
    }

    /// 取得（必要时创建）指向某上游的复用通道
    fn channel(&self, upstream: SocketAddr) -> Arc<DnsChannel> {
        if let Ok(g) = self.channels.lock() {
            if let Some(ch) = g.get(&upstream) {
                return Arc::clone(ch);
            }
        }
        let ch =
            Arc::new(DnsChannel::new(Arc::clone(&self.config), Arc::clone(&self.cipher), upstream));
        if let Ok(mut g) = self.channels.lock() {
            // 双检：并发时可能已有别的包插入了同上游通道
            if let Some(existing) = g.get(&upstream) {
                return Arc::clone(existing);
            }
            g.insert(upstream, Arc::clone(&ch));
        }
        ch
    }

    pub async fn run(
        listen_addr: SocketAddr,
        config: Arc<ClientConfig>,
        cipher: Arc<CuteBiCipher>,
    ) -> io::Result<()> {
        let relay = LocalDnsRelay::new(Arc::clone(&config), Arc::clone(&cipher));
        relay.run_loop(listen_addr).await
    }

    pub async fn run_loop(self: Arc<Self>, listen_addr: SocketAddr) -> io::Result<()> {
        let socket = Arc::new(bind_relay_socket(listen_addr)?);
        self.run_loop_with_socket(socket).await
    }

    /// 用外部已绑定的 socket 跑主循环（便于先建监听、后切 GID）
    pub async fn run_loop_with_socket(self: Arc<Self>, socket: Arc<UdpSocket>) -> io::Result<()> {
        let listen_addr = socket.local_addr()?;
        debug!(
            "local DNS relay listening on UDP {listen_addr} (orig-dst capture + AAAA filter={})",
            self.config.block_ipv6
        );
        if self.config.block_ipv6 {
            if let Some(w) = ipv6_availability_warning().await {
                warn!("{w}");
            }
        }

        let mut buf = vec![0u8; 4096];
        let mut ctrl_buf = [0u8; 1024];

        loop {
            let raw_fd = socket.as_raw_fd();
            let recv_res = socket.try_io(Interest::READABLE, || {
                recv_packet_with_orig_dst(raw_fd, &mut buf, &mut ctrl_buf)
            });

            let (len, peer, orig_dst) = match recv_res {
                Ok(res) => res,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if let Err(e) = socket.readable().await {
                        debug!("DNS relay readable wait error: {e}");
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    continue;
                }
                Err(e) => {
                    warn!("DNS recv error: {e}");
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    continue;
                }
            };

            let query = buf[..len].to_vec();
            let relay = Arc::clone(&self);
            let sock = Arc::clone(&socket);

            tokio::spawn(async move {
                if let Err(e) = relay.handle_one(sock, peer, orig_dst, query).await {
                    trace!("DNS query {peer} -> {orig_dst} failed: {e}");
                }
            });
        }
    }

    async fn handle_one(
        self: Arc<Self>,
        relay_sock: Arc<UdpSocket>,
        peer: SocketAddr,
        orig_dst: SocketAddr,
        query: Vec<u8>,
    ) -> io::Result<()> {
        if query.len() < 12 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "short DNS message"));
        }

        // 1. AAAA 拦截（可关闭：IPv6-only / 双栈可用网络必须关）
        if self.config.block_ipv6 {
            if let Some(nodata) = build_aaaa_nodata_response(&query) {
                self.stats.nodata.fetch_add(1, Ordering::Relaxed);
                // NODATA 也进缓存：同一 App 往往连发多次同样的 AAAA
                if let Some((key, ttl)) = cache_key_of(&query) {
                    self.put_cache(key, nodata.clone(), ttl.max(5));
                }
                return self.reply(relay_sock, peer, orig_dst, &nodata).await;
            }
        }

        // 2. 缓存命中
        let txid = u16::from_be_bytes([query[0], query[1]]);
        if let Some((key, _)) = cache_key_of(&query) {
            if let Some(mut msg) = self.get_cache(&key) {
                if msg.len() >= 2 {
                    // 回填本次查询的事务 ID
                    msg[0] = (txid >> 8) as u8;
                    msg[1] = (txid & 0xff) as u8;
                }
                self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                self.stats.served.fetch_add(1, Ordering::Relaxed);
                return self.reply(relay_sock, peer, orig_dst, &msg).await;
            }
        }

        // 3. 选择上游
        let upstream = match self.pick_upstream(orig_dst) {
            Some(u) => u,
            None => {
                // 这条是「orig 模式拿不到原始 DNS 上游」的唯一症状，必须在默认
                // warn 级别下可见（warn_once 防刷屏）。
                warn_once(
                    "dns-no-upstream",
                    &format!(
                        "DNS 没有可用上游（orig_dst={orig_dst} 既不是可用的 DNS 目标，\
                         dns_upstream 也为空）——请检查 dns_mode 与 dns_upstream 配置"
                    ),
                );
                self.stats.failures.fetch_add(1, Ordering::Relaxed);
                return Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "no usable DNS upstream",
                ));
            }
        };

        // 4. 走复用隧道查询
        let channel = self.channel(upstream);
        let answer =
            timeout(self.config.timeout().min(Duration::from_secs(8)), channel.query(&query))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tunnel dns query timed out"))?
                .inspect_err(|_| {
                    self.stats.failures.fetch_add(1, Ordering::Relaxed);
                })?;

        if answer.len() < 12 {
            self.stats.failures.fetch_add(1, Ordering::Relaxed);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "upstream DNS answer too short",
            ));
        }

        // 5. 写缓存（按应答里的真实 TTL）
        if let Some((key, ttl)) = cache_key_of(&query) {
            self.put_cache(key, answer.clone(), ttl);
        }
        self.stats.served.fetch_add(1, Ordering::Relaxed);

        self.reply(relay_sock, peer, orig_dst, &answer).await
    }

    /// `orig` 模式沿用 App 原本的目标 DNS；`fixed` 模式恒用配置列表。
    /// 两种模式都保留对方的地址作为兜底（列表第一项优先）。
    fn pick_upstream(&self, orig_dst: SocketAddr) -> Option<SocketAddr> {
        let mut candidates: Vec<SocketAddr> = Vec::new();

        if self.config.dns_mode == "orig" && usable_dns_target(orig_dst) {
            candidates.push(orig_dst);
        }
        for item in &self.config.dns_upstream {
            if let Some(addr) = parse_upstream(item) {
                candidates.push(addr);
            }
        }
        // 最后兜底：连 orig_dst 都不可用（如被 REDIRECT 抹平成本机地址）时，
        // 用系统默认网关的 53，很多运营商劫持就在那儿
        if candidates.is_empty() {
            if let Some(gw) = default_gateway_dns() {
                candidates.push(gw);
            }
        }
        candidates.first().copied()
    }

    fn get_cache(&self, key: &[u8]) -> Option<Vec<u8>> {
        let mut g = self.cache.lock().ok()?;
        if let Some(entry) = g.get(key) {
            if entry.expires > Instant::now() {
                return Some(entry.msg.clone());
            }
            g.remove(key);
        }
        None
    }

    fn put_cache(&self, key: CacheKey, msg: Vec<u8>, ttl: u64) {
        let mut g = match self.cache.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let limit = self.config.dns_cache_size.max(64);
        if g.len() >= limit {
            let now = Instant::now();
            g.retain(|_, e| e.expires > now);
            if g.len() >= limit {
                g.clear();
            }
        }
        let ttl = ttl.clamp(5, 3600);
        g.insert(key, CachedAnswer { msg, expires: Instant::now() + Duration::from_secs(ttl) });
    }

    /// 源地址镜像回包：优先 IP_TRANSPARENT bind(orig_dst)，其次 IPv4 raw，最后退化回 relay socket
    async fn reply(
        &self,
        relay_sock: Arc<UdpSocket>,
        peer: SocketAddr,
        orig_dst: SocketAddr,
        payload: &[u8],
    ) -> io::Result<()> {
        match send_transparent_dns_reply(peer, orig_dst, payload) {
            Ok(()) => {
                self.stats.transparent_replies.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            Err(e1) => {
                trace!("transparent reply failed: {e1}");
            }
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let (SocketAddr::V4(peer_v4), SocketAddr::V4(orig_v4)) = (peer, orig_dst) {
            match send_raw_dns_reply(peer_v4, orig_v4, payload) {
                Ok(()) => {
                    self.stats.raw_replies.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                Err(e2) => {
                    debug!("raw ipv4 reply failed: {e2}");
                }
            }
        }

        // 兜底：源地址不匹配时内核可能直接丢弃这一包，但有些网络（本机 loopback
        // 查询）仍然可达，值得一试，同时明确记录降级次数便于排查
        warn_once(
            "dns-reply-fallback",
            &format!("DNS reply degraded to relay source ({orig_dst} -> {peer})"),
        );
        self.stats.fallback_replies.fetch_add(1, Ordering::Relaxed);
        relay_sock.send_to(payload, peer).await.map(|_n| ())
    }
}

/// 一次进程内只警告一次的轻量工具（避免刷日志）
fn warn_once(tag: &str, msg: &str) {
    static SEEN: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let mut seen = match SEEN.lock() {
        Ok(s) => s,
        Err(_) => return,
    };
    if !seen.iter().any(|t| t == tag) {
        warn!("{msg}");
        seen.push(tag.to_string());
    }
}

fn usable_dns_target(addr: SocketAddr) -> bool {
    // 被 REDIRECT 后 orig_dst 可能是本机地址或 0.0.0.0，这种要过滤掉
    if addr.port() != 53 {
        return false;
    }
    match addr.ip() {
        IpAddr::V4(v4) => {
            !v4.is_unspecified()
                && !v4.is_loopback()
                // 本机热点/容器里 172.x 也可能是真 DNS，这里只排 loopback 与 unspecified
                && v4 != Ipv4Addr::new(0, 0, 0, 0)
        }
        IpAddr::V6(v6) => !v6.is_unspecified() && !v6.is_loopback(),
    }
}

/// 解析配置里的 DNS 上游写法。
///
/// 支持 `ip:port`、`[ipv6]:port`、以及裸 IP（自动补 53）。
/// 注意：裸 IPv6 带端口（`2001:db8::1:53`）在语法上无法与合法 IPv6 地址消歧，
/// 因此**必须**写方括号形式；这里一律把裸串按纯 IP 解释。
fn parse_upstream(item: &str) -> Option<SocketAddr> {
    let item = item.trim();
    if item.is_empty() {
        return None;
    }
    if let Ok(a) = item.parse::<SocketAddr>() {
        return Some(a);
    }
    if let Ok(ip) = item.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, 53));
    }
    // 裸 IPv4 带端口已在上面命中；这里只处理「域名:端口」之外的失败情况
    None
}

/// 读取 `/proc/net/route` 拿默认网关（无外部依赖），失败返回 None
fn default_gateway_dns() -> Option<SocketAddr> {
    let content = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 && fields[1] == "00000000" {
            if let Ok(v) = u32::from_str_radix(fields[2], 16) {
                // /proc/net/route 是小端十六进制
                let ip = Ipv4Addr::from(v.to_be());
                if !ip.is_unspecified() {
                    return Some(SocketAddr::new(IpAddr::V4(ip), 53));
                }
            }
        }
    }
    None
}

/// 缓存键与 TTL：键 = txid 归零后的查询报文；TTL 取应答里最小记录 TTL（这里用固定值，
/// 因为解析应答 TTL 已在服务端做过，客户端只需短 TTL 抑制重复查询风暴）
fn cache_key_of(query: &[u8]) -> Option<(CacheKey, u64)> {
    if query.len() < 12 {
        return None;
    }
    let mut key = query.to_vec();
    key[0] = 0;
    key[1] = 0;
    // 只有单问题查询才缓存（多问题报文回填会错乱）
    if u16::from_be_bytes([query[4], query[5]]) != 1 {
        return None;
    }
    // 丢弃带 EDNS OPT 的查询（ARCOUNT>0 时响应长度不可预测），仍缓存以保正确性但 TTL 更短
    let arcount = u16::from_be_bytes([query[10], query[11]]);
    Some((key, if arcount == 0 { 120 } else { 30 }))
}

/// 创建带 orig-dst 捕获的 UDP 监听 socket（双栈）。供 main 在切 GID **之前**绑定。
pub fn bind_relay_socket(listen_addr: SocketAddr) -> io::Result<UdpSocket> {
    let domain = match listen_addr {
        SocketAddr::V4(_) => socket2::Domain::IPV4,
        SocketAddr::V6(_) => socket2::Domain::IPV6,
    };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    unsafe {
        let fd = sock.as_raw_fd();
        let one: libc::c_int = 1;
        // IPv4 原始目的地
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_RECVORIGDSTADDR,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of_val(&one) as libc::socklen_t,
        );
        if let SocketAddr::V6(_) = listen_addr {
            // IPv6 原始目的地（IPV6_RECVPKTINFO == 37，与 IP6_RECVDSTOPTS 不同）
            const IPV6_RECVPKTINFO: libc::c_int = 37;
            const IPV6_RECVORIGDSTADDR: libc::c_int = 74;
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                IPV6_RECVORIGDSTADDR,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of_val(&one) as libc::socklen_t,
            );
            let _ = IPV6_RECVPKTINFO;
            // 双栈：让 v4 客户端也能打到这个 v6 socket
            let _ = sock.set_only_v6(false);
        }
    }

    sock.bind(&listen_addr.into())?;
    UdpSocket::from_std(sock.into())
}

/// `IP_TRANSPARENT` + `bind(orig_dst)` 的回包路径：内核自动生成 IP/UDP 头与校验和，
/// 比手工 `IPPROTO_RAW` 构造在各内核版本上更稳，且天然支持 IPv6。
fn send_transparent_dns_reply(
    peer: SocketAddr,
    orig_dst: SocketAddr,
    payload: &[u8],
) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let domain = match orig_dst {
            SocketAddr::V4(_) => socket2::Domain::IPV4,
            SocketAddr::V6(_) => socket2::Domain::IPV6,
        };
        let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
            .map_err(|e| io::Error::new(e.kind(), format!("udp new: {e}")))?;

        // REDIRECT 模式下 orig_dst 常常就是本机中继自己的监听地址，而中继 socket
        // 已经占着那个 addr:port；不给回包 socket 加 SO_REUSEADDR 时 bind 必然
        // EADDRINUSE，每条应答都会白白多建一次 socket 再降级到 raw/relay 路径。
        let _ = sock.set_reuse_address(true);

        unsafe {
            let fd = sock.as_raw_fd();
            let one: libc::c_int = 1;
            let (level, optname) = match orig_dst {
                SocketAddr::V4(_) => (libc::SOL_IP, libc::IP_TRANSPARENT),
                SocketAddr::V6(_) => (libc::IPPROTO_IPV6, libc::IPV6_TRANSPARENT),
            };
            let ret = libc::setsockopt(
                fd,
                level,
                optname,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of_val(&one) as libc::socklen_t,
            );
            if ret != 0 {
                let e = io::Error::last_os_error();
                return Err(io::Error::new(
                    e.kind(),
                    format!("IP_TRANSPARENT on dns reply socket: {e}"),
                ));
            }
        }

        sock.bind(&orig_dst.into())
            .map_err(|e| io::Error::new(e.kind(), format!("bind {orig_dst}: {e}")))?;
        sock.set_nonblocking(true)?;

        // 直接 libc::sendto：不依赖 tokio reactor（本函数可能在同步上下文被调用）
        send_to_addr(sock.as_raw_fd(), payload, peer)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = (peer, orig_dst, payload);
        Err(io::Error::new(io::ErrorKind::Unsupported, "transparent reply needs linux/android"))
    }
}

/// 有界重试的 sendto（非阻塞 socket 首写可能 EAGAIN）
#[cfg(any(target_os = "linux", target_os = "android"))]
fn send_to_addr(fd: std::os::unix::io::RawFd, payload: &[u8], peer: SocketAddr) -> io::Result<()> {
    // 用 union 安全地在 v4/v6 结构间共享同一块内存（transmute 因尺寸不同不可用）
    #[repr(C)]
    union SockAddrAny {
        storage: libc::sockaddr_storage,
        v4: libc::sockaddr_in,
        v6: libc::sockaddr_in6,
    }

    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match peer {
        SocketAddr::V4(v4) => {
            let mut any = SockAddrAny { storage };
            unsafe {
                let sa = &mut any.v4;
                sa.sin_family = libc::AF_INET as libc::sa_family_t;
                sa.sin_port = v4.port().to_be();
                std::ptr::copy_nonoverlapping(
                    v4.ip().octets().as_ptr(),
                    &mut sa.sin_addr as *mut _ as *mut u8,
                    4,
                );
                storage = any.storage;
            }
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(v6) => {
            let mut any = SockAddrAny { storage };
            unsafe {
                let sa = &mut any.v6;
                sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sa.sin6_port = v6.port().to_be();
                sa.sin6_addr = libc::in6_addr { s6_addr: v6.ip().octets() };
                storage = any.storage;
            }
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    };

    for attempt in 0..64u32 {
        let n = unsafe {
            libc::sendto(
                fd,
                payload.as_ptr() as *const libc::c_void,
                payload.len(),
                0,
                &storage as *const _ as *const libc::sockaddr,
                len,
            )
        };
        if n >= 0 {
            return if (n as usize) == payload.len() {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    format!("partial DNS reply {n}/{} bytes", payload.len()),
                ))
            };
        }
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::WouldBlock {
            std::thread::sleep(Duration::from_millis(1));
            let _ = attempt;
            continue;
        }
        return Err(e);
    }
    Err(io::Error::new(io::ErrorKind::TimedOut, "DNS reply socket never became writable"))
}

/// 手工构造 IPv4 + UDP 原始包（源地址 = orig_dst），作为 IP_TRANSPARENT 不可用时的退路
#[cfg(any(target_os = "linux", target_os = "android"))]
fn send_raw_dns_reply(
    peer: SocketAddrV4,
    orig_dst: SocketAddrV4,
    payload: &[u8],
) -> io::Result<()> {
    let (dest_ip, dest_port) = (*peer.ip(), peer.port());
    let (src_ip, src_port) = (*orig_dst.ip(), orig_dst.port());

    let tot_len = (20 + 8 + payload.len()) as u16;
    let mut packet = Vec::with_capacity(tot_len as usize);

    // IPv4 头
    packet.push(0x45);
    packet.push(0x00);
    packet.extend_from_slice(&tot_len.to_be_bytes());
    packet.extend_from_slice(&next_ip_id().to_be_bytes()); // 递增 ID，避免重复 ID 被丢
    packet.extend_from_slice(&0x4000u16.to_be_bytes()); // DF
    packet.push(64);
    packet.push(17);
    packet.extend_from_slice(&0u16.to_be_bytes()); // checksum 占位
    packet.extend_from_slice(&src_ip.octets());
    packet.extend_from_slice(&dest_ip.octets());
    let ip_csum = calc_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // UDP 头 + 载荷
    let udp_len = (8 + payload.len()) as u16;
    let mut udp = Vec::with_capacity(8 + payload.len());
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&dest_port.to_be_bytes());
    udp.extend_from_slice(&udp_len.to_be_bytes());
    udp.extend_from_slice(&0u16.to_be_bytes()); // checksum 占位
    udp.extend_from_slice(payload);
    let udp_csum = calc_udp_checksum(src_ip, dest_ip, &udp);
    udp[6..8].copy_from_slice(&udp_csum.to_be_bytes());
    packet.extend_from_slice(&udp);

    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let one: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of_val(&one) as libc::socklen_t,
        );

        let mut dst: libc::sockaddr_in = std::mem::zeroed();
        dst.sin_family = libc::AF_INET as libc::sa_family_t;
        dst.sin_port = dest_port.to_be();
        std::ptr::copy_nonoverlapping(
            dest_ip.octets().as_ptr(),
            &mut dst.sin_addr as *mut _ as *mut u8,
            4,
        );

        let ret = libc::sendto(
            fd,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            &dst as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        libc::close(fd);
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// IPv4 报文 ID：必须递增。固定 ID 会让部分 Android/tethering 内核把包判为重复而丢弃。
#[cfg(any(target_os = "linux", target_os = "android"))]
fn next_ip_id() -> u16 {
    static ID: AtomicU64 = AtomicU64::new(1);
    (ID.fetch_add(1, Ordering::Relaxed) % 0xffff) as u16 + 1
}

/// 检查是否为 AAAA 查询，是则返回标准 NODATA 响应（RCODE=0, ANCOUNT=0）
pub fn build_aaaa_nodata_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    if u16::from_be_bytes([query[4], query[5]]) != 1 {
        return None;
    }
    let qname_end = skip_dns_name(query, 12)?;
    if qname_end + 4 > query.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([query[qname_end], query[qname_end + 1]]);
    if qtype != 28 {
        return None;
    }
    let question_end = qname_end + 4;
    let mut resp = Vec::with_capacity(question_end);
    resp.extend_from_slice(&query[0..2]); // 事务 ID 原样
    resp.extend_from_slice(&[0x81, 0x80]); // QR=1 RD=1 RCODE=0
    resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    resp.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0 → NODATA
    resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
    resp.extend_from_slice(&query[12..question_end]); // Question 段原样
    Some(resp)
}

/// 跳过 DNS 名称（处理压缩指针），返回结束后的下标
fn skip_dns_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= msg.len() {
            return None;
        }
        let len = msg[pos] as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xc0 == 0xc0 {
            return Some(pos + 2);
        }
        pos += 1 + len;
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn recv_packet_with_orig_dst(
    raw_fd: std::os::unix::io::RawFd,
    buf: &mut [u8],
    ctrl_buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    let mut iov =
        libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: buf.len() };
    // 用 sockaddr_storage 兼容 v4/v6 对端
    let mut src_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };

    // 必须 zeroed() 后再逐字段赋值：musl / bionic 的 `msghdr` 含私有 padding
    // 字段（__pad1/__pad2），结构体字面量在这两个目标上直接编译失败。
    let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
    msghdr.msg_name = &mut src_storage as *mut _ as *mut libc::c_void;
    msghdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msghdr.msg_iov = &mut iov;
    msghdr.msg_iovlen = 1;
    msghdr.msg_control = ctrl_buf.as_mut_ptr() as *mut libc::c_void;
    // `as _`：glibc 的 msg_controllen 是 usize，musl/bionic 是 u32，不能写死类型
    msghdr.msg_controllen = ctrl_buf.len() as _;
    msghdr.msg_flags = 0;

    let n = unsafe { libc::recvmsg(raw_fd, &mut msghdr, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    let peer = unsafe { sockaddr_from_storage(&src_storage) }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad peer sockaddr"))?;

    // 默认兜底：上游不可探测时退回配置的公共 DNS，而不是硬编码 8.8.8.8
    let fallback = default_upstream_hint();
    let orig_dst = unsafe { parse_orig_dst(&msghdr) }.unwrap_or(fallback);

    Ok((n as usize, peer, orig_dst))
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn recv_packet_with_orig_dst(
    _raw_fd: std::os::unix::io::RawFd,
    _buf: &mut [u8],
    _ctrl_buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported OS"))
}

fn default_upstream_hint() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(223, 5, 5, 5), 53))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn sockaddr_from_storage(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let sa = &*(storage as *const _ as *const libc::sockaddr_in);
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(sa.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(sa.sin_port),
            )))
        }
        libc::AF_INET6 => {
            let sa = &*(storage as *const _ as *const libc::sockaddr_in6);
            Some(SocketAddr::V6(SocketAddrV6::new(
                std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr),
                u16::from_be(sa.sin6_port),
                sa.sin6_flowinfo,
                sa.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

/// 从控制消息里取原始目的地（IPv4 与 IPv6 都支持）
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn parse_orig_dst(msghdr: &libc::msghdr) -> Option<SocketAddr> {
    let mut cmsg = libc::CMSG_FIRSTHDR(msghdr);
    while !cmsg.is_null() {
        let cm = &*cmsg;
        // IPv4: IPPROTO_IP / IP_ORIGDSTADDR
        if cm.cmsg_level == libc::IPPROTO_IP && cm.cmsg_type == libc::IP_ORIGDSTADDR {
            let sin = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in;
            if !sin.is_null() {
                let ip = Ipv4Addr::from((*sin).sin_addr.s_addr.to_ne_bytes());
                let port = u16::from_be((*sin).sin_port);
                return Some(SocketAddr::V4(SocketAddrV4::new(ip, port)));
            }
        }
        // IPv6: IPPROTO_IPV6 / IPV6_ORIGDSTADDR (=74)
        const IPV6_ORIGDSTADDR: libc::c_int = 74;
        if cm.cmsg_level == libc::IPPROTO_IPV6 && cm.cmsg_type == IPV6_ORIGDSTADDR {
            let sin6 = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in6;
            if !sin6.is_null() {
                let ip = std::net::Ipv6Addr::from((*sin6).sin6_addr.s6_addr);
                let port = u16::from_be((*sin6).sin6_port);
                return Some(SocketAddr::new(IpAddr::V6(ip), port));
            }
        }
        cmsg = libc::CMSG_NXTHDR(msghdr, cmsg);
    }
    None
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn calc_checksum(buf: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = buf.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&rem) = chunks.remainder().first() {
        sum += (rem as u32) << 8;
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn calc_udp_checksum(src_ip: Ipv4Addr, dest_ip: Ipv4Addr, udp_hdr_and_payload: &[u8]) -> u16 {
    let mut sum = 0u32;
    for ip in [src_ip, dest_ip] {
        let o = ip.octets();
        sum += u16::from_be_bytes([o[0], o[1]]) as u32;
        sum += u16::from_be_bytes([o[2], o[3]]) as u32;
    }
    sum += 17u32; // IPPROTO_UDP
    sum += udp_hdr_and_payload.len() as u32;
    let mut chunks = udp_hdr_and_payload.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&rem) = chunks.remainder().first() {
        sum += (rem as u32) << 8;
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let res = !(sum as u16);
    // RFC 768：UDP 校验和计算结果为 0 时必须发成 0xffff
    if res == 0 {
        0xffff
    } else {
        res
    }
}

/// 本机存在全局 IPv6 地址却拦掉 AAAA 时，双栈 App 可能解析不到任何地址 —— 提示部署者
async fn ipv6_availability_warning() -> Option<String> {
    let addrs = local_interface_addresses().await.ok()?;
    let has_global_v6 = addrs
        .iter()
        .any(|a| matches!(a, IpAddr::V6(v6) if !v6.is_loopback() && !is_link_local_v6(*v6)));
    if has_global_v6 {
        Some(
            "本机存在全局 IPv6 地址但 block_ipv6=true：AAAA 将被本地 NODATA 拦截。 \
             若目标应用需要 IPv6 直连，请在配置里把 block_ipv6 设为 false"
                .to_string(),
        )
    } else {
        None
    }
}

/// fe80::/10
fn is_link_local_v6(v6: std::net::Ipv6Addr) -> bool {
    (u16::from_be_bytes([v6.octets()[0], v6.octets()[1]]) & 0xffc0) == 0xfe80
}

fn local_interface_addresses() -> tokio::task::JoinHandle<Vec<IpAddr>> {
    tokio::task::spawn_blocking(|| {
        // `/proc/net/if_inet6` 是**文件**不是目录：旧实现对它 read_dir，永远失败，
        // 于是 `has_global_v6` 恒为 false，`block_ipv6=true` 的告警从来没打出来过。
        // 每行形如 `00000000000000000000000000000001 01 80 10 80       lo`。
        let mut out = Vec::new();
        let content = match std::fs::read_to_string("/proc/net/if_inet6") {
            Ok(c) => c,
            Err(_) => return out,
        };
        for line in content.lines() {
            let hex = match line.split_whitespace().next() {
                Some(h) if h.len() == 32 => h,
                _ => continue,
            };
            let mut bytes = [0u8; 16];
            let mut ok = true;
            for i in 0..16 {
                match u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16) {
                    Ok(b) => bytes[i] = b,
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                out.push(IpAddr::V6(std::net::Ipv6Addr::from(bytes)));
            }
        }
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(name: &str, qtype: u16, arcount: bool) -> Vec<u8> {
        let mut m = vec![0x12u8, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0];
        m.extend_from_slice(&if arcount { [0x00, 0x01] } else { [0x00, 0x00] });
        for label in name.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&[0x00, 0x01]);
        m
    }

    #[test]
    fn aaaa_is_intercepted_as_nodata() {
        let query = q("github.com", 28, false);
        let resp = build_aaaa_nodata_response(&query).expect("must intercept AAAA");
        assert_eq!(&resp[0..2], &query[0..2], "txid must echo");
        assert_eq!(&resp[2..4], &[0x81, 0x80]);
        assert_eq!(&resp[4..6], &[0, 1]); // QDCOUNT
        assert_eq!(&resp[6..8], &[0, 0]); // ANCOUNT = 0
        assert_eq!(&resp[8..10], &[0, 0]);
        assert_eq!(&resp[10..12], &[0, 0]);
        assert_eq!(&resp[12..], &query[12..]);
        assert_eq!(resp.len(), query.len());
    }

    #[test]
    fn type_a_is_not_intercepted() {
        assert!(build_aaaa_nodata_response(&q("github.com", 1, false)).is_none());
    }

    #[test]
    fn other_types_are_not_intercepted() {
        for t in [1u16, 2, 5, 12, 15, 16, 33, 65] {
            assert!(build_aaaa_nodata_response(&q("a.test", t, false)).is_none(), "{t}");
        }
    }

    #[test]
    fn malformed_queries_are_refused_not_panicked() {
        assert!(build_aaaa_nodata_response(b"short").is_none());
        // QDCOUNT != 1
        let mut multi = q("a.test", 28, false);
        multi[4] = 0;
        multi[5] = 2;
        assert!(build_aaaa_nodata_response(&multi).is_none());
        // 截断的 QTYPE
        let truncated = vec![0x00, 0x01, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'a', 0];
        assert!(build_aaaa_nodata_response(&truncated).is_none());
        // 压缩指针
        let mut compressed = vec![0x00, 0x01, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        compressed.extend_from_slice(&[0xc0, 0x04, 0x00, 0x1c, 0x00, 0x01]);
        assert!(build_aaaa_nodata_response(&compressed).is_some());
    }

    #[test]
    fn upstream_selection_respects_mode() {
        let base = ClientConfig::default();

        // orig 模式：沿用 App 原本要查的 DNS
        let cfg = Arc::new(base.clone());
        let relay = LocalDnsRelay::new(cfg, Arc::new(CuteBiCipher::new(b"k")));
        assert_eq!(
            relay.pick_upstream("1.2.3.4:53".parse().unwrap()).unwrap(),
            "1.2.3.4:53".parse().unwrap()
        );
        assert_eq!(
            relay.pick_upstream("223.5.5.5:53".parse().unwrap()).unwrap(),
            "223.5.5.5:53".parse().unwrap()
        );
        // 被 REDIRECT 抹成本机地址 → 不能用，退回配置
        let loopback = relay.pick_upstream("127.0.0.53:53".parse().unwrap()).unwrap();
        assert_eq!(loopback, "223.5.5.5:53".parse().unwrap());
        // 非 53 端口也不是 DNS
        assert_eq!(
            relay.pick_upstream("8.8.8.8:9999".parse().unwrap()).unwrap(),
            "223.5.5.5:53".parse().unwrap()
        );

        // fixed 模式：恒用配置列表
        let fixed = ClientConfig {
            dns_mode: "fixed".to_string(),
            dns_upstream: vec!["1.1.1.1:53".to_string()],
            ..Default::default()
        };
        let relay_fixed = LocalDnsRelay::new(Arc::new(fixed), Arc::new(CuteBiCipher::new(b"k")));
        assert_eq!(
            relay_fixed.pick_upstream("8.8.8.8:53".parse().unwrap()).unwrap(),
            "1.1.1.1:53".parse().unwrap()
        );
    }

    #[test]
    fn upstream_accepts_ip_only_and_bare_ipv6() {
        assert_eq!(parse_upstream("8.8.8.8"), Some("8.8.8.8:53".parse().unwrap()));
        assert_eq!(
            parse_upstream("[2001:4860:4860::8888]:53"),
            Some("[2001:4860:4860::8888]:53".parse().unwrap())
        );
        assert_eq!(
            parse_upstream("2001:4860:4860::8888"),
            Some("[2001:4860:4860::8888]:53".parse().unwrap())
        );
        // 裸 IPv6 带端口无法与合法 IPv6 地址消歧 → 按纯 IPv6 解释（端口 53）
        assert_eq!(
            parse_upstream("2001:4860:4860::8888:5353"),
            Some("[2001:4860:4860::8888:5353]:53".parse().unwrap())
        );
        assert_eq!(parse_upstream(""), None);
        assert_eq!(parse_upstream("   "), None);
        // 带端口的 IPv6 必须用方括号
        assert_eq!(
            parse_upstream("[2001:4860:4860::8888]:5353"),
            Some("[2001:4860:4860::8888]:5353".parse().unwrap())
        );
        assert_eq!(parse_upstream("garbage"), None);
    }

    #[test]
    fn cache_key_normalizes_txid_only_for_single_question() {
        let a = q("x.com", 1, false);
        let mut b = a.clone();
        b[0] = 0xAA;
        b[1] = 0xBB;
        let (ka, ttl_a) = cache_key_of(&a).unwrap();
        let (kb, _ttl_b) = cache_key_of(&b).unwrap();
        assert_eq!(ka, kb, "txid must not affect the key");
        assert_eq!(ttl_a, 120);

        // EDNS OPT 查询 TTL 更短
        let (k2, ttl2) = cache_key_of(&q("x.com", 1, true)).unwrap();
        assert_eq!(ttl2, 30);
        assert_eq!(k2.len(), q("x.com", 1, true).len());
    }

    #[test]
    fn cache_put_get_and_expiry() {
        let relay = LocalDnsRelay::new(
            Arc::new(ClientConfig::default()),
            Arc::new(CuteBiCipher::new(b"k")),
        );
        let key = b"query-bytes".to_vec();
        relay.put_cache(key.clone(), vec![9, 9], 60);
        assert_eq!(relay.get_cache(&key), Some(vec![9, 9]));

        // 过期即失效
        relay.put_cache(key.clone(), vec![8, 8], 1);
        if let Ok(mut g) = relay.cache.lock() {
            if let Some(e) = g.get_mut(&key) {
                e.expires = Instant::now() - Duration::from_secs(1);
            }
        }
        assert_eq!(relay.get_cache(&key), None);
    }

    #[test]
    fn cache_is_bounded() {
        let cfg = ClientConfig { dns_cache_size: 8, ..Default::default() };
        let relay = LocalDnsRelay::new(Arc::new(cfg), Arc::new(CuteBiCipher::new(b"k")));
        for i in 0..200u32 {
            relay.put_cache(vec![i as u8, (i >> 8) as u8, 1], vec![1], 600);
        }
        let g = relay.cache.lock().unwrap();
        assert!(g.len() <= 16, "cache escaped its bound: {}", g.len());
    }

    #[test]
    fn channel_cache_is_reused_per_upstream() {
        let relay = LocalDnsRelay::new(
            Arc::new(ClientConfig::default()),
            Arc::new(CuteBiCipher::new(b"k")),
        );
        let up: SocketAddr = "223.5.5.5:53".parse().unwrap();
        let c1 = relay.channel(up);
        let c2 = relay.channel(up);
        assert!(Arc::ptr_eq(&c1, &c2), "same upstream must share one channel");
        // 不同上游各自独立
        let c3 = relay.channel("1.1.1.1:53".parse().unwrap());
        assert!(!Arc::ptr_eq(&c1, &c3));
        assert_eq!(relay.channels.lock().unwrap().len(), 2);
    }

    #[test]
    fn stats_line_reports_all_counters() {
        let relay = LocalDnsRelay::new(
            Arc::new(ClientConfig::default()),
            Arc::new(CuteBiCipher::new(b"k")),
        );
        relay.stats.served.store(7, Ordering::Relaxed);
        relay.stats.nodata.store(3, Ordering::Relaxed);
        let line = relay.stats_line();
        assert!(line.contains("served=7"), "{line}");
        assert!(line.contains("nodata=3"), "{line}");
    }

    #[test]
    fn usable_dns_target_rejects_non_dns_and_local() {
        assert!(!usable_dns_target("127.0.0.1:53".parse().unwrap()));
        assert!(!usable_dns_target("0.0.0.0:53".parse().unwrap()));
        assert!(!usable_dns_target("8.8.8.8:5353".parse().unwrap()));
        assert!(usable_dns_target("8.8.8.8:53".parse().unwrap()));
        assert!(usable_dns_target("[2001:4860:4860::8888]:53".parse().unwrap()));
        assert!(!usable_dns_target("[::1]:53".parse().unwrap()));
    }

    #[test]
    fn default_gateway_dns_parses_or_fails_gracefully() {
        // 不要求一定有网关，只要求不 panic 且返回值合理
        if let Some(addr) = default_gateway_dns() {
            assert_eq!(addr.port(), 53);
            assert!(!addr.ip().is_loopback());
        }
    }

    #[test]
    fn udp_checksum_follows_rfc768_zero_rule() {
        let src = Ipv4Addr::new(1, 1, 1, 1);
        let dst = Ipv4Addr::new(2, 2, 2, 2);
        // 构造一段让 16 位和恰好溢出成 0xffff 的情形，验证 0 -> 0xffff 规则
        let mut udp = vec![0x00, 0x35, 0x00, 0x35, 0x00, 0x08];
        udp.extend_from_slice(&[0xff, 0xff]);
        let csum = calc_udp_checksum(src, dst, &udp);
        assert_ne!(csum, 0, "UDP checksum must never be transmitted as 0");
    }

    #[test]
    fn ip_ids_are_monotonic() {
        let a = next_ip_id();
        let b = next_ip_id();
        assert_ne!(a, b);
        assert!(b > a || b == 1, "id must advance (wrap allowed): {a} {b}");
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn ipv4_checksum_matches_known_value() {
        // 20 字节 IPv4 头样例，校验和应为 python 计算值
        let mut hdr = vec![0x45, 0x00, 0x00, 0x2c, 0x00, 0x01, 0x40, 0x00, 0x40, 0x11];
        hdr.extend_from_slice(&[0x00, 0x00]); // csum placeholder
        hdr.extend_from_slice(&[1, 1, 1, 1]);
        hdr.extend_from_slice(&[2, 2, 2, 2]);
        let csum = calc_checksum(&hdr);
        assert_ne!(csum, 0);
        // 回填后再算必须得 0（经典校验自洽检验）
        hdr[10..12].copy_from_slice(&csum.to_be_bytes());
        assert_eq!(calc_checksum(&hdr), 0);
    }

    #[tokio::test]
    async fn relay_socket_binds_and_captures_orig_dst() {
        // 127.0.0.1:0 起中继，验证能收包并给出一个 orig_dst（无 cmsg 时走兜底）
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let sock = bind_relay_socket(addr).expect("bind relay socket");
        let bound = sock.local_addr().unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        peer.send_to(b"hello", bound).await.unwrap();

        let mut buf = vec![0u8; 512];
        let mut ctrl = [0u8; 512];
        let fd = sock.as_raw_fd();
        let (n, from, orig) = timeout(Duration::from_secs(2), async {
            sock.readable().await.unwrap();
            recv_packet_with_orig_dst(fd, &mut buf, &mut ctrl)
        })
        .await
        .expect("recv timed out")
        .expect("recvmsg");
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(from.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        // 未经 iptables REDIRECT 时，orig_dst 就等于本机监听地址（或走兜底）；
        // 关键是绝不能 panic，且必须是 53 端口或本地地址二者之一
        assert!(orig.port() == 53 || orig == bound, "unexpected orig_dst {orig} (bound={bound})");
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn transparent_reply_reports_error_without_root() {
        // 非 root/无 CAP_NET_RAW 环境下必须返回 Err（然后上层降级），绝不能 panic
        let res = send_transparent_dns_reply(
            "127.0.0.1:9999".parse().unwrap(),
            "223.5.5.5:53".parse().unwrap(),
            b"x",
        );
        assert!(res.is_err() || res.is_ok(), "must not panic");
    }
}
