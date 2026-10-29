use crate::config::ClientConfig;
use crate::outbound::{MuxKind, MuxTunnel};
use cns_core::crypto::CuteBiCipher;
use cns_core::protocol::{canonicalize_addr, UdpPacket};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::Interest;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tracing::{debug, trace};

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::unix::io::AsRawFd;

/// 透明代理劫持方式
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TproxyMode {
    /// iptables `-j REDIRECT --to-ports N`：原始目标只能靠 `SO_ORIGINAL_DST` 取
    Redirect,
    /// iptables `-j TPROXY` + `IP_TRANSPARENT`：`local_addr()` 本身就是原始目标
    Tproxy,
    /// 先试 SO_ORIGINAL_DST，失败再用 local_addr（兼容混合规则）
    Auto,
}

impl TproxyMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "redirect" => Some(Self::Redirect),
            "tproxy" => Some(Self::Tproxy),
            "auto" | "" => Some(Self::Auto),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Redirect => "redirect",
            Self::Tproxy => "tproxy",
            Self::Auto => "auto",
        }
    }
}

const SO_ORIGINAL_DST: libc::c_int = 80;
const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;

/// 判断是否为本机自连回环
#[inline]
fn is_loopback_self(addr: SocketAddr, listen_port: u16) -> bool {
    (addr.ip().is_loopback() || addr.ip().is_unspecified()) && addr.port() == listen_port
}

/// 取回被 iptables 劫持前的真实目标地址。
///
/// 修复要点：
/// 1. TPROXY 模式：`stream.local_addr()` 包含内核保留的真实目标地址。
///    仅当 local_addr 为本机回环/未指定 且 端口等于监听端口时拒绝自连；
///    如果目标是外部公网 IP，即使端口恰好等于 listen_port 也允许通过。
/// 2. REDIRECT 模式：严格通过 `getsockopt` 查 `SO_ORIGINAL_DST`（v4/v6）。
///    如果查不到明确返回 NotFound 错误，严禁回落成自连。
/// 3. AUTO 模式：先查 SO_ORIGINAL_DST，查不到再查 local_addr，最后兜底 peer_addr，
///    全链路严格防自连成环。
pub fn get_original_dst_with_mode(
    stream: &TcpStream,
    listen_port: u16,
    mode: TproxyMode,
) -> io::Result<SocketAddr> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let fd = stream.as_raw_fd();

        // 1. TPROXY+IP_TRANSPARENT：local_addr 就是原始目标，优先级最高
        if mode == TproxyMode::Tproxy {
            let local = stream.local_addr()?;
            if is_loopback_self(local, listen_port) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("TPROXY mode but local_addr is own listen port {listen_port}"),
                ));
            }
            if local.port() != 0 {
                return Ok(local);
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TPROXY mode but local_addr has port 0",
            ));
        }

        // 2. REDIRECT 模式：查 SO_ORIGINAL_DST
        if mode == TproxyMode::Redirect {
            if let Some(addr) = unsafe { getsockopt_original_dst_v4(fd) } {
                if is_loopback_self(addr, listen_port) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("SO_ORIGINAL_DST returned own listen port {listen_port}"),
                    ));
                }
                return Ok(addr);
            }
            if let Some(addr) = unsafe { getsockopt_original_dst_v6(fd) } {
                if is_loopback_self(addr, listen_port) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("SO_ORIGINAL_DST returned own listen port {listen_port}"),
                    ));
                }
                return Ok(addr);
            }
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "not a REDIRECT-ed connection (SO_ORIGINAL_DST unavailable)",
            ));
        }

        // 3. AUTO 模式：兼容混合规则
        if let Some(addr) = unsafe { getsockopt_original_dst_v4(fd) } {
            if !is_loopback_self(addr, listen_port) {
                return Ok(addr);
            }
        }
        if let Some(addr) = unsafe { getsockopt_original_dst_v6(fd) } {
            if !is_loopback_self(addr, listen_port) {
                return Ok(addr);
            }
        }

        if let Ok(local) = stream.local_addr() {
            if !is_loopback_self(local, listen_port) && local.port() != 0 {
                return Ok(local);
            }
        }

        let peer = stream.peer_addr()?;
        if is_loopback_self(peer, listen_port) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot determine original destination (loop risk)",
            ));
        }
        Ok(peer)
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = (listen_port, mode);
        stream.peer_addr()
    }
}

/// 兼容旧签名：Auto 模式
pub fn get_original_dst(stream: &TcpStream, listen_port: u16) -> io::Result<SocketAddr> {
    get_original_dst_with_mode(stream, listen_port, TproxyMode::Auto)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn getsockopt_original_dst_v4(fd: std::os::unix::io::RawFd) -> Option<SocketAddr> {
    let mut addr: libc::sockaddr_in = std::mem::zeroed();
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let ret = libc::getsockopt(
        fd,
        libc::SOL_IP,
        SO_ORIGINAL_DST,
        &mut addr as *mut _ as *mut libc::c_void,
        &mut len,
    );
    if ret != 0 {
        return None;
    }
    let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    if ip.is_unspecified() || port == 0 {
        return None;
    }
    Some(SocketAddr::new(std::net::IpAddr::V4(ip), port))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn getsockopt_original_dst_v6(fd: std::os::unix::io::RawFd) -> Option<SocketAddr> {
    let mut addr6: libc::sockaddr_in6 = std::mem::zeroed();
    let mut len6 = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
    let ret = libc::getsockopt(
        fd,
        libc::SOL_IPV6,
        IP6T_SO_ORIGINAL_DST,
        &mut addr6 as *mut _ as *mut libc::c_void,
        &mut len6,
    );
    if ret != 0 {
        return None;
    }
    let ip = std::net::Ipv6Addr::from(addr6.sin6_addr.s6_addr);
    let port = u16::from_be(addr6.sin6_port);
    if ip.is_unspecified() || port == 0 {
        return None;
    }
    Some(SocketAddr::new(std::net::IpAddr::V6(ip), port))
}

/// 切换进程 GID（配合 iptables `--gid-owner` 防回环）。
///
/// 必须同时降掉补充组，避免残留权限命中其它 owner 匹配规则；另外 GID 切换后
/// 无法恢复，所以要在建立任何监听 socket **之后**、真正开始服务之前调用。
pub fn apply_process_gid(gid: u32) -> io::Result<()> {
    #[cfg(unix)]
    unsafe {
        let cur = libc::getgid();
        if cur == gid as libc::gid_t {
            return Ok(());
        }
        if libc::setgid(gid as libc::gid_t) != 0 {
            return Err(io::Error::last_os_error());
        }
        // 清空补充组，避免残留权限命中其它 owner 匹配规则。
        libc::setgroups(0, std::ptr::null::<libc::gid_t>());
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// TPROXY UDP 透明代理实现
// ----------------------------------------------------------------------------

const UDP_SESSION_TTL: Duration = Duration::from_secs(180);
const UDP_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// 会话映射：隧道对端真实目标 (orig_dst) -> 最初发起的本地 App 地址 (client_addr)
#[derive(Clone)]
struct UdpTproxySessionMap {
    by_peer: Arc<Mutex<HashMap<SocketAddr, (SocketAddr, Instant)>>>,
}

impl UdpTproxySessionMap {
    fn new() -> Self {
        Self { by_peer: Arc::new(Mutex::new(HashMap::new())) }
    }

    fn bind(&self, orig_dst: SocketAddr, client_app: SocketAddr) {
        if let Ok(mut m) = self.by_peer.lock() {
            m.insert(canonicalize_addr(orig_dst), (client_app, Instant::now()));
        }
    }

    fn lookup(&self, orig_dst: SocketAddr) -> Option<SocketAddr> {
        let mut m = self.by_peer.lock().ok()?;
        let entry = m.get_mut(&canonicalize_addr(orig_dst))?;
        entry.1 = Instant::now();
        Some(entry.0)
    }

    fn evict_older_than(&self, age: Duration) -> usize {
        let cutoff = Instant::now() - age;
        match self.by_peer.lock() {
            Ok(mut m) => {
                let before = m.len();
                m.retain(|_, (_, t)| *t > cutoff);
                before - m.len()
            }
            Err(_) => 0,
        }
    }
}

/// UDP TPROXY 透明代理运行统计
#[derive(Default, Debug)]
pub struct UdpTproxyStats {
    pub from_client: AtomicU64,
    pub to_client: AtomicU64,
    pub dropped_loop: AtomicU64,
    pub dropped_unmapped: AtomicU64,
    pub tunnel_errors: AtomicU64,
}

/// 通用 UDP 透明代理处理器。
///
/// 在 TPROXY 模式下拦截客户端发往任意远程主机的 UDP 数据包：
/// 1. 通过 `IP_RECVORIGDSTADDR` 提取真实目的地址 (`orig_dst`)；
/// 2. 封装为 `httpUDP` 帧走复用隧道发往 CNS 服务端；
/// 3. 服务端回包时，通过开启了 `IP_TRANSPARENT` 的 socket，以 `orig_dst` 作为伪装源地址发回给客户端。
pub struct UdpTproxyRelay {
    config: Arc<ClientConfig>,
    cipher: Arc<CuteBiCipher>,
    tunnel: Mutex<Option<MuxTunnel>>,
    sessions: UdpTproxySessionMap,
    stats: Arc<UdpTproxyStats>,
    listen_port: u16,
}

impl UdpTproxyRelay {
    pub fn new(config: Arc<ClientConfig>, cipher: Arc<CuteBiCipher>, listen_port: u16) -> Arc<Self> {
        Arc::new(Self {
            config,
            cipher,
            tunnel: Mutex::new(None),
            sessions: UdpTproxySessionMap::new(),
            stats: Arc::new(UdpTproxyStats::default()),
            listen_port,
        })
    }

    pub fn stats(&self) -> &Arc<UdpTproxyStats> {
        &self.stats
    }

    /// 建立/复用 httpUDP 隧道，并驱动入向回包分发
    async fn ensure_tunnel(&self) -> io::Result<MuxTunnel> {
        if let Some(t) = self.tunnel.lock().ok().and_then(|g| g.clone()) {
            if t.is_alive() {
                return Ok(t);
            }
        }

        let (tx, mut rx) = mpsc::unbounded_channel::<UdpPacket>();
        let tunnel =
            MuxTunnel::open(&self.config, &self.cipher, MuxKind::Udp, "", Some(tx)).await?;

        let sessions = self.sessions.clone();
        let stats = Arc::clone(&self.stats);
        let label = tunnel.label().to_string();

        tokio::spawn(async move {
            while let Some(pkt) = rx.recv().await {
                let orig_dst = pkt.peer;
                let Some(client_app) = sessions.lookup(orig_dst) else {
                    stats.dropped_unmapped.fetch_add(1, Ordering::Relaxed);
                    trace!("[{label}] no client mapping for reply from orig_dst {orig_dst}");
                    continue;
                };

                // 核心：源地址伪装回包（利用 IP_TRANSPARENT bind orig_dst）
                match send_transparent_udp_reply(orig_dst, client_app, &pkt.payload) {
                    Ok(()) => {
                        stats.to_client.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        debug!("transparent UDP reply from {orig_dst} to {client_app} failed: {e}");
                    }
                }
            }
        });

        if let Ok(mut g) = self.tunnel.lock() {
            *g = Some(tunnel.clone());
        }
        Ok(tunnel)
    }

    /// 在指定的 UDP 监听 socket 上运行接收循环
    pub async fn run_loop_with_socket(self: Arc<Self>, socket: Arc<UdpSocket>) -> io::Result<()> {
        let listen_addr = socket.local_addr()?;
        debug!("UDP tproxy relay active on {listen_addr} (orig-dst capture enabled)");

        let mut buf = vec![0u8; 65535];
        let mut ctrl_buf = [0u8; 1024];
        let mut sweep = tokio::time::interval(UDP_SWEEP_INTERVAL);
        sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            // 一次唤醒内把内核队列抽干（最多 64 包，保证 sweep 不会被饿死）。
            //
            // 必须走 `try_io`：readiness 位只有在 try_io 观察到 WouldBlock 时才被
            // tokio 清掉。旧实现用 `readable()` + 裸 recvmsg(MSG_DONTWAIT)，第一个包
            // 之后 readiness 恒为 Ready，于是「readable→EAGAIN→continue」纯自旋，
            // 一个 worker 线程永远不再让出（表现为 tproxy 模式一发 UDP 就 100% CPU）。
            let mut drained = 0usize;
            while drained < 64 {
                #[cfg(any(target_os = "linux", target_os = "android"))]
                let raw_fd = socket.as_raw_fd();
                #[cfg(not(any(target_os = "linux", target_os = "android")))]
                let raw_fd = 0;

                let recv = socket.try_io(Interest::READABLE, || {
                    recv_udp_with_orig_dst(raw_fd, &mut buf, &mut ctrl_buf)
                });

                let (len, client_peer, orig_dst) = match recv {
                    Ok(v) => v,
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        debug!("UDP tproxy recv error: {e}");
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        break;
                    }
                };
                drained += 1;

                // 防回环：若原始目标依然是本机监听端口，丢弃
                if is_loopback_self(orig_dst, self.listen_port) || orig_dst.port() == 0 {
                    self.stats.dropped_loop.fetch_add(1, Ordering::Relaxed);
                    continue;
                }

                let payload = buf[..len].to_vec();
                self.stats.from_client.fetch_add(1, Ordering::Relaxed);
                self.sessions.bind(orig_dst, client_peer);

                let relay = Arc::clone(&self);
                tokio::spawn(async move {
                    if let Err(e) = relay.forward_udp(orig_dst, &payload).await {
                        relay.stats.tunnel_errors.fetch_add(1, Ordering::Relaxed);
                        debug!("UDP tproxy forward to {orig_dst} error: {e}");
                    }
                });
            }

            if drained >= 64 {
                continue; // 仍有积压，先继续抽包，下一轮再处理 sweep tick
            }

            tokio::select! {
                _ = sweep.tick() => {
                    self.sessions.evict_older_than(UDP_SESSION_TTL);
                }
                res = socket.readable() => {
                    if let Err(e) = res {
                        debug!("UDP tproxy socket readable wait error: {e}");
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }
            }
        }
    }

    async fn forward_udp(&self, orig_dst: SocketAddr, payload: &[u8]) -> io::Result<()> {
        let tunnel = self.ensure_tunnel().await?;
        tunnel.udp_send(orig_dst, payload)
    }
}

/// 底层通过 recvmsg 读取数据包及 IP_ORIGDSTADDR / IPV6_ORIGDSTADDR 控制数据
#[cfg(any(target_os = "linux", target_os = "android"))]
fn recv_udp_with_orig_dst(
    raw_fd: std::os::unix::io::RawFd,
    buf: &mut [u8],
    ctrl_buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    let mut iov =
        libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: buf.len() };
    let mut src_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };

    let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
    msghdr.msg_name = &mut src_storage as *mut _ as *mut libc::c_void;
    msghdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msghdr.msg_iov = &mut iov;
    msghdr.msg_iovlen = 1;
    msghdr.msg_control = ctrl_buf.as_mut_ptr() as *mut libc::c_void;
    msghdr.msg_controllen = ctrl_buf.len() as _;
    msghdr.msg_flags = 0;

    let n = unsafe { libc::recvmsg(raw_fd, &mut msghdr, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    let peer = unsafe { parse_sockaddr_storage(&src_storage) }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad client sockaddr"))?;

    let fallback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let orig_dst = unsafe { parse_cmsg_orig_dst(&msghdr) }.unwrap_or(fallback);

    Ok((n as usize, peer, orig_dst))
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn recv_udp_with_orig_dst(
    _raw_fd: i32,
    _buf: &mut [u8],
    _ctrl_buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported OS"))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn parse_sockaddr_storage(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
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

#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn parse_cmsg_orig_dst(msghdr: &libc::msghdr) -> Option<SocketAddr> {
    let mut cmsg = libc::CMSG_FIRSTHDR(msghdr);
    while !cmsg.is_null() {
        let cm = &*cmsg;
        // IPv4: IP_ORIGDSTADDR
        if cm.cmsg_level == libc::IPPROTO_IP && cm.cmsg_type == libc::IP_ORIGDSTADDR {
            let sin = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in;
            if !sin.is_null() {
                let ip = Ipv4Addr::from((*sin).sin_addr.s_addr.to_ne_bytes());
                let port = u16::from_be((*sin).sin_port);
                return Some(SocketAddr::V4(SocketAddrV4::new(ip, port)));
            }
        }
        // IPv6: IPV6_ORIGDSTADDR (=74)
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

/// 源地址伪装回包：在 socket 上开启 `IP_TRANSPARENT`，bind `orig_dst` 后发回客户端
pub fn send_transparent_udp_reply(
    orig_dst: SocketAddr,
    client: SocketAddr,
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

        // 与 DNS 回包同理：目标口可能就是本机自己占着的监听口，没有 SO_REUSEADDR
        // 就会 EADDRINUSE 而整包回不去。
        let _ = sock.set_reuse_address(true);

        unsafe {
            let fd = sock.as_raw_fd();
            let one: libc::c_int = 1;
            const IPV6_TRANSPARENT_OPT: libc::c_int = 75;
            let (level, optname) = match orig_dst {
                SocketAddr::V4(_) => (libc::SOL_IP, libc::IP_TRANSPARENT),
                SocketAddr::V6(_) => (libc::IPPROTO_IPV6, IPV6_TRANSPARENT_OPT),
            };
            let ret = libc::setsockopt(
                fd,
                level,
                optname,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of_val(&one) as libc::socklen_t,
            );
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
        }

        sock.bind(&orig_dst.into())
            .map_err(|e| io::Error::new(e.kind(), format!("bind {orig_dst}: {e}")))?;
        sock.set_nonblocking(true)?;

        send_to_client(sock.as_raw_fd(), payload, client)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = (orig_dst, client, payload);
        Err(io::Error::new(io::ErrorKind::Unsupported, "transparent reply needs linux/android"))
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn send_to_client(fd: std::os::unix::io::RawFd, payload: &[u8], client: SocketAddr) -> io::Result<()> {
    #[repr(C)]
    union SockAddrAny {
        storage: libc::sockaddr_storage,
        v4: libc::sockaddr_in,
        v6: libc::sockaddr_in6,
    }

    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match client {
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
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn connected_pair() -> (TcpStream, TcpStream, SocketAddr) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let a = TcpStream::connect(addr).await.unwrap();
        let (b, _) = listener.accept().await.unwrap();
        (a, b, addr)
    }

    #[test]
    fn mode_parsing() {
        assert_eq!(TproxyMode::parse("redirect"), Some(TproxyMode::Redirect));
        assert_eq!(TproxyMode::parse("TPROXY"), Some(TproxyMode::Tproxy));
        assert_eq!(TproxyMode::parse(" auto "), Some(TproxyMode::Auto));
        assert_eq!(TproxyMode::parse(""), Some(TproxyMode::Auto));
        assert_eq!(TproxyMode::parse("magic"), None);
        assert_eq!(TproxyMode::Tproxy.as_str(), "tproxy");
    }

    #[tokio::test]
    async fn unredirected_connection_never_targets_own_listen_port() {
        let (client, _server, listen_addr) = connected_pair().await;
        let port = listen_addr.port();

        let res = get_original_dst_with_mode(&client, port, TproxyMode::Auto);
        match res {
            Ok(addr) => {
                assert_ne!(addr.port(), port, "returned own listen port => forwarding loop")
            }
            Err(e) => {
                assert_ne!(e.kind(), io::ErrorKind::Unsupported, "should not be unsupported");
            }
        }

        match get_original_dst_with_mode(&client, port, TproxyMode::Redirect) {
            Ok(addr) => panic!("must refuse self-target, got {addr}"),
            Err(e) => assert!(
                matches!(e.kind(), io::ErrorKind::InvalidInput | io::ErrorKind::NotFound),
                "unexpected error kind {:?}",
                e.kind()
            ),
        }
    }

    #[tokio::test]
    async fn tproxy_mode_reads_local_addr() {
        let (client, server, listen_addr) = connected_pair().await;
        let port = listen_addr.port();
        // server 端直连未被透明代理改写时，local_addr 恰为 127.0.0.1:port，必须被拒绝防回环
        let res = get_original_dst_with_mode(&server, port, TproxyMode::Tproxy);
        assert!(
            res.is_err(),
            "tproxy mode must refuse self-target loopback connection on server stream"
        );

        // client 端本地端口非监听端口，模拟已被 TPROXY 改写的原始目的地址
        let res_client = get_original_dst_with_mode(&client, port, TproxyMode::Tproxy);
        assert!(res_client.is_ok());
    }

    #[tokio::test]
    async fn legacy_wrapper_still_works() {
        let (client, _, _) = connected_pair().await;
        let addr = get_original_dst(&client, 1).unwrap();
        assert!(addr.port() != 0);
    }

    #[test]
    fn gid_helper_is_call_safe() {
        #[cfg(unix)]
        unsafe {
            let my_gid = libc::getgid() as u32;
            let r = apply_process_gid(my_gid);
            assert!(r.is_ok());

            if libc::geteuid() == 0 {
                let r0 = apply_process_gid(0);
                assert!(r0.is_ok());
            }
        }
    }

    #[tokio::test]
    async fn connected_pair_sanity() {
        let (mut a, mut b, _) = connected_pair().await;
        a.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[test]
    fn loopback_self_detection() {
        let listen_port = 7750;
        // 127.0.0.1:7750 是自连
        assert!(is_loopback_self("127.0.0.1:7750".parse().unwrap(), listen_port));
        // 0.0.0.0:7750 是自连
        assert!(is_loopback_self("0.0.0.0:7750".parse().unwrap(), listen_port));
        // [::1]:7750 是自连
        assert!(is_loopback_self("[::1]:7750".parse().unwrap(), listen_port));
        // [::]:7750 是自连
        assert!(is_loopback_self("[::]:7750".parse().unwrap(), listen_port));

        // 外部公网 IP：即使端口偶然等于 7750 也不算自连
        assert!(!is_loopback_self("1.2.3.4:7750".parse().unwrap(), listen_port));
        // 回环 IP 但端口不是 7750：算外部/其他服务
        assert!(!is_loopback_self("127.0.0.1:80".parse().unwrap(), listen_port));
    }

    #[test]
    fn udp_tproxy_session_map_lifecycle() {
        let sessions = UdpTproxySessionMap::new();
        let orig_dst: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let client_app: SocketAddr = "127.0.0.1:54321".parse().unwrap();

        assert_eq!(sessions.lookup(orig_dst), None);
        sessions.bind(orig_dst, client_app);
        assert_eq!(sessions.lookup(orig_dst), Some(client_app));

        // 清理超过 1 小时的会话（当前会话不被清理）
        let evicted = sessions.evict_older_than(Duration::from_secs(3600));
        assert_eq!(evicted, 0);
        assert_eq!(sessions.lookup(orig_dst), Some(client_app));

        // 立即过期
        let evicted_now = sessions.evict_older_than(Duration::from_millis(0));
        assert_eq!(evicted_now, 1);
        assert_eq!(sessions.lookup(orig_dst), None);
    }
}
