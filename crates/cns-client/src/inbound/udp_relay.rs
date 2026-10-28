//! SOCKS5 UDP ASSOCIATE -> httpUDP 隧道。
//!
//! 旧版状态：`render_udp_header()` 定义了却**从未被调用**，SOCKS5 UDP ASSOCIATE
//! 只 `warn!` 一句就把连接丢掉；服务端的 `UdpTunnel` 因此成了只有老 clnc 能触达的
//! 死代码路径。免流场景下 UDP 只有 53 端口在网关侧通，且 53 还有严格网关限制，
//! 所以 UDP 只能与隧道一起走 —— 这个 relay 就是那条路。

use crate::config::ClientConfig;
use crate::inbound::socks5::{parse_socks5_udp, wrap_socks5_udp};
use crate::outbound::{MuxKind, MuxTunnel};
use cns_core::crypto::CuteBiCipher;
use cns_core::protocol::{canonicalize_addr, UdpPacket};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::debug;

/// 空闲多久后回收会话/登记
const SESSION_TTL: Duration = Duration::from_secs(180);
/// 扫描周期
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// 已登记 ASSOCIATE 的 App **地址（按 IP）** 集合。
///
/// 没有这张表，本 relay 就成了任意人可用的 UDP 反射器（SOCKS5 UDP 无认证时是真实
/// 的滥用面）。只有先在同一 TCP 连接上做过 UDP ASSOCIATE 的来源才允许发数据报。
///
/// 为什么按 IP 而不是 `IP:port`：App 的 UDP 数据报源端口与它做 ASSOCIATE 的 TCP
/// 控制连接端口**必然不同**（RFC 1928 也允许客户端用任意源端口发），按
/// `IP:port` 精确匹配会把所有正常客户端一律拒掉。因此登记与校验都只看 IP；
/// 回包目标则由 `SessionMap` 按「隧道对端 -> 最近一次发数据报的完整地址」记录。
#[derive(Clone, Default)]
pub struct UdpAssociates {
    allowed: Arc<Mutex<HashMap<IpAddr, Instant>>>,
}

impl UdpAssociates {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allow(&self, app: SocketAddr) {
        if let Ok(mut m) = self.allowed.lock() {
            m.insert(app.ip(), Instant::now());
        }
    }

    pub fn is_allowed(&self, app: SocketAddr) -> bool {
        // 同时刷新时间戳，活跃的 App 不该被回收
        if let Ok(mut m) = self.allowed.lock() {
            if let Some(t) = m.get_mut(&app.ip()) {
                *t = Instant::now();
                return true;
            }
        }
        false
    }

    pub fn evict_older_than(&self, age: Duration) -> usize {
        let cutoff = Instant::now() - age;
        match self.allowed.lock() {
            Ok(mut m) => {
                let before = m.len();
                m.retain(|_, t| *t > cutoff);
                before - m.len()
            }
            Err(_) => 0,
        }
    }

    /// 控制连接断开时解除登记，避免遗留地址被长期复用
    pub fn revoke(&self, app: SocketAddr) {
        if let Ok(mut m) = self.allowed.lock() {
            m.remove(&app.ip());
        }
    }

    pub fn len(&self) -> usize {
        self.allowed.lock().map(|m| m.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// 会话映射：隧道对端 -> 最初发起的 App 地址（回包靠它找路）
#[derive(Clone)]
struct SessionMap {
    by_peer: Arc<Mutex<HashMap<SocketAddr, SocketAddr>>>,
}

impl SessionMap {
    fn new() -> Self {
        Self { by_peer: Arc::new(Mutex::new(HashMap::new())) }
    }

    fn bind(&self, peer: SocketAddr, app: SocketAddr) {
        if let Ok(mut m) = self.by_peer.lock() {
            m.insert(canonicalize_addr(peer), app);
        }
    }

    fn lookup(&self, peer: SocketAddr) -> Option<SocketAddr> {
        self.by_peer.lock().ok().and_then(|m| m.get(&canonicalize_addr(peer)).copied())
    }

    fn evict_older_than(&self, _age: Duration) -> usize {
        // 本表以「隧道对端」为键，没有独立时间戳；随 relay 会话整体回收
        0
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.by_peer.lock().map(|m| m.len()).unwrap_or(0)
    }
}

#[derive(Default, Debug)]
pub struct UdpRelayStats {
    pub from_app: AtomicU64,
    pub to_app: AtomicU64,
    pub rejected: AtomicU64,
    pub tunnel_errors: AtomicU64,
    pub dropped_unmapped: AtomicU64,
}

pub struct UdpRelay {
    config: Arc<ClientConfig>,
    cipher: Arc<CuteBiCipher>,
    tunnel: Mutex<Option<MuxTunnel>>,
    sessions: SessionMap,
    associates: UdpAssociates,
    bind_addr: Mutex<SocketAddr>,
    stats: Arc<UdpRelayStats>,
}

impl UdpRelay {
    /// `bind_addr` 为 0 端口时，实际地址由 `run()` 绑定后通过 `bound_addr()` 读取
    pub fn new(
        config: Arc<ClientConfig>,
        cipher: Arc<CuteBiCipher>,
        bind_addr: SocketAddr,
        associates: UdpAssociates,
    ) -> Arc<Self> {
        Arc::new(Self {
            config,
            cipher,
            tunnel: Mutex::new(None),
            sessions: SessionMap::new(),
            associates,
            bind_addr: Mutex::new(bind_addr),
            stats: Arc::new(UdpRelayStats::default()),
        })
    }

    pub fn stats(&self) -> &Arc<UdpRelayStats> {
        &self.stats
    }

    /// 实际（或配置）的监听地址，用于 SOCKS5 回复里的 BND.ADDR
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr.lock().map(|a| *a).unwrap_or_else(|_| ([127, 0, 0, 1], 0).into())
    }

    /// 建立/复用 httpUDP 隧道，并把入向数据报接回 App
    async fn ensure_tunnel(&self, sock: &Arc<UdpSocket>) -> io::Result<MuxTunnel> {
        if let Some(t) = self.tunnel.lock().ok().and_then(|g| g.clone()) {
            if t.is_alive() {
                return Ok(t);
            }
        }

        let (tx, mut rx) = mpsc::unbounded_channel::<UdpPacket>();
        let tunnel =
            MuxTunnel::open(&self.config, &self.cipher, MuxKind::Udp, "", Some(tx)).await?;

        // 入向：隧道 -> App（按会话映射回投）
        let sessions = self.sessions.clone();
        let stats = Arc::clone(&self.stats);
        let label = tunnel.label().to_string();
        let sock = Arc::clone(sock);
        tokio::spawn(async move {
            while let Some(pkt) = rx.recv().await {
                let Some(app) = sessions.lookup(pkt.peer) else {
                    stats.dropped_unmapped.fetch_add(1, Ordering::Relaxed);
                    debug!("[{label}] no app bound for peer {}", pkt.peer);
                    continue;
                };
                let framed = wrap_socks5_udp(pkt.peer, &pkt.payload);
                match sock.try_send_to(&framed, app) {
                    Ok(_) => {
                        stats.to_app.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => debug!("udp relay send to {app} failed: {e}"),
                }
            }
        });

        if let Ok(mut g) = self.tunnel.lock() {
            *g = Some(tunnel.clone());
        }
        Ok(tunnel)
    }

    /// 绑定并进入主循环
    pub async fn run(self: Arc<Self>) -> io::Result<()> {
        let sock = Arc::new(UdpSocket::bind(self.bind_addr()).await?);
        if let Ok(mut a) = self.bind_addr.lock() {
            *a = sock.local_addr()?;
        }
        debug!("SOCKS5 UDP relay listening on {}", self.bind_addr());
        self.run_with_socket(sock).await
    }

    /// 用外部已绑定的 socket 跑主循环（测试与端口复用场景）
    pub async fn run_with_socket(self: Arc<Self>, sock: Arc<UdpSocket>) -> io::Result<()> {
        if let Ok(mut a) = self.bind_addr.lock() {
            *a = sock.local_addr()?;
        }
        let mut buf = vec![0u8; 65535];
        let mut sweep = tokio::time::interval(SWEEP_INTERVAL);
        sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                res = sock.recv_from(&mut buf) => {
                    let (n, app) = match res {
                        Ok(v) => v,
                        Err(e) => {
                            debug!("udp relay recv error: {e}");
                            continue;
                        }
                    };
                    let relay = Arc::clone(&self);
                    let s = Arc::clone(&sock);
                    let data = buf[..n].to_vec();
                    tokio::spawn(async move {
                        if let Err(e) = relay.forward(s, app, &data).await {
                            debug!("udp relay dropped packet from {app}: {e}");
                        }
                    });
                }
                _ = sweep.tick() => {
                    let n = self.associates.evict_older_than(SESSION_TTL);
                    if n > 0 {
                        debug!("udp relay evicted {n} idle associates");
                    }
                    self.sessions.evict_older_than(SESSION_TTL);
                }
            }
        }
    }

    async fn forward(
        self: &Arc<Self>,
        sock: Arc<UdpSocket>,
        app: SocketAddr,
        data: &[u8],
    ) -> io::Result<()> {
        if !self.associates.is_allowed(app) {
            self.stats.rejected.fetch_add(1, Ordering::Relaxed);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("no UDP ASSOCIATE registered for {app}"),
            ));
        }

        let req = parse_socks5_udp(data)?;
        self.stats.from_app.fetch_add(1, Ordering::Relaxed);
        self.sessions.bind(req.target, app);

        let tunnel = self.ensure_tunnel(&sock).await.inspect_err(|_| {
            self.stats.tunnel_errors.fetch_add(1, Ordering::Relaxed);
            // 失败即丢弃隧道句柄，下次重建
            if let Ok(mut g) = self.tunnel.lock() {
                *g = None;
            }
        })?;

        tunnel.udp_send(req.target, &req.data).inspect_err(|_| {
            self.stats.tunnel_errors.fetch_add(1, Ordering::Relaxed);
            tunnel.close();
            if let Ok(mut g) = self.tunnel.lock() {
                *g = None;
            }
        })
    }
}

/// 供 SOCKS5 handler 登记一个 UDP ASSOCIATE
pub fn register_associate(associates: &UdpAssociates, app: SocketAddr) {
    associates.allow(app);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::timeout;
    use tokio_util::codec::{Decoder, Encoder};

    fn cfg(server: SocketAddr) -> Arc<ClientConfig> {
        Arc::new(ClientConfig {
            socks5_listen: String::new(),
            dns_listen: String::new(),
            cns_server: server.to_string(),
            cns_password: "mux-test-key".to_string(),
            timeout_seconds: 5,
            enable_tfo: false,
            ..Default::default()
        })
    }

    #[test]
    fn associate_allowlist_is_ip_scoped() {
        let ctl: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        // App 的 UDP 源端口与 TCP 控制端口不同 —— 这是真实客户端的常态
        let udp_src: SocketAddr = "127.0.0.1:5001".parse().unwrap();
        let foreign: SocketAddr = "10.0.0.9:5001".parse().unwrap();

        let a = UdpAssociates::new();
        assert!(!a.is_allowed(ctl));
        register_associate(&a, ctl);
        assert!(a.is_allowed(ctl));
        assert!(
            a.is_allowed(udp_src),
            "同一 IP 的不同 UDP 源端口必须被接受，否则所有真实客户端都被拒"
        );
        assert!(!a.is_allowed(foreign));
        assert_eq!(a.len(), 1);
        assert!(!a.is_empty());

        a.revoke(ctl);
        assert!(!a.is_allowed(udp_src), "解除登记后必须拒绝");
    }

    #[test]
    fn associate_eviction_is_time_based() {
        let a = UdpAssociates::new();
        let app: SocketAddr = "127.0.0.1:6000".parse().unwrap();
        a.allow(app);
        assert_eq!(a.evict_older_than(Duration::from_secs(60)), 0);
        // 人为制造过期
        if let Ok(mut m) = a.allowed.lock() {
            if let Some(t) = m.get_mut(&app.ip()) {
                *t = Instant::now() - Duration::from_secs(3600);
            }
        }
        assert_eq!(a.evict_older_than(Duration::from_secs(60)), 1);
        assert!(!a.is_allowed(app));
        assert!(a.is_empty());
    }

    #[test]
    fn session_map_canonicalizes_mapped_peers() {
        let m = SessionMap::new();
        let app: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        m.bind("[::ffff:203.0.113.9]:53".parse().unwrap(), app);
        // 用纯 v4 形式查询必须命中（隧道回来的帧里是 v4）
        assert_eq!(m.lookup("203.0.113.9:53".parse().unwrap()), Some(app));
        assert_eq!(m.len(), 1);
    }

    #[tokio::test]
    async fn forward_rejects_unregistered_source() {
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let relay = UdpRelay::new(
            cfg("127.0.0.1:1".parse().unwrap()),
            Arc::new(CuteBiCipher::new(b"k")),
            bind,
            UdpAssociates::new(),
        );
        let sock = Arc::new(UdpSocket::bind(bind).await.unwrap());
        let app: SocketAddr = "127.0.0.1:4000".parse().unwrap();

        let err = relay.forward(sock, app, &[0, 0, 0, 0x01]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(relay.stats().rejected.load(Ordering::Relaxed), 1);
        assert_eq!(relay.stats().from_app.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn forward_rejects_malformed_frame() {
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let app: SocketAddr = "127.0.0.1:4001".parse().unwrap();
        let assoc = UdpAssociates::new();
        assoc.allow(app);
        let relay = UdpRelay::new(
            cfg("127.0.0.1:1".parse().unwrap()),
            Arc::new(CuteBiCipher::new(b"k")),
            bind,
            assoc,
        );
        let sock = Arc::new(UdpSocket::bind(bind).await.unwrap());
        assert!(relay.forward(sock, app, &[0, 0]).await.is_err());
        // 解析失败不计入 from_app
        assert_eq!(relay.stats().from_app.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn forward_surfaces_tunnel_failure_and_clears_handle() {
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let app: SocketAddr = "127.0.0.1:4002".parse().unwrap();
        let assoc = UdpAssociates::new();
        assoc.allow(app);
        let relay = UdpRelay::new(
            cfg("127.0.0.1:1".parse().unwrap()),
            Arc::new(CuteBiCipher::new(b"k")),
            bind,
            assoc,
        );
        let sock = Arc::new(UdpSocket::bind(bind).await.unwrap());

        let mut pkt = vec![0, 0, 0, 0x01];
        pkt.extend_from_slice(&[1, 1, 1, 1]);
        pkt.extend_from_slice(&53u16.to_be_bytes());
        pkt.extend_from_slice(b"query");

        let res = timeout(Duration::from_secs(8), relay.forward(sock, app, &pkt)).await;
        assert!(res.expect("must not hang").is_err());
        assert_eq!(relay.stats().from_app.load(Ordering::Relaxed), 1);
        assert!(relay.stats().tunnel_errors.load(Ordering::Relaxed) >= 1);
        assert!(relay.tunnel.lock().unwrap().is_none(), "dead handle must be cleared");
        // 会话映射在发送前已登记（否则回包无处可投）
        assert!(relay.sessions.lookup("1.1.1.1:53".parse().unwrap()).is_some());
    }

    /// 完整链路：App -> relay -> httpUDP 隧道 -> 假 CNS -> UDP 目标 -> 原路返回
    #[tokio::test]
    async fn end_to_end_datagram_roundtrip() {
        // 1. 真实 UDP 回显目标
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            while let Ok((n, from)) = echo.recv_from(&mut b).await {
                let _ = echo.send_to(&b[..n], from).await;
            }
        });

        // 2. 假 CNS 服务端：解 httpUDP 帧 -> 转发 -> 回帧
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cns_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            let mut acc: Vec<u8> = Vec::new();
            let mut t = [0u8; 512];
            loop {
                let n = s.read(&mut t).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                acc.extend_from_slice(&t[..n]);
                if acc.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").await;

            let cipher = CuteBiCipher::new(b"mux-test-key");
            let out = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut inbuf = bytes::BytesMut::new();
            let (mut in_sub, mut out_sub) = (0usize, 0usize);
            let mut codec = cns_core::protocol::HttpUdpCodec::new();

            loop {
                let mut r = [0u8; 4096];
                let n = match s.read(&mut r).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                let mut chunk = r[..n].to_vec();
                in_sub = cipher.crypt_in_place(&mut chunk, in_sub);
                inbuf.extend_from_slice(&chunk);
                while let Ok(Some(pkt)) = codec.decode(&mut inbuf) {
                    if out.send_to(&pkt.payload, pkt.peer).await.is_err() {
                        return;
                    }
                    let mut rb = [0u8; 2048];
                    if let Ok((m, from)) = out.recv_from(&mut rb).await {
                        let mut enc = bytes::BytesMut::new();
                        if codec
                            .encode(
                                UdpPacket {
                                    peer: canonicalize_addr(from),
                                    payload: rb[..m].to_vec().into(),
                                },
                                &mut enc,
                            )
                            .is_err()
                        {
                            return;
                        }
                        let mut wire = enc.to_vec();
                        out_sub = cipher.crypt_in_place(&mut wire, out_sub);
                        if s.write_all(&wire).await.is_err() {
                            return;
                        }
                    }
                }
            }
        });

        // 3. App 侧 UDP socket + 登记的 associate
        let app_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let app_addr = app_sock.local_addr().unwrap();
        let assoc = UdpAssociates::new();
        assoc.allow(app_addr);

        // 4. relay 预绑定，拿到真实端口后再交给 run_with_socket
        let pre = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = pre.local_addr().unwrap();
        let relay_sock = Arc::new(pre);
        let relay = UdpRelay::new(
            cfg(cns_addr),
            Arc::new(CuteBiCipher::new(b"mux-test-key")),
            relay_addr,
            assoc,
        );
        let runner = Arc::clone(&relay);
        let sock_for_run = Arc::clone(&relay_sock);
        tokio::spawn(async move {
            let _ = runner.run_with_socket(sock_for_run).await;
        });
        tokio::time::sleep(Duration::from_millis(60)).await;

        // 5. App -> relay -> 隧道 -> 目标 -> 原路回 App
        app_sock
            .send_to(&wrap_socks5_udp(echo_addr, b"udp-over-tunnel"), relay_addr)
            .await
            .unwrap();

        let mut resp = vec![0u8; 2048];
        let (n, from) = timeout(Duration::from_secs(8), app_sock.recv_from(&mut resp))
            .await
            .expect("no reply through tunnel")
            .expect("recv");
        assert_eq!(from, relay_addr);
        let back = parse_socks5_udp(&resp[..n]).expect("valid socks5 udp reply");
        assert_eq!(back.target, echo_addr);
        assert_eq!(&back.data, b"udp-over-tunnel");

        let s = relay.stats();
        assert_eq!(s.from_app.load(Ordering::Relaxed), 1);
        assert_eq!(s.to_app.load(Ordering::Relaxed), 1);
        assert_eq!(s.tunnel_errors.load(Ordering::Relaxed), 0);
        assert_eq!(s.dropped_unmapped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn bind_addr_is_exposed_for_bnd_reply() {
        let bind: SocketAddr = SocketAddr::from((Ipv4Addr::LOCALHOST, 1081));
        let relay = UdpRelay::new(
            Arc::new(ClientConfig::default()),
            Arc::new(CuteBiCipher::empty()),
            bind,
            UdpAssociates::new(),
        );
        assert_eq!(relay.bind_addr(), bind);
        assert!(relay.tunnel.lock().unwrap().is_none());
    }
}
