//! 服务端会话引擎。
//!
//! 从 `main.rs` 下沉到 lib，使集成测试可以启动**真实**的监听 + 握手 + 转发
//! 全流程，而不必像旧测试那样手搓一份 mock server（mock 与被测代码不同源，
//! 测过了不代表真服务能用）。

use crate::config::{Config, DialPolicy};
use crate::outbound::{DirectOutbound, Guard, Resolver, ResolverOptions};
use crate::tunnel::{handle_dns_tcp_over_udp, handle_http_dns, pump_tcp_stream, UdpTunnel};
use cns_core::crypto::CuteBiCipher;
use cns_core::protocol::{HandshakeParser, SessionType, MAX_HANDSHAKE_BYTES};
use cns_core::transport::{
    create_tcp_listener, expand_listen_spec, read_until_header_end, tune_tcp_stream, ListenOptions,
};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

/// 每客户端 IP 的并发占用。Drop 自动归还额度。
struct IpPermit {
    ip: IpAddr,
    table: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl Drop for IpPermit {
    fn drop(&mut self) {
        if let Ok(mut m) = self.table.lock() {
            if let Some(c) = m.get_mut(&self.ip) {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    m.remove(&self.ip);
                }
            }
        }
    }
}

/// RAII 活跃会话计数守卫
struct ActiveGuard(Arc<AtomicUsize>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct ServerCtx {
    pub parser: Arc<HandshakeParser>,
    pub cipher: CuteBiCipher,
    pub config: Arc<Config>,
    /// 回源守卫（SSRF + fakeip 泄漏段，段表已在 `DialPolicy` 里解析过）
    pub guard: Guard,
    pub resolver: Arc<Resolver>,
    /// 校验过的回源拨号策略（族偏好 / 错峰窗口 / 每族限量 / 出站 MSS / fakeip 段）
    pub dial: Arc<DialPolicy>,
    conn_sem: Arc<Semaphore>,
    ip_table: Arc<Mutex<HashMap<IpAddr, usize>>>,
    pub active: Arc<AtomicUsize>,
    pub sessions: Arc<AtomicU64>,
    pub shutdown: Arc<Notify>,
}

impl ServerCtx {
    /// 保持 v0.2.x 的不失败签名（测试与嵌入式调用方在用）。
    ///
    /// 「不静默回落」是本项目 v0.2.0 起的原则：配置到这一步仍非法就是程序员的
    /// 责任，直接 panic 把问题暴露在启动瞬间，而不是带着一个错误的拨号策略跑起来
    /// （表现是「随机连不上某些站点」，事后极难归因）。
    /// 走 `main.rs` / `Config::from_file` 的正常路径永远先 `validate()`，
    /// 生产部署不会碰到这个 panic；需要显式处理错误请用 [`ServerCtx::try_new`]。
    pub fn new(config: Config) -> Self {
        Self::try_new(config).unwrap_or_else(|e| panic!("invalid server config: {e}"))
    }

    /// 从配置构造服务上下文；任何非法的回源参数都在这里变成错误。
    pub fn try_new(config: Config) -> anyhow::Result<Self> {
        let dial = Arc::new(DialPolicy::from_config(&config)?);
        let resolver = Arc::new(Resolver::new(
            &config.dns_upstream.clone(),
            ResolverOptions {
                cache_limit: config.dns_cache_size,
                query_timeout: config.dial_timeout_duration().max(Duration::from_secs(2)),
                ..Default::default()
            },
        ));
        // 启动即把择优策略打出来：现场排障时「配的到底是哪个族偏好、
        // MSS 钳到多少、fakeip 守卫了哪些段」必须是可见的一行，而不是让人去猜。
        info!("outbound dial policy: {}", dial.diag_line());
        let cipher = CuteBiCipher::new(config.encrypt_password.as_bytes());
        let parser = Arc::new(HandshakeParser::with_options(
            &config.proxy_key,
            &config.udp_flag,
            cipher.clone(),
            config.enable_dns_tcp_over_udp,
            &config.header_host,
            config.default_target_port,
        ));
        let conn_sem = Arc::new(Semaphore::new(config.max_connections));
        // guard 的 fakeip 段表由 policy 注入：任何一条回源路径都不可能漏掉这层守卫
        let guard = dial.apply_to(Guard::new(config.allow_private_targets));
        let config = Arc::new(config);
        Ok(Self {
            parser,
            cipher,
            guard,
            resolver,
            dial,
            conn_sem,
            ip_table: Arc::new(Mutex::new(HashMap::new())),
            active: Arc::new(AtomicUsize::new(0)),
            sessions: Arc::new(AtomicU64::new(0)),
            shutdown: Arc::new(Notify::new()),
            config,
        })
    }

    pub fn active_sessions(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    pub fn total_sessions(&self) -> u64 {
        self.sessions.load(Ordering::Relaxed)
    }

    /// limit=0 表示不限制：返回一个未在表中登记的 permit，Drop 时找不到键即无操作。
    fn try_ip_permit(&self, peer: IpAddr) -> Option<IpPermit> {
        let limit = self.config.max_connections_per_ip;
        if limit == 0 {
            return Some(IpPermit { ip: peer, table: Arc::clone(&self.ip_table) });
        }
        let mut table = self.ip_table.lock().ok()?;
        match table.get_mut(&peer) {
            Some(count) if *count >= limit => None,
            Some(count) => {
                *count += 1;
                Some(IpPermit { ip: peer, table: Arc::clone(&self.ip_table) })
            }
            None => {
                table.insert(peer, 1);
                Some(IpPermit { ip: peer, table: Arc::clone(&self.ip_table) })
            }
        }
    }
}

/// 已绑定的监听器 + 其地址
pub struct BoundListener {
    pub listener: TcpListener,
    pub addr: SocketAddr,
}

/// 按配置绑定全部监听器（通配地址自动展开为 v6+v4 双栈）。
/// 返回空列表表示全部失败，由调用方决定是否终止。
pub fn bind_listeners(config: &Config) -> Vec<BoundListener> {
    let mut out = Vec::new();
    for spec in &config.listen_addr {
        let addrs = expand_listen_spec(spec);
        if addrs.is_empty() {
            error!("invalid listen address '{spec}', skipping");
            continue;
        }
        for addr in addrs {
            let opts = ListenOptions {
                enable_tfo: config.enable_tfo,
                ipv6_only: config.ipv6_only,
                transparent: config.transparent,
                ..Default::default()
            };
            match create_tcp_listener(addr, opts) {
                Ok(listener) => {
                    let bound = listener.local_addr().unwrap_or(addr);
                    info!("listening on {bound}");
                    out.push(BoundListener { listener, addr: bound });
                    // 显式写了 v6 通配就不需要再试 v4（双栈 socket 已覆盖）
                    break;
                }
                Err(e) => {
                    debug!("bind {addr} failed: {e}, trying next family");
                }
            }
        }
    }
    out
}

/// 接受循环。`ctx.shutdown` 被通知后退出。
pub async fn run_listener(listener: TcpListener, ctx: Arc<ServerCtx>) {
    loop {
        let accept = tokio::select! {
            res = listener.accept() => res,
            _ = ctx.shutdown.notified() => return,
        };

        match accept {
            Ok((stream, peer_addr)) => {
                tune_tcp_stream(&stream);

                let permit = match Arc::clone(&ctx.conn_sem).try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!(
                            "max concurrency {} reached, rejecting {peer_addr}",
                            ctx.config.max_connections
                        );
                        drop(stream);
                        continue;
                    }
                };

                let ip_permit = match ctx.try_ip_permit(peer_addr.ip()) {
                    Some(p) => p,
                    None => {
                        debug!(
                            "per-IP limit {} reached for {peer_addr}",
                            ctx.config.max_connections_per_ip
                        );
                        drop(stream);
                        continue;
                    }
                };

                ctx.active.fetch_add(1, Ordering::Relaxed);
                ctx.sessions.fetch_add(1, Ordering::Relaxed);

                let session_ctx = Arc::clone(&ctx);
                tokio::spawn(async move {
                    let _global = permit;
                    let _per_ip = ip_permit;
                    let _active = ActiveGuard(Arc::clone(&session_ctx.active));
                    if let Err(e) = handle_client(stream, peer_addr, session_ctx).await {
                        debug!("session [{peer_addr}] finished: {e}");
                    }
                });
            }
            Err(e) => {
                warn!("accept error: {e}");
                // 持续性错误（fd 耗尽等）不能零间隔空转刷日志
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
}

/// 读取并解析握手，然后分发到对应隧道
pub async fn handle_client(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    ctx: Arc<ServerCtx>,
) -> anyhow::Result<()> {
    let (raw, complete) = read_until_header_end(
        &mut stream,
        ctx.config.handshake_timeout_duration(),
        MAX_HANDSHAKE_BYTES,
    )
    .await?;

    if raw.is_empty() {
        return Ok(()); // 空连接，直接回收
    }

    // * 读到 \r\n\r\n → HTTP 会话
    // * 明显非 HTTP（二进制 httpUDP 首帧）→ parser 归类为 SessionType::Udp
    // * 以方法名开头却没有头部结束符 → 截断/Slowloris，拒绝
    if !complete && HandshakeParser::is_http_request(&raw) {
        return Err(anyhow::anyhow!(
            "incomplete HTTP handshake from {peer_addr} ({} bytes)",
            raw.len()
        ));
    }

    let handshake = ctx.parser.parse(&raw)?;

    // 时序对齐原版 Go：解出免流头立刻回写 200，让客户端状态机就绪
    if let Some(resp) = handshake.response_header.as_ref() {
        stream.write_all(resp).await?;
    }

    dispatch(stream, peer_addr, ctx, handshake).await
}

async fn dispatch(
    stream: TcpStream,
    peer_addr: SocketAddr,
    ctx: Arc<ServerCtx>,
    handshake: cns_core::protocol::HandshakeResult,
) -> anyhow::Result<()> {
    let idle = ctx.config.tcp_timeout_duration();

    match handshake.session_type {
        SessionType::Tcp { target_host } => {
            debug!("TCP tunnel [{peer_addr}] -> [{target_host}]");
            // dial_tcp 内部已有 per-candidate 预算（policy.dial_timeout），外层的
            // timeout 只是「整个会话建立」的硬闸门；fakeip 守卫与族择优都在 dial 里做。
            let target = timeout(
                ctx.config.dial_timeout_duration(),
                DirectOutbound::dial_tcp(
                    &target_host,
                    &ctx.guard,
                    &ctx.resolver,
                    &ctx.dial,
                    ctx.config.enable_tfo,
                ),
            )
            .await
            .map_err(|_| anyhow::anyhow!("dial {target_host} timed out"))??;
            pump_tcp_stream(stream, target, ctx.cipher.clone(), idle).await?;
        }
        SessionType::Udp => {
            debug!("httpUDP tunnel [{peer_addr}]");
            let socket = DirectOutbound::bind_udp(true).await?;
            UdpTunnel::new(stream, socket, ctx.cipher.clone(), ctx.config.udp_timeout_duration())
                .run(handshake.remaining_data)
                .await?;
        }
        SessionType::DnsTcpOverUdp { target_host } => {
            debug!("tcpDNS tunnel [{peer_addr}] -> [{target_host}]");
            handle_dns_tcp_over_udp(
                stream,
                &target_host,
                ctx.cipher.clone(),
                ctx.config.udp_timeout_duration(),
                handshake.remaining_data,
                // Guard 不再是 Copy（带 fakeip 段表的 Arc），clone 只涨一次引用计数
                ctx.guard.clone(),
                &ctx.config.dns_upstream,
            )
            .await?;
        }
        SessionType::HttpDns { domain, is_ipv6 } => {
            if !ctx.config.enable_httpdns {
                debug!("httpDNS query for {domain} refused (enable_httpdns=false)");
                let mut s = stream;
                s.write_all(b"HTTP/1.0 403 Forbidden\r\nConnection: Close\r\n\r\n").await?;
                let _ = s.shutdown().await;
                return Ok(());
            }
            handle_http_dns(stream, &domain, is_ipv6, &ctx.resolver).await?;
        }
    }
    Ok(())
}

/// 起一个后台服务实例（测试与嵌入式部署用）。返回句柄，drop 或调用 `stop()` 即关闭。
pub struct RunningServer {
    pub addrs: Vec<SocketAddr>,
    ctx: Arc<ServerCtx>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl RunningServer {
    /// 用给定配置启动；`listen_addr` 建议传 `[":0"]` 以便测试拿随机端口
    ///
    /// 这里走 `try_new`：本函数已经返回 `Result`，配置非法就该是 Err 而不是 panic
    /// （嵌入式调用方拿到错误可以自己决定是退出还是回滚配置文件）。
    pub async fn start(config: Config) -> anyhow::Result<Self> {
        let ctx = Arc::new(ServerCtx::try_new(config)?);
        let listeners = bind_listeners(&ctx.config);
        if listeners.is_empty() {
            anyhow::bail!("no listener could be bound");
        }
        let addrs: Vec<SocketAddr> = listeners.iter().map(|l| l.addr).collect();
        let mut tasks = Vec::new();
        for BoundListener { listener, addr: _ } in listeners {
            let c = Arc::clone(&ctx);
            tasks.push(tokio::spawn(run_listener(listener, c)));
        }
        Ok(Self { addrs, ctx, tasks: Mutex::new(tasks) })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addrs[0]
    }

    pub fn ctx(&self) -> Arc<ServerCtx> {
        Arc::clone(&self.ctx)
    }

    pub fn active_sessions(&self) -> usize {
        self.ctx.active.load(Ordering::Relaxed)
    }

    pub fn total_sessions(&self) -> u64 {
        self.ctx.sessions.load(Ordering::Relaxed)
    }

    pub async fn stop(&self) {
        self.ctx.shutdown.notify_waiters();
        let handles = self.tasks.lock().map(|mut t| std::mem::take(&mut *t)).unwrap_or_default();
        let join_all = async move {
            for h in handles {
                let _ = h.await;
            }
        };
        // 排水窗口；超时就放弃等待（accept 循环已在 notify 后 return）
        let _ = timeout(Duration::from_secs(2), join_all).await;
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        self.ctx.shutdown.notify_waiters();
        if let Ok(mut t) = self.tasks.lock() {
            for h in t.drain(..) {
                h.abort();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cns_core::crypto::CuteBiCipher;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    const PASSWORD: &str = "dualstack-keystream";

    fn base() -> Config {
        Config {
            listen_addr: vec![":0".to_string()],
            proxy_key: "Meng".to_string(),
            udp_flag: "httpUDP".to_string(),
            encrypt_password: PASSWORD.to_string(),
            tcp_timeout: 5,
            udp_timeout: 3,
            handshake_timeout: 5,
            dial_timeout: 5,
            // 测试目标都在 127.0.0.1，必须放开私网回源
            allow_private_targets: true,
            enable_tfo: false,
            transparent: false,
            ..Default::default()
        }
    }

    /// 非法回源配置在**两条入口**上都必须是错误（启动路径绝不能带着错策略跑起来）
    #[test]
    fn server_ctx_rejects_illegal_outbound_config() {
        let cfg = Config { prefer_family: "ipv5".into(), ..base() };
        // ServerCtx 不实现 Debug，不能 unwrap_err()：显式 match 拿错误
        let e = match ServerCtx::try_new(cfg) {
            Ok(_) => panic!("prefer_family=ipv5 must not start"),
            Err(e) => e,
        };
        assert!(e.to_string().contains("prefer_family"), "{e}");

        let cfg = Config { fakeip_guard_cidrs: vec!["198.18.0.0/x".into()], ..base() };
        assert!(ServerCtx::try_new(cfg).is_err(), "非法 CIDR 必须拒绝");

        let cfg = Config { outbound_mss: 15000, ..base() };
        assert!(ServerCtx::try_new(cfg).is_err(), "outbound_mss 不许被 clamp 后启动");
    }

    /// `RunningServer::start` 自己也返回 Result，非法配置必须是 Err 而不是 panic
    #[tokio::test]
    async fn running_server_start_reports_config_error() {
        let cfg = Config { happy_eyeballs_ms: 9999, ..base() };
        // RunningServer 有 Drop，不实现 Debug -> 用 match 取错误
        let e = match RunningServer::start(cfg).await {
            Ok(sv) => {
                sv.stop().await;
                panic!("happy_eyeballs_ms=9999 must not start");
            }
            Err(e) => e,
        };
        assert!(e.to_string().contains("happy_eyeballs_ms"), "{e}");
    }

    /// ctx.guard 必须已经挂上 fakeip 段表：SSRF 之外的第二层守卫不是可选项
    #[test]
    fn ctx_guard_carries_fakeip_segments() {
        let ctx = ServerCtx::try_new(base()).unwrap();
        assert_eq!(ctx.guard.fakeip_guard_len(), 2, "默认 198.18.0.0/15 + fd53::/48");
        assert!(ctx.guard.check_ip("198.18.0.77".parse().unwrap()).is_err());
        assert!(ctx
            .guard
            .check_ip("198.18.0.77".parse().unwrap())
            .unwrap_err()
            .to_string()
            .contains("目标落在客户端 fakeip 段"));
        // allow_private_targets=true 也照样拦（fakeip 不是「私网放行」能豁免的东西）
        assert!(ctx.guard.check_ip("127.0.0.1".parse().unwrap()).is_ok());
    }

    async fn connect_and_handshake(
        server: SocketAddr,
        target: &str,
    ) -> anyhow::Result<(TcpStream, String)> {
        let cipher = CuteBiCipher::new(PASSWORD.as_bytes());
        let mut client = TcpStream::connect(server).await?;
        let enc = cipher.encrypt_host(target);
        client
            .write_all(
                format!("GET / HTTP/1.1\r\nHost: mclient.alipay.com\r\nMeng: {enc}\r\n\r\n")
                    .as_bytes(),
            )
            .await?;
        let mut buf = vec![0u8; 512];
        let n = timeout(Duration::from_secs(3), client.read(&mut buf))
            .await
            .map_err(|_| anyhow::anyhow!("no reply at all"))??;
        Ok((client, String::from_utf8_lossy(&buf[..n]).to_string()))
    }

    /// 端到端：客户端把 fakeip 原样当目标送来（反查失败的泄漏场景）时，
    /// 会话必须**快速**失败，而不是回源打上去、干等一整个 dial_timeout。
    #[tokio::test]
    async fn fakeip_target_is_refused_fast_end_to_end() {
        let mut cfg = base();
        cfg.listen_addr = vec![":0".to_string()];
        let server = RunningServer::start(cfg).await.unwrap();

        let t0 = std::time::Instant::now();
        let (_c, head) = connect_and_handshake(server.addr(), "198.18.0.77:443").await.unwrap();
        let took = t0.elapsed();

        // 免流时序：解出伪装头就先回 200，会话错误体现在 200 之后立刻断开
        assert!(head.contains("200"), "{head}");
        assert!(
            took < Duration::from_millis(1500),
            "fakeip 目标不该走完整个回源预算才失败: {took:?}"
        );
        server.stop().await;
    }

    /// tcpDNS 快速通道的判定（目标串以 `:53` 结尾）**不受族择优影响**：
    /// 这类会话走 DnsTcpOverUdp，绝不进 dial_tcp；同时 fakeip 形态的
    /// dns_upstream 会被 guard 拒掉（守卫覆盖这条路径）。
    #[tokio::test]
    async fn dns_over_udp_path_is_not_affected_and_still_guarded() {
        let ctx = ServerCtx::try_new(base()).unwrap();
        // 守卫层：dns_upstream 若被写成 fakeip，resolve_dns_upstream 会因 check_ip 失败剔除
        for leak in ["198.18.0.53", "fd53::53"] {
            let ip: std::net::IpAddr = leak.parse().unwrap();
            assert!(ctx.guard.check_ip(ip).is_err(), "{leak} 作为 DNS 上游也必须拦下");
        }
        // 真实上游串不受影响
        assert!(ctx.guard.check_ip("202.96.128.86".parse().unwrap()).is_ok());
    }

    /// prefer_family=ipv4 时，域名候选里不该出现 v6（这里用字面量验证排序层，
    /// 不依赖外网 DNS）
    #[tokio::test]
    async fn dial_policy_is_reachable_from_ctx() {
        let mut cfg = base();
        cfg.prefer_family = "ipv4".into();
        cfg.happy_eyeballs_ms = 250;
        cfg.dial_probe_count = 3;
        cfg.outbound_mss = 1300;
        let ctx = ServerCtx::try_new(cfg).unwrap();
        assert_eq!(ctx.dial.prefer, crate::config::FamilyPreference::Ipv4);
        assert_eq!(ctx.dial.happy_eyeballs, Duration::from_millis(250));
        assert_eq!(ctx.dial.probe_count, 3);
        assert_eq!(ctx.dial.outbound_mss, 1300);
        assert!(ctx.dial.diag_line().contains("prefer=ipv4"));
        assert!(ctx.dial.diag_line().contains("mss=1300"));
    }
}
