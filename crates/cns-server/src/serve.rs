//! 服务端会话引擎。
//!
//! 从 `main.rs` 下沉到 lib，使集成测试可以启动**真实**的监听 + 握手 + 转发
//! 全流程，而不必像旧测试那样手搓一份 mock server（mock 与被测代码不同源，
//! 测过了不代表真服务能用）。

use crate::config::Config;
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
    pub guard: Guard,
    pub resolver: Arc<Resolver>,
    conn_sem: Arc<Semaphore>,
    ip_table: Arc<Mutex<HashMap<IpAddr, usize>>>,
    pub active: Arc<AtomicUsize>,
    pub sessions: Arc<AtomicU64>,
    pub shutdown: Arc<Notify>,
}

impl ServerCtx {
    pub fn new(config: Config) -> Self {
        let resolver = Arc::new(Resolver::new(
            &config.dns_upstream.clone(),
            ResolverOptions {
                cache_limit: config.dns_cache_size,
                query_timeout: config.dial_timeout_duration().max(Duration::from_secs(2)),
                ..Default::default()
            },
        ));
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
        Self {
            parser,
            cipher,
            guard: Guard::new(config.allow_private_targets),
            resolver,
            conn_sem,
            ip_table: Arc::new(Mutex::new(HashMap::new())),
            active: Arc::new(AtomicUsize::new(0)),
            sessions: Arc::new(AtomicU64::new(0)),
            shutdown: Arc::new(Notify::new()),
            config: Arc::new(config),
        }
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
            let target = timeout(
                ctx.config.dial_timeout_duration(),
                DirectOutbound::dial_tcp(&target_host, ctx.guard, ctx.config.enable_tfo),
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
                ctx.guard,
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
    pub async fn start(config: Config) -> anyhow::Result<Self> {
        let ctx = Arc::new(ServerCtx::new(config));
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
