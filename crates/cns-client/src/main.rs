use clap::Parser;
use cns_client::config::ClientConfig;
use cns_client::inbound::{
    apply_process_gid, get_original_dst_with_mode, register_associate, LocalDnsRelay,
    Socks5Command, Socks5Handshake, TproxyMode, UdpAssociates, UdpRelay, UdpTproxyRelay,
};
use cns_client::outbound::CnsClientTunnel;
use cns_core::crypto::CuteBiCipher;
use cns_core::transport::{
    create_tcp_listener, create_udp_tproxy_socket, tune_tcp_stream, BufferPool, ListenOptions,
};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Notify, Semaphore};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

/// 客户端本地最大并发保护上限，避免系统应用突发高并发吃光 Android 内存
const CLIENT_MAX_CONCURRENCY: usize = 2048;

#[derive(Parser, Debug)]
#[command(
    name = "cns-client",
    author = "CuteBi Modernizers",
    version = env!("CARGO_PKG_VERSION"),
    about = "Ultra-high-performance, modern CuteBi Network Client (CLNC) in pure Rust"
)]
struct Args {
    /// Path to JSON client configuration file
    #[arg(short = 'c', long = "config", default_value = "client.json")]
    config: String,

    /// Switch process GID to prevent routing loop (e.g. 3004)
    #[arg(short = 'g', long = "gid")]
    gid: Option<u32>,

    /// Override transparent proxy listen port (e.g. 7750)
    #[arg(short = 't', long = "tproxy-port")]
    tproxy_port: Option<u16>,

    /// 透明代理劫持方式：redirect | tproxy | auto（不传则用配置里的 tproxy_mode）
    #[arg(long)]
    mode: Option<String>,

    /// Save PID to file (compatibility with legacy root scripts)
    #[arg(short = 'p', long = "pid-file")]
    pid_file: Option<String>,

    /// 覆盖本地 DNS 中继监听地址（如 0.0.0.0:6653）。
    /// 不传时用配置文件里的 dns_listen；两者都没给才用内置默认。
    #[arg(long)]
    dns_listen: Option<String>,

    /// 不启动本地 DNS 中继（已由外部 dnsmasq/AdGuard 接管时使用）
    #[arg(long)]
    no_dns: bool,

    /// 不启动 SOCKS5（只要透明代理时省一个监听口）
    #[arg(long)]
    no_socks5: bool,

    /// 周期性打印统计（秒，0 = 关闭）
    #[arg(long, default_value_t = 0)]
    stats_interval: u64,
}

/// 全局运行统计
#[derive(Default)]
struct Stats {
    socks_tcp: AtomicU64,
    socks_udp: AtomicU64,
    tproxy_tcp: AtomicU64,
    rejected: AtomicU64,
    active: std::sync::atomic::AtomicU64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 默认 warn 级别，避免长时间运行把手机存储写满
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();

    let args = Args::parse();

    if let Some(ref pid_path) = args.pid_file {
        let pid = std::process::id();
        fs::write(pid_path, format!("{pid}\n"))
            .map_err(|e| anyhow::anyhow!("failed to write pid file {pid_path}: {e}"))?;
    }

    // 关键修复：配置错误必须终止启动。旧实现回落到默认配置，而默认的
    // cns_server 是 127.0.0.1:1254、口令为空 —— 手机会对着自己疯狂失败并静默断网。
    let config = match ClientConfig::from_file(&args.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("{e}");
            return Err(e);
        }
    };

    // 优先级：命令行 > 配置文件 > 内置默认。
    // 旧实现给 --dns-listen / --mode 写了 default_value，clap 永远返回「已给值」，
    // 于是用户手改 modes/*.json 里的 dns_listen / tproxy_mode 完全不生效。
    let dns_listen = args.dns_listen.clone().unwrap_or_else(|| config.dns_listen.clone());

    let mode = match args.mode.as_deref() {
        Some(raw) => TproxyMode::parse(raw).ok_or_else(|| {
            anyhow::anyhow!("invalid --mode '{raw}' (expected redirect|tproxy|auto)")
        })?,
        None => config.tproxy_mode_parsed(),
    };

    if config.cns_password.is_empty() {
        warn!("cns_password is EMPTY — traffic is unobfuscated. Set a password.");
    }
    // REDIRECT 会把目的地址改写成中继自己的地址，本地 DNS 中继因此拿不到 App 原本
    // 要查的 DNS；`dns_mode=orig` 在这种模式下必然失效并静默回落到 dns_upstream。
    // 内网域名 / split-horizon 的正确解法是各模式 JSON 里显式写 dns_mode="fixed"。
    if mode == TproxyMode::Redirect && config.dns_mode == "orig" {
        warn!(
            "tproxy_mode=redirect 与 dns_mode=orig 组合下拿不到 App 原本的 DNS 上游：\
             所有查询会回落到 dns_upstream={:?}。内网/local 域名如需按原样解析，\
             请在该模式 JSON 里改 dns_mode=\"fixed\" 并显式列出上游。",
            config.dns_upstream
        );
    }
    if config.block_ipv6 {
        warn!(
            "block_ipv6=true：AAAA 将被本地 NODATA 拦截（IPv6-only 网络请设为 false）。\
             隧道侧对 IPv6 目标仍按服务端能力转发"
        );
    }

    let cipher = Arc::new(CuteBiCipher::new(config.cns_password.as_bytes()));
    let config = Arc::new(config);
    let pool = BufferPool::with_cap(config.buffer_pool_cap);
    let stats = Arc::new(Stats::default());
    let semaphore = Arc::new(Semaphore::new(CLIENT_MAX_CONCURRENCY));
    let shutdown = Arc::new(Notify::new());

    info!(
        "cns-client {} -> {} (mode={}, tfo={}, dns_relay={} {})",
        env!("CARGO_PKG_VERSION"),
        config.cns_server,
        mode.as_str(),
        config.enable_tfo,
        if args.no_dns { "off" } else { "on" },
        dns_listen
    );

    // ---- 1. 先把所有监听 socket 建好，之后才改 GID ----
    // setgid 之后新建 socket 的 owner 才会命中 iptables 的 --gid-owner 白名单；
    // 反过来做会让监听 socket 自身被 REDIRECT 抓回，形成回环。
    let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    let socks5_addr = if args.no_socks5 || config.socks5_listen.is_empty() {
        None
    } else {
        match config.socks5_listen.parse::<SocketAddr>() {
            Ok(a) => Some(a),
            Err(e) => {
                anyhow::bail!("invalid socks5_listen '{}': {e}", config.socks5_listen);
            }
        }
    };

    let socks5_listener = match socks5_addr {
        Some(addr) => {
            let l = TcpListener::bind(addr)
                .await
                .map_err(|e| anyhow::anyhow!("bind SOCKS5 {addr}: {e}"))?;
            info!("SOCKS5 listening on {addr}");
            Some(l)
        }
        None => None,
    };

    // SOCKS5 UDP relay 端口与 TCP 监听端口一致（BND.PORT 语义要求）
    let udp_bind = if !config.socks5_udp_listen.is_empty() {
        config
            .socks5_udp_listen
            .parse::<SocketAddr>()
            .map_err(|e| anyhow::anyhow!("invalid socks5_udp_listen: {e}"))?
    } else {
        SocketAddr::new(
            socks5_addr.map(|a| a.ip()).unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            socks5_addr.map(|a| a.port()).unwrap_or(1080),
        )
    };

    let tproxy_port: Option<u16> = args.tproxy_port.or_else(|| {
        config.tproxy_listen.as_ref().and_then(|addr| {
            if let Some(idx) = addr.rfind(':') {
                addr[idx + 1..].parse::<u16>().ok()
            } else {
                addr.parse::<u16>().ok()
            }
        })
    });

    let mut tproxy_listeners: Vec<(TcpListener, u16)> = Vec::new();
    let mut udp_tproxy_sockets: Vec<(UdpSocket, u16)> = Vec::new();
    if let Some(port) = tproxy_port {
        for addr in [
            format!("0.0.0.0:{port}").parse::<SocketAddr>().unwrap(),
            format!("[::]:{port}").parse::<SocketAddr>().unwrap(),
        ] {
            let opts = ListenOptions {
                enable_tfo: config.enable_tfo,
                ipv6_only: addr.is_ipv6(),
                transparent: true,
                ..Default::default()
            };
            match create_tcp_listener(addr, opts) {
                Ok(l) => {
                    let bound = l.local_addr().unwrap_or(addr);
                    tproxy_listeners.push((l, port));
                    info!("TCP transparent proxy listening on {bound} ({})", addr);
                }
                Err(e) => {
                    // IPv4 是出厂配置的主路径：端口被占 / 权限不足 / 上一个实例没退干净时，
                    // iptables 仍然会把流量导到这个没人监听的端口 —— 用户看到的是
                    // 「进程活着但全站断网」。这种情况必须终止启动，不能带病常驻。
                    if addr.is_ipv4() {
                        anyhow::bail!(
                            "failed to bind IPv4 TCP transparent proxy on {addr}: {e}\n\
                             规则仍会把流量导到这里，拒绝带病启动。请检查端口占用\
                             （ss -lntp | grep {port}）或上一个实例是否残留。"
                        );
                    } else {
                        // IPv6 常被禁用，属可容忍降级
                        debug!("IPv6 TCP transparent proxy unavailable on {addr}: {e}");
                    }
                }
            }

            // 若开启了 UDP 隧道，同时启动对应地址的 UDP 透明代理监听
            if config.enable_udp_tunnel {
                match create_udp_tproxy_socket(addr) {
                    Ok(sock) => {
                        let bound = sock.local_addr().unwrap_or(addr);
                        udp_tproxy_sockets.push((sock, port));
                        info!("UDP transparent proxy listening on {bound} ({})", addr);
                    }
                    Err(e) => {
                        if addr.is_ipv4() {
                            warn!("failed to bind IPv4 UDP transparent proxy on {addr}: {e}");
                        } else {
                            debug!("IPv6 UDP transparent proxy unavailable on {addr}: {e}");
                        }
                    }
                }
            }
        }
    }

    // 至少要有一个 TCP 透明代理监听真正起来了，否则后面的规则就是把人往黑洞里导
    if tproxy_port.is_some() && tproxy_listeners.is_empty() {
        anyhow::bail!(
            "没有任何 TCP 透明代理监听成功（port={}），拒绝带病启动",
            tproxy_port.unwrap()
        );
    }

    let dns_addr: Option<SocketAddr> = if args.no_dns {
        None
    } else {
        match dns_listen.parse::<SocketAddr>() {
            Ok(a) => Some(a),
            Err(e) => {
                anyhow::bail!("invalid dns listen '{dns_listen}': {e}");
            }
        }
    };

    let dns_listener = match dns_addr {
        Some(a) => match cns_client::inbound::bind_relay_socket(a) {
            Ok(s) => Some(s),
            Err(e) => {
                // 规则会把 UDP/53 导到这里；监听没起来 = 解析全挂但进程还在跑。
                // 想要"不起 DNS 中继"应该用 --no-dns，而不是让它悄悄失败。
                anyhow::bail!(
                    "failed to bind DNS relay on {a}: {e}\n\
                     规则会把 UDP/53 导到这里，拒绝带病启动（如不需要中继请用 --no-dns）。"
                );
            }
        },
        None => None,
    };

    // ---- 2. 现在才切 GID（防回环白名单）----
    let target_gid = args.gid.or(config.gid);
    if let Some(gid) = target_gid {
        match apply_process_gid(gid) {
            Ok(()) => info!("process GID switched to {gid} (iptables anti-loop whitelist)"),
            Err(e) => warn!("failed to set GID {gid}: {e}; 请确认 iptables 的 --gid-owner 规则"),
        }
    } else {
        warn!(
            "未设置 gid：cns-client 自己的出站连接会被 REDIRECT 抓回自己（回环）。 \
             请用 -g 3004 或在配置里写 gid"
        );
    }

    // ---- 3. 启动各 inbound ----
    if let Some(listener) = socks5_listener {
        let sem = Arc::clone(&semaphore);
        let st = Arc::clone(&stats);
        let assoc = UdpAssociates::new();
        let shutdown = Arc::clone(&shutdown);
        let rt = Runtime {
            config: Arc::clone(&config),
            cipher: Arc::clone(&cipher),
            stats: Arc::clone(&st),
            pool: pool.clone(),
        };

        // UDP relay 独立任务：与 SOCKS5 共享 allowlist
        let relay_cfg = Arc::clone(&config);
        let relay_cipher = Arc::clone(&cipher);
        let relay_assoc = assoc.clone();
        handles.push(tokio::spawn(async move {
            if !relay_cfg.enable_udp_tunnel {
                info!("httpUDP tunnel disabled (enable_udp_tunnel=false)");
                return;
            }
            let relay = UdpRelay::new(relay_cfg, relay_cipher, udp_bind, relay_assoc);
            if let Err(e) = relay.run().await {
                warn!("SOCKS5 UDP relay exited: {e}");
            }
        }));

        handles
            .push(tokio::spawn(run_socks5_listener(listener, rt, sem, assoc, udp_bind, shutdown)));
    }

    for (listener, port) in tproxy_listeners {
        let sem = Arc::clone(&semaphore);
        let st = Arc::clone(&stats);
        let shutdown = Arc::clone(&shutdown);
        let rt = Runtime {
            config: Arc::clone(&config),
            cipher: Arc::clone(&cipher),
            stats: st,
            // 每个监听器共享同一个底层池（BufferPool 内部是 Arc）
            pool: pool.clone(),
        };
        handles.push(tokio::spawn(run_tproxy_listener(listener, port, mode, rt, sem, shutdown)));
    }

    for (sock, port) in udp_tproxy_sockets {
        let cfg = Arc::clone(&config);
        let cph = Arc::clone(&cipher);
        handles.push(tokio::spawn(async move {
            let relay = UdpTproxyRelay::new(cfg, cph, port);
            if let Err(e) = relay.run_loop_with_socket(Arc::new(sock)).await {
                warn!("UDP tproxy relay error: {e}");
            }
        }));
    }

    if let Some(sock) = dns_listener {
        let cfg = Arc::clone(&config);
        let cph = Arc::clone(&cipher);
        let addr = dns_addr.unwrap();
        handles.push(tokio::spawn(async move {
            let relay = LocalDnsRelay::new(cfg, cph);
            info!("local DNS relay up on {addr}");
            if let Err(e) = relay.run_loop_with_socket(Arc::new(sock)).await {
                warn!("Local DNS Relay error: {e}");
            }
        }));
    }

    // ---- 4. 统计与退出 ----
    if args.stats_interval > 0 {
        let st = Arc::clone(&stats);
        let cfg = Arc::clone(&config);
        let shutdown = Arc::clone(&shutdown);
        handles.push(tokio::spawn(async move {
            let every = Duration::from_secs(args.stats_interval.max(5));
            loop {
                if tokio::time::timeout(every, shutdown.notified()).await.is_ok() {
                    return;
                }
                info!(
                    "stats socks_tcp={} socks_udp={} tproxy={} rejected={} active={} server={}",
                    st.socks_tcp.load(Ordering::Relaxed),
                    st.socks_udp.load(Ordering::Relaxed),
                    st.tproxy_tcp.load(Ordering::Relaxed),
                    st.rejected.load(Ordering::Relaxed),
                    st.active.load(Ordering::Relaxed),
                    cfg.cns_server
                );
            }
        }));
    }

    // 模块脚本用的是 `kill`（SIGTERM），只处理 ctrl_c() 等于永远走不到下面的
    // drain/删 pid 逻辑，还会让 KSU/Magisk 每 2 秒补一次 kill -9。
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
        tokio::select! {
            res = tokio::signal::ctrl_c() => {
                if let Err(e) = res {
                    error!("signal handler error: {e}");
                }
            }
            _ = sigterm.recv() => info!("SIGTERM received"),
            _ = sighup.recv() => info!("SIGHUP received (no live reload, shutting down)"),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.ok();
    }

    info!("shutdown signal received, draining sessions...");
    shutdown.notify_waiters();
    // 留一点时间让在途会话收尾（半关闭会自行结束）
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    for h in handles {
        h.abort();
    }

    if let Some(ref pid_path) = args.pid_file {
        let _ = fs::remove_file(pid_path);
    }
    info!("cns-client stopped");
    Ok(())
}

use std::time::Duration;

async fn run_socks5_listener(
    listener: TcpListener,
    rt: Runtime,
    semaphore: Arc<Semaphore>,
    associates: UdpAssociates,
    udp_bind: SocketAddr,
    shutdown: Arc<Notify>,
) {
    loop {
        let accept = tokio::select! {
            res = listener.accept() => res,
            _ = shutdown.notified() => return,
        };
        match accept {
            Ok((stream, peer_addr)) => {
                tune_tcp_stream(&stream);
                let permit = match Arc::clone(&semaphore).try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        rt.stats.rejected.fetch_add(1, Ordering::Relaxed);
                        warn!("client concurrency limit reached, dropping SOCKS5 from {peer_addr}");
                        drop(stream);
                        continue;
                    }
                };

                let session_rt = rt.clone();
                let assoc = associates.clone();
                rt.stats.active.fetch_add(1, Ordering::Relaxed);

                tokio::spawn(async move {
                    let _permit = permit;
                    let _guard = ActiveGuard(Arc::clone(&session_rt.stats));
                    handle_socks5(stream, peer_addr, session_rt, assoc, udp_bind).await;
                });
            }
            Err(e) => {
                error!("SOCKS5 accept error: {e}");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
}

async fn handle_socks5(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    rt: Runtime,
    associates: UdpAssociates,
    udp_bind: SocketAddr,
) {
    match Socks5Handshake::handle(&mut stream).await {
        Ok(Socks5Command::Connect { target }) => {
            rt.stats.socks_tcp.fetch_add(1, Ordering::Relaxed);
            let logged = target.clone();
            if let Err(e) = CnsClientTunnel::handle_tcp_proxy(
                stream,
                target,
                (*rt.config).clone(),
                (*rt.cipher).clone(),
                rt.pool,
            )
            .await
            {
                debug!("SOCKS5 CONNECT {logged} ended: {e}");
            }
        }
        Ok(Socks5Command::UdpAssociate { client_udp }) => {
            // 登记来源：UDP relay 只接受已登记地址的数据报。
            // 判定按 IP —— App 的 UDP 源端口与 TCP 控制端口必然不同。
            let src = client_udp.unwrap_or(peer_addr);
            register_associate(&associates, src);
            register_associate(&associates, peer_addr);
            rt.stats.socks_udp.fetch_add(1, Ordering::Relaxed);
            debug!("SOCKS5 UDP ASSOCIATE registered for {} (relay {udp_bind})", src.ip());

            // 保持控制连接打开：SOCKS5 语义是「控制连接关闭即解除关联」。
            // 不解除的话这个 IP 会被永久放行，等于留了一个开放 UDP 转发口子。
            let mut sink = [0u8; 64];
            loop {
                if stream.read(&mut sink).await.unwrap_or(0) == 0 {
                    break;
                }
            }
            associates.revoke(peer_addr);
            associates.revoke(src);
            debug!("SOCKS5 UDP ASSOCIATE ended, revoked {}", src.ip());
        }
        Err(e) => {
            debug!("SOCKS5 handshake error from {peer_addr}: {e}");
            // 明确回一个失败再关闭，别让客户端猜
            let _ = timeout(
                Duration::from_millis(500),
                stream.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]),
            )
            .await;
        }
    }
}

async fn run_tproxy_listener(
    listener: TcpListener,
    listen_port: u16,
    mode: TproxyMode,
    rt: Runtime,
    semaphore: Arc<Semaphore>,
    shutdown: Arc<Notify>,
) {
    loop {
        let accept = tokio::select! {
            res = listener.accept() => res,
            _ = shutdown.notified() => return,
        };
        match accept {
            Ok((stream, peer_addr)) => {
                tune_tcp_stream(&stream);
                let permit = match Arc::clone(&semaphore).try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        rt.stats.rejected.fetch_add(1, Ordering::Relaxed);
                        warn!("client concurrency limit reached, dropping tproxy from {peer_addr}");
                        drop(stream);
                        continue;
                    }
                };

                let session_rt = rt.clone();
                rt.stats.active.fetch_add(1, Ordering::Relaxed);

                tokio::spawn(async move {
                    let _permit = permit;
                    let _guard = ActiveGuard(Arc::clone(&session_rt.stats));
                    match get_original_dst_with_mode(&stream, listen_port, mode) {
                        Ok(target_addr) => {
                            session_rt.stats.tproxy_tcp.fetch_add(1, Ordering::Relaxed);
                            let target = target_addr.to_string();
                            let logged = target.clone();
                            if let Err(e) = CnsClientTunnel::handle_tcp_proxy(
                                stream,
                                target,
                                (*session_rt.config).clone(),
                                (*session_rt.cipher).clone(),
                                session_rt.pool,
                            )
                            .await
                            {
                                debug!("tproxy {logged} ended: {e}");
                            }
                        }
                        Err(e) => {
                            // 环路/非劫持连接：直接拒绝，绝不转发给自己
                            debug!("no original dst for [{peer_addr}]: {e}");
                        }
                    }
                });
            }
            Err(e) => {
                error!("TProxy accept error: {e}");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
}

/// 每个入站会话共享的运行时上下文（避免 handler 参数爆炸）
#[derive(Clone)]
struct Runtime {
    config: Arc<ClientConfig>,
    cipher: Arc<CuteBiCipher>,
    stats: Arc<Stats>,
    pool: BufferPool,
}

/// 活跃会话计数守卫（持有 Arc 克隆，避免与闭包内的其它使用冲突）
struct ActiveGuard(Arc<Stats>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}
