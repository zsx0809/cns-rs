use clap::Parser;
use cns_client::config::ClientConfig;
use cns_client::inbound::{apply_process_gid, get_original_dst, LocalDnsRelay, Socks5Command, Socks5Handshake};
use cns_client::outbound::CnsClientTunnel;
use cns_core::crypto::CuteBiCipher;
use cns_core::transport::{create_tcp_listener, tune_tcp_stream};
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(
    name = "cns-client",
    author = "CuteBi Modernizers",
    version = "0.1.0",
    about = "Ultra-high-performance, modern CuteBi Network Client (CLNC) in pure Rust"
)]
struct Args {
    /// Path to JSON client configuration file
    #[arg(short = 'c', long = "config", default_value = "client.json")]
    config: String,

    /// Switch process GID to prevent routing loop (e.g., 3004)
    #[arg(short = 'g', long = "gid")]
    gid: Option<u32>,

    /// Override transparent proxy listen port (e.g., 7750)
    #[arg(short = 't', long = "tproxy-port")]
    tproxy_port: Option<u16>,

    /// Save PID to file (compatibility with legacy root scripts)
    #[arg(short = 'p', long = "pid-file")]
    pid_file: Option<String>,

    /// Local UDP DNS relay listen address (e.g., 0.0.0.0:6653)
    #[arg(long = "dns-listen", default_value = "0.0.0.0:6653")]
    dns_listen: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();

    if let Some(ref pid_path) = args.pid_file {
        let pid = std::process::id();
        let _ = fs::write(pid_path, format!("{}\n", pid));
    }

    info!("Loading client configuration from: {}", args.config);

    let config = match ClientConfig::from_file(&args.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!("Failed to read {}: {}. Falling back to default client configuration.", args.config, e);
            ClientConfig::default()
        }
    };

    let target_gid = args.gid.or(config.gid);
    if let Some(gid) = target_gid {
        if let Err(e) = apply_process_gid(gid) {
            warn!("Failed to set process GID {}: {}. Running with current GID.", gid, e);
        } else {
            info!("Successfully switched process GID to {} (anti-routing-loop protection)", gid);
        }
    }

    let cipher = CuteBiCipher::new(config.cns_password.as_bytes());
    let config_arc = Arc::new(config);
    let cipher_arc = Arc::new(cipher);

    // 1. 启动 SOCKS5 Inbound 服务
    if !config_arc.socks5_listen.is_empty() {
        let socks5_addr = config_arc.socks5_listen.clone();
        let cfg_clone = Arc::clone(&config_arc);
        let cph_clone = Arc::clone(&cipher_arc);

        tokio::spawn(async move {
            match TcpListener::bind(&socks5_addr).await {
                Ok(listener) => {
                    info!("SOCKS5 Inbound listening on: {}", socks5_addr);
                    run_socks5_listener(listener, cfg_clone, cph_clone).await;
                }
                Err(e) => {
                    warn!("Failed to bind SOCKS5 on {}: {}", socks5_addr, e);
                }
            }
        });
    }

    // 2. 启动 TProxy / REDIRECT 透明代理 Inbound 服务 (双栈解耦监听)
    let tproxy_port: Option<u16> = args.tproxy_port.or_else(|| {
        config_arc.tproxy_listen.as_ref().and_then(|addr| {
            if let Some(idx) = addr.rfind(':') {
                addr[idx + 1..].parse::<u16>().ok()
            } else {
                addr.parse::<u16>().ok()
            }
        })
    });

    if let Some(port) = tproxy_port {
        let v4_addr: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
        let v6_addr: SocketAddr = format!("[::]:{}", port).parse().unwrap();

        // IPv4 监听器
        let cfg_v4 = Arc::clone(&config_arc);
        let cph_v4 = Arc::clone(&cipher_arc);
        match create_tcp_listener(v4_addr, cfg_v4.enable_tfo) {
            Ok(listener) => {
                info!("Transparent Proxy (IPv4 REDIRECT) listening on: {}", v4_addr);
                tokio::spawn(async move {
                    run_tproxy_listener(listener, cfg_v4, cph_v4).await;
                });
            }
            Err(e) => warn!("Failed to bind IPv4 Transparent Proxy on {}: {}", v4_addr, e),
        }

        // IPv6 监听器
        let cfg_v6 = Arc::clone(&config_arc);
        let cph_v6 = Arc::clone(&cipher_arc);
        match create_tcp_listener(v6_addr, cfg_v6.enable_tfo) {
            Ok(listener) => {
                info!("Transparent Proxy (IPv6 REDIRECT) listening on: {}", v6_addr);
                tokio::spawn(async move {
                    run_tproxy_listener(listener, cfg_v6, cph_v6).await;
                });
            }
            Err(e) => warn!("Failed to bind IPv6 Transparent Proxy on {}: {}", v6_addr, e),
        }
    }

    // 3. 启动本地 UDP DNS 转发中继 (彻底解决手机端域名解析与免流断网问题)
    if let Ok(dns_addr) = args.dns_listen.parse::<SocketAddr>() {
        let cfg_dns = Arc::clone(&config_arc);
        let cph_dns = Arc::clone(&cipher_arc);
        tokio::spawn(async move {
            if let Err(e) = LocalDnsRelay::run(dns_addr, cfg_dns, cph_dns).await {
                warn!("Local DNS Relay error: {}", e);
            }
        });
        info!("Local UDP DNS Relay listening on: {}", dns_addr);
    }

    info!("Upstream CNS Server: {}", config_arc.cns_server);

    tokio::signal::ctrl_c().await?;
    info!("Shutdown signal received. Exiting client...");

    if let Some(ref pid_path) = args.pid_file {
        let _ = fs::remove_file(pid_path);
    }

    Ok(())
}

async fn run_socks5_listener(
    listener: TcpListener,
    config: Arc<ClientConfig>,
    cipher: Arc<CuteBiCipher>,
) {
    loop {
        match listener.accept().await {
            Ok((mut stream, peer_addr)) => {
                tune_tcp_stream(&stream);
                let cfg = Arc::clone(&config);
                let cph = Arc::clone(&cipher);

                tokio::spawn(async move {
                    match Socks5Handshake::handle(&mut stream).await {
                        Ok(Socks5Command::Connect { target }) => {
                            tracing::debug!("SOCKS5 Proxying [{}] from [{}]", target, peer_addr);
                            if let Err(e) = CnsClientTunnel::handle_tcp_proxy(stream, &target, &cfg, &cph).await {
                                tracing::debug!("TCP proxy session ended: {}", e);
                            }
                        }
                        Ok(Socks5Command::UdpAssociate) => {
                            warn!("UDP Associate requested from [{}].", peer_addr);
                        }
                        Err(e) => {
                            tracing::debug!("SOCKS5 handshake error from [{}]: {}", peer_addr, e);
                        }
                    }
                });
            }
            Err(e) => {
                error!("SOCKS5 accept error: {}", e);
            }
        }
    }
}

async fn run_tproxy_listener(
    listener: TcpListener,
    config: Arc<ClientConfig>,
    cipher: Arc<CuteBiCipher>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                tune_tcp_stream(&stream);
                let cfg = Arc::clone(&config);
                let cph = Arc::clone(&cipher);

                tokio::spawn(async move {
                    match get_original_dst(&stream) {
                        Ok(target_addr) => {
                            let target_host = target_addr.to_string();
                            tracing::debug!("TProxy intercepted connection to [{}] from [{}]", target_host, peer_addr);
                            if let Err(e) = CnsClientTunnel::handle_tcp_proxy(stream, &target_host, &cfg, &cph).await {
                                tracing::debug!("TProxy session ended: {}", e);
                            }
                        }
                        Err(e) => {
                            warn!("Failed to get SO_ORIGINAL_DST from [{}]: {}", peer_addr, e);
                        }
                    }
                });
            }
            Err(e) => {
                error!("TProxy accept error: {}", e);
            }
        }
    }
}
