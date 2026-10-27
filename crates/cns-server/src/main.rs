use clap::Parser;
use cns_core::crypto::CuteBiCipher;
use cns_core::protocol::{HandshakeParser, SessionType};
use cns_core::transport::{create_tcp_listener, tune_tcp_stream};
use cns_server::config::Config;
use cns_server::outbound::DirectOutbound;
use cns_server::tunnel::{handle_dns_tcp_over_udp, handle_http_dns, pump_tcp_stream, UdpTunnel};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{error, info, warn};

/// 最大并发 TCP 连接配额，彻底杜绝连接风暴与内存暴涨 (OOM) 风险
const MAX_CONCURRENT_CONNECTIONS: usize = 4096;
/// 客户端首包握手必须在 10 秒内送达，超时强制丢弃防 Slowloris 挂死连接
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// 回源连接建立超时限制
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Parser, Debug)]
#[command(
    name = "cns-server",
    author = "CuteBi Modernizers",
    version = "0.1.0",
    about = "Ultra-high-performance, zero-GC CuteBi Network Suite (CNS) server in pure Rust"
)]
struct Args {
    /// Path to JSON configuration file
    #[arg(short = 'c', long = "config", alias = "json", default_value = "config.json")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 生产环境安全日志：默认仅输出 warn 及以上日志，避免大量并发请求刷爆 VPS 磁盘
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn".into()),
        )
        .init();

    let args = Args::parse();
    info!("Loading configuration from: {}", args.config);

    let config = match Config::from_file(&args.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!("Failed to read {}: {}. Falling back to default configuration.", args.config, e);
            Config::default()
        }
    };

    let cipher = CuteBiCipher::new(config.encrypt_password.as_bytes());
    let parser = Arc::new(HandshakeParser::new(
        &config.proxy_key,
        &config.udp_flag,
        cipher.clone(),
        config.enable_dns_tcp_over_udp,
    ));

    info!(
        "CuteBi Network Suite Server starting up. Cipher loaded: {}",
        !cipher.is_empty()
    );

    let config_arc = Arc::new(config);
    let conn_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    for addr_str in &config_arc.listen_addr {
        let normalized_addr = if addr_str.starts_with(':') {
            format!("[::]{}", addr_str)
        } else {
            addr_str.clone()
        };

        let socket_addr: SocketAddr = match normalized_addr.parse() {
            Ok(addr) => addr,
            Err(_) => {
                let v4_fallback = format!("0.0.0.0{}", addr_str);
                match v4_fallback.parse() {
                    Ok(addr) => addr,
                    Err(e) => {
                        error!("Invalid listen address '{}': {}", addr_str, e);
                        continue;
                    }
                }
            }
        };

        let listener = create_tcp_listener(socket_addr, config_arc.enable_tfo)?;
        info!("Listening on TCP: {}", socket_addr);

        let parser_clone = Arc::clone(&parser);
        let config_clone = Arc::clone(&config_arc);
        let cipher_clone = cipher.clone();
        let sem_clone = Arc::clone(&conn_semaphore);

        tokio::spawn(async move {
            run_listener(listener, parser_clone, config_clone, cipher_clone, sem_clone).await;
        });
    }

    tokio::signal::ctrl_c().await?;
    info!("Shutdown signal received. Exiting gracefully...");

    Ok(())
}

async fn run_listener(
    listener: TcpListener,
    parser: Arc<HandshakeParser>,
    config: Arc<Config>,
    cipher: CuteBiCipher,
    semaphore: Arc<Semaphore>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                tune_tcp_stream(&stream);
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        // 达到最大并发上限，主动关闭连接，保护系统内存不 OOM
                        warn!("Max concurrency limit ({}) reached, rejecting connection from {}", MAX_CONCURRENT_CONNECTIONS, peer_addr);
                        drop(stream);
                        continue;
                    }
                };

                let parser = Arc::clone(&parser);
                let config = Arc::clone(&config);
                let cipher = cipher.clone();

                tokio::spawn(async move {
                    let _permit = permit; // 任务结束自动释放并发许可
                    if let Err(e) = handle_client(stream, peer_addr, parser, config, cipher).await {
                        tracing::debug!("Client [{}] session finished: {}", peer_addr, e);
                    }
                });
            }
            Err(e) => {
                warn!("Listener accept error: {}", e);
            }
        }
    }
}

async fn handle_client(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    parser: Arc<HandshakeParser>,
    config: Arc<Config>,
    cipher: CuteBiCipher,
) -> anyhow::Result<()> {
    let mut header_buf = vec![0u8; 4096];
    
    // 带超时读取首个 HTTP 握手包，防止空连接永不释放耗尽 FD 和 RAM
    let n = timeout(HANDSHAKE_TIMEOUT, stream.read(&mut header_buf))
        .await
        .map_err(|_| anyhow::anyhow!("Client handshake timed out"))??;
        
    if n == 0 {
        return Ok(());
    }
    header_buf.truncate(n);

    let handshake = parser.parse(&header_buf)?;

    if let Some(resp) = handshake.response_header {
        stream.write_all(&resp).await?;
    }

    match handshake.session_type {
        SessionType::Tcp { target_host } => {
            tracing::debug!("Establishing TCP tunnel for [{}] -> [{}]", peer_addr, target_host);
            let target_stream = timeout(DIAL_TIMEOUT, DirectOutbound::dial_tcp(&target_host))
                .await
                .map_err(|_| anyhow::anyhow!("Dial target host {} timed out", target_host))??;

            pump_tcp_stream(
                stream,
                target_stream,
                cipher,
                config.tcp_timeout_duration(),
                handshake.remaining_data,
            )
            .await?;
        }
        SessionType::Udp => {
            let udp_socket = DirectOutbound::bind_udp(true).await?;
            let tunnel = UdpTunnel::new(
                stream,
                udp_socket,
                cipher,
                config.udp_timeout_duration(),
            );
            tunnel.run(handshake.remaining_data).await?;
        }
        SessionType::DnsTcpOverUdp { target_host } => {
            handle_dns_tcp_over_udp(
                stream,
                &target_host,
                cipher,
                config.udp_timeout_duration(),
                handshake.remaining_data,
            )
            .await?;
        }
        SessionType::HttpDns { domain, is_ipv6 } => {
            handle_http_dns(stream, &domain, is_ipv6).await?;
        }
    }

    Ok(())
}
