use clap::Parser;
use cns_client::config::ClientConfig;
use cns_client::inbound::{Socks5Command, Socks5Handshake};
use cns_client::outbound::CnsClientTunnel;
use cns_core::crypto::CuteBiCipher;
use cns_core::transport::tune_tcp_stream;
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
    info!("Loading client configuration from: {}", args.config);

    let config = match ClientConfig::from_file(&args.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!("Failed to read {}: {}. Falling back to default client configuration.", args.config, e);
            ClientConfig::default()
        }
    };

    let cipher = CuteBiCipher::new(config.cns_password.as_bytes());
    let config_arc = Arc::new(config);
    let cipher_arc = Arc::new(cipher);

    let listener = TcpListener::bind(&config_arc.socks5_listen).await?;
    info!("SOCKS5 Inbound listening on: {}", config_arc.socks5_listen);
    info!("Upstream CNS Server: {}", config_arc.cns_server);

    let config_clone = Arc::clone(&config_arc);
    let cipher_clone = Arc::clone(&cipher_arc);

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut stream, peer_addr)) => {
                    tune_tcp_stream(&stream);
                    let cfg = Arc::clone(&config_clone);
                    let cph = Arc::clone(&cipher_clone);

                    tokio::spawn(async move {
                        match Socks5Handshake::handle(&mut stream).await {
                            Ok(Socks5Command::Connect { target }) => {
                                tracing::debug!("Proxying connection to [{}] from [{}]", target, peer_addr);
                                if let Err(e) = CnsClientTunnel::handle_tcp_proxy(stream, &target, &cfg, &cph).await {
                                    tracing::debug!("TCP proxy session ended: {}", e);
                                }
                            }
                            Ok(Socks5Command::UdpAssociate) => {
                                warn!("UDP Associate requested from [{}]. Currently prioritizing stream proxy.", peer_addr);
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
    });

    tokio::signal::ctrl_c().await?;
    info!("Shutdown signal received. Exiting client...");

    Ok(())
}
