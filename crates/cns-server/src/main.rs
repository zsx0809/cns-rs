use clap::Parser;
use cns_server::config::Config;
use cns_server::serve::{bind_listeners, run_listener, ServerCtx};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(
    name = "cns-server",
    author = "CuteBi Modernizers",
    version = env!("CARGO_PKG_VERSION"),
    about = "Ultra-high-performance, zero-GC CuteBi Network Suite (CNS) server in pure Rust"
)]
struct Args {
    /// Path to JSON configuration file
    #[arg(short = 'c', long = "config", alias = "json", default_value = "config.json")]
    config: String,

    /// 配置缺失或损坏时仍用内置默认值启动。默认口令为空 = 明文，仅供本机调试。
    #[arg(long)]
    allow_defaults: bool,

    /// 覆盖监听地址（可重复），如 --listen 0.0.0.0:1254
    #[arg(short = 'l', long = "listen")]
    listen: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 生产环境安全日志：默认 warn 以上，避免热路径刷爆 VPS 磁盘
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();

    let args = Args::parse();

    // 关键修复：配置错误必须 fail-fast。
    // 旧实现解析失败后静默使用默认配置，而默认 encrypt_password 为空 = 明文开放代理。
    let mut config = match Config::from_file(&args.config) {
        Ok(cfg) => cfg,
        Err(e) if args.allow_defaults => {
            warn!("{e}");
            warn!("--allow-defaults given: starting with built-in defaults (UNSECURED).");
            Config::default()
        }
        Err(e) => {
            error!("{e}");
            return Err(e);
        }
    };

    if !args.listen.is_empty() {
        config.listen_addr = args.listen.clone();
    }

    if config.encrypt_password.is_empty() {
        warn!("encrypt_password is EMPTY — traffic is plain HTTP-visible. Set a password.");
    }
    if config.allow_private_targets {
        warn!("allow_private_targets=true — this server can reach private networks.");
    }

    info!(
        "cns-server {} starting (cipher={}, tfo={}, httpdns={}, per_ip_limit={})",
        env!("CARGO_PKG_VERSION"),
        !config.encrypt_password.is_empty(),
        config.enable_tfo,
        config.enable_httpdns,
        config.max_connections_per_ip
    );

    let ctx = Arc::new(ServerCtx::new(config));
    let listeners = bind_listeners(&ctx.config);
    if listeners.is_empty() {
        anyhow::bail!("no listener could be bound; check listen_addr and permissions");
    }

    let mut handles = Vec::new();
    for bound in listeners {
        let c = Arc::clone(&ctx);
        handles.push(tokio::spawn(run_listener(bound.listener, c)));
    }

    tokio::select! {
        res = tokio::signal::ctrl_c() => {
            if let Err(e) = res {
                error!("signal handler error: {e}");
            }
        }
        _ = ctx.shutdown.notified() => {}
    }

    info!("shutdown requested, draining {} active sessions", ctx.active_sessions());
    ctx.shutdown.notify_waiters();

    // 给在途连接一个排水窗口，超时才硬收
    let drain = Duration::from_secs(3);
    let started = std::time::Instant::now();
    while ctx.active_sessions() > 0 && started.elapsed() < drain {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let left = ctx.active_sessions();
    if left > 0 {
        warn!("drain window elapsed with {left} sessions still open");
    }
    let join_all = async move {
        for h in handles {
            let _ = h.await;
        }
    };
    let _ = timeout(Duration::from_secs(1), join_all).await;

    info!("cns-server stopped (served {} sessions total)", ctx.total_sessions());
    Ok(())
}
