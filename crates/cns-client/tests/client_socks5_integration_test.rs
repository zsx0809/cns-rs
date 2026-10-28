//! 客户端 <-> 真实服务端 的端到端集成测试。
//!
//! 旧版这个测试在测试里手搓了一份 mock CNS server，跟真实的 `cns-server`
//! 不同源 —— mock 通过不代表真服务可用。现在直接起真实的
//! `cns_server::serve::RunningServer`，走完整的「SOCKS5 -> 隧道 -> 服务端 -> 目标」链路。

use cns_client::config::ClientConfig;
use cns_client::inbound::{Socks5Command, Socks5Handshake};
use cns_client::outbound::CnsClientTunnel;
use cns_core::crypto::CuteBiCipher;
use cns_server::config::Config as ServerConfig;
use cns_server::serve::RunningServer;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const PASSWORD: &str = "e2e-shared-password";

async fn echo_target() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

fn client_config(server: SocketAddr) -> ClientConfig {
    ClientConfig {
        socks5_listen: String::new(),
        dns_listen: String::new(),
        tproxy_listen: None,
        gid: None,
        cns_server: server.to_string(),
        cns_password: PASSWORD.to_string(),
        proxy_key: "Meng".to_string(),
        udp_flag: "httpUDP".to_string(),
        header_host: "mclient.alipay.com".to_string(),
        custom_header: None,
        enable_tfo: false,
        timeout_seconds: 5,
        ..Default::default()
    }
}

fn server_config(listen: Vec<String>) -> ServerConfig {
    ServerConfig {
        listen_addr: listen,
        proxy_key: "Meng".to_string(),
        udp_flag: "httpUDP".to_string(),
        encrypt_password: PASSWORD.to_string(),
        tcp_timeout: 5,
        udp_timeout: 3,
        handshake_timeout: 5,
        dial_timeout: 5,
        // 测试目标都在环回上
        allow_private_targets: true,
        enable_tfo: false,
        ..Default::default()
    }
}

/// 全链路：App -> SOCKS5 -> cns-client -> 真实 cns-server -> 目标
#[tokio::test]
async fn socks5_to_real_cns_server_end_to_end() {
    let target = echo_target().await;
    let server = RunningServer::start(server_config(vec![":0".to_string()])).await.unwrap();
    let cns_addr = server.addr();

    // 本地 SOCKS5 入口
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = listener.local_addr().unwrap();
    let cfg = client_config(cns_addr);
    let cipher = CuteBiCipher::new(PASSWORD.as_bytes());

    tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(cmd) = Socks5Handshake::handle(&mut stream).await else {
            return;
        };
        if let Socks5Command::Connect { target } = cmd {
            let pool = cns_core::transport::BufferPool::new();
            let _ = CnsClientTunnel::handle_tcp_proxy(stream, target, cfg, cipher, pool).await;
        }
    });

    let mut app = TcpStream::connect(socks_addr).await.unwrap();
    app.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut auth = [0u8; 2];
    app.read_exact(&mut auth).await.unwrap();
    assert_eq!(auth, [0x05, 0x00]);

    let mut req: Vec<u8> = vec![0x05, 0x01, 0x00, 0x01];
    let SocketAddr::V4(target_v4) = target else {
        panic!("test target must be IPv4");
    };
    req.extend_from_slice(&target_v4.ip().octets());
    req.extend_from_slice(&target_v4.port().to_be_bytes());
    app.write_all(&req).await.unwrap();

    let mut reply = [0u8; 10];
    app.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "SOCKS5 CONNECT rejected: {reply:?}");

    let msg: &[u8] = b"GET /echo HTTP/1.1\r\nHost: real-cns-e2e\r\n\r\n";
    app.write_all(msg).await.unwrap();
    let mut got = vec![0u8; msg.len()];
    timeout(Duration::from_secs(8), app.read_exact(&mut got))
        .await
        .expect("echo timed out through the real server")
        .expect("read");
    assert_eq!(&got, msg);

    drop(app);
    server.stop().await;
}

/// 大载荷跨多个 32KB 缓冲：验证两端密钥流不会漂移
#[tokio::test]
async fn large_payload_keeps_keystream_aligned_end_to_end() {
    let target = echo_target().await;
    let server = RunningServer::start(server_config(vec![":0".to_string()])).await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = listener.local_addr().unwrap();
    let cfg = client_config(server.addr());
    let cipher = CuteBiCipher::new(PASSWORD.as_bytes());

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let Ok(Socks5Command::Connect { target }) = Socks5Handshake::handle(&mut stream).await
            else {
                break;
            };
            let pool = cns_core::transport::BufferPool::new();
            let _ = CnsClientTunnel::handle_tcp_proxy(
                stream,
                target,
                cfg.clone(),
                cipher.clone(),
                pool,
            )
            .await;
        }
    });

    let mut app = TcpStream::connect(socks_addr).await.unwrap();
    app.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut auth = [0u8; 2];
    app.read_exact(&mut auth).await.unwrap();
    let mut req: Vec<u8> = vec![0x05, 0x01, 0x00, 0x01];
    let SocketAddr::V4(target_v4) = target else {
        panic!("test target must be IPv4");
    };
    req.extend_from_slice(&target_v4.ip().octets());
    req.extend_from_slice(&target_v4.port().to_be_bytes());
    app.write_all(&req).await.unwrap();
    let mut reply = [0u8; 10];
    app.read_exact(&mut reply).await.unwrap();

    let blob: Vec<u8> = (0..200 * 1024).map(|i| (i * 131 + 7) as u8).collect();
    let expect = blob.len();
    // into_split：写端在独立任务里灌 200KB，读端回收
    let (mut app_reader, mut app_writer) = app.into_split();
    let payload = blob.clone();
    let writer_task = tokio::spawn(async move {
        app_writer.write_all(&payload).await.expect("write");
        app_writer
    });

    let mut got: Vec<u8> = Vec::with_capacity(expect);
    let mut tmp = [0u8; 32768];
    let started = std::time::Instant::now();
    while got.len() < expect && started.elapsed() < Duration::from_secs(30) {
        match app_reader.read(&mut tmp).await {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&tmp[..n]),
        }
    }
    assert_eq!(got.len(), expect, "truncated echo (got {})", got.len());
    assert_eq!(got, blob, "keystream drift over multi-chunk transfer");
    let _ = writer_task.await;
    drop(app_reader);
    server.stop().await;
}

/// 服务端拒绝（口令不匹配）必须让客户端明确失败，而不是静默挂住
#[tokio::test]
async fn wrong_password_fails_fast() {
    let mut scfg = server_config(vec![":0".to_string()]);
    scfg.encrypt_password = "totally-different".to_string();
    scfg.proxy_key = "Meng".to_string();
    let server = RunningServer::start(scfg).await.unwrap();

    let mut client = TcpStream::connect(server.addr()).await.unwrap();
    let cipher = CuteBiCipher::new(PASSWORD.as_bytes());
    let enc = cipher.encrypt_host("example.com:443");
    client
        .write_all(
            format!("GET / HTTP/1.1\r\nHost: mclient.alipay.com\r\nMeng: {enc}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();

    // 服务端解不出合法目标 -> 关闭连接；客户端应读到 EOF 而不是无限等待
    let mut buf = [0u8; 16];
    let n = timeout(Duration::from_secs(6), client.read(&mut buf))
        .await
        .expect("server hung instead of rejecting")
        .expect("read");
    assert_eq!(n, 0, "expected immediate close, got {n} bytes");
    server.stop().await;
}

/// 客户端在 DNS 中继不可用（无 root）时也必须能跑 TCP 会话
#[tokio::test]
async fn tcp_session_works_without_dns_relay() {
    let target = echo_target().await;
    let server = RunningServer::start(server_config(vec![":0".to_string()])).await.unwrap();
    let cfg = client_config(server.addr());
    let cipher = CuteBiCipher::new(PASSWORD.as_bytes());

    let (app_side, mut app_peer) = tokio::io::duplex(8192);
    let pool = cns_core::transport::BufferPool::new();
    let handle = tokio::spawn(CnsClientTunnel::handle_tcp_proxy(
        app_side,
        target.to_string(),
        cfg,
        cipher,
        pool,
    ));

    let msg = b"no-dns-needed";
    app_peer.write_all(msg).await.unwrap();
    let mut got = vec![0u8; msg.len()];
    timeout(Duration::from_secs(8), app_peer.read_exact(&mut got))
        .await
        .expect("no echo")
        .expect("read");
    assert_eq!(&got, msg);

    drop(app_peer);
    let _ = handle.await;
    server.stop().await;
}
