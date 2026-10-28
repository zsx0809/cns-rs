//! 真实服务端全流程集成测试。
//!
//! 旧测试在测试里手搓了一份 mock server，与被测代码不同源 —— mock 通过不代表
//! 真服务可用。这里一律通过 `cns_server::serve::RunningServer` 启动真实监听、
//! 真实握手与真实转发。

use cns_core::crypto::CuteBiCipher;
use cns_server::config::Config;
use cns_server::serve::RunningServer;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const PASSWORD: &str = "test-keystream-tstkey";

fn base_config() -> Config {
    Config {
        listen_addr: vec![":0".to_string()],
        proxy_key: "Meng".to_string(),
        udp_flag: "httpUDP".to_string(),
        encrypt_password: PASSWORD.to_string(),
        tcp_timeout: 5,
        udp_timeout: 3,
        handshake_timeout: 5,
        dial_timeout: 5,
        // 测试目标都是 127.0.0.1，必须放开私网回源
        allow_private_targets: true,
        enable_tfo: false,
        transparent: false,
        ..Default::default()
    }
}

/// 起一个 TCP 回显目标端
async fn echo_target() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
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
    (addr, handle)
}

async fn wait_connected(addr: std::net::SocketAddr) -> TcpStream {
    for _ in 0..50 {
        if let Ok(s) = TcpStream::connect(addr).await {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("cannot connect to {addr}");
}

/// 发一个免流 TCP 会话并回显验证
async fn tcp_session_probe(
    server: std::net::SocketAddr,
    target: std::net::SocketAddr,
    cipher: &CuteBiCipher,
) -> anyhow::Result<()> {
    let mut client = wait_connected(server).await;
    let enc = cipher.encrypt_host(&target.to_string());
    let req = format!("GET / HTTP/1.1\r\nHost: mclient.alipay.com\r\nMeng: {enc}\r\n\r\n");
    client.write_all(req.as_bytes()).await?;

    // 读响应头（必须靠流式读取处理粘包）
    let mut resp = Vec::new();
    let mut tmp = [0u8; 256];
    let mut head_done = false;
    while !head_done {
        let n = timeout(Duration::from_secs(3), client.read(&mut tmp)).await??;
        if n == 0 {
            break;
        }
        resp.extend_from_slice(&tmp[..n]);
        if resp.windows(4).any(|w| w == b"\r\n\r\n") {
            head_done = true;
        }
    }
    let text = String::from_utf8_lossy(&resp).to_string();
    anyhow::ensure!(text.contains("200"), "bad handshake response: {text}");

    // 发载荷并验证回显
    let payload = b"CuteBi-RS real server end-to-end payload 2026";
    let mut enc_payload = payload.to_vec();
    cipher.crypt_in_place(&mut enc_payload, 0);
    client.write_all(&enc_payload).await?;

    let mut got = vec![0u8; payload.len()];
    timeout(Duration::from_secs(3), client.read_exact(&mut got))
        .await
        .map_err(|_| anyhow::anyhow!("echo timed out"))??;
    cipher.crypt_in_place(&mut got, 0);
    anyhow::ensure!(got == payload, "payload mismatch");
    Ok(())
}

#[tokio::test]
async fn real_server_proxies_encrypted_tcp_session() {
    let (target, _t) = echo_target().await;
    let server = RunningServer::start(base_config()).await.unwrap();
    let cipher = CuteBiCipher::new(PASSWORD.as_bytes());

    tcp_session_probe(server.addr(), target, &cipher)
        .await
        .expect("TCP session must work end-to-end");

    assert_eq!(server.total_sessions(), 1);
    server.stop().await;
}

/// P0 回归 #1：监听 [::]:port 必须同时接受 IPv4 客户端。
/// 旧实现 set_only_v6(true) 会让 IPv4-only 移动网络完全连不上。
#[tokio::test]
async fn dualstack_listener_accepts_ipv4_clients() {
    let mut cfg = base_config();
    cfg.listen_addr = vec![":0".to_string()];
    let server = RunningServer::start(cfg).await.unwrap();
    let addr = server.addr();
    let (target, _t) = echo_target().await;

    // 绑到的地址应是 IPv6 通配，但 127.0.0.1 必须连得进去
    assert!(addr.is_ipv6(), "wildcard bind should yield an IPv6 socket, got {addr}");
    let v4: std::net::SocketAddr = format!("127.0.0.1:{}", addr.port()).parse().unwrap();
    let cipher = CuteBiCipher::new(PASSWORD.as_bytes());
    tcp_session_probe(v4, target, &cipher)
        .await
        .expect("IPv4 client must be served by the dual-stack listener");
    server.stop().await;
}

/// P0 回归 #4：握手响应与首段数据粘在同一个 TCP 段里时，残余数据不能丢。
#[tokio::test]
async fn server_forwards_target_first_push_banner() {
    // 目标端在客户端发数据之前先推送（SSH banner 语义）
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (s, _) = listener.accept().await.unwrap();
        let (mut r, mut w) = s.into_split();
        let _ = w.write_all(b"SSH-2.0-OpenSSH_9.9\r\n").await;
        let mut sink = [0u8; 64];
        let _ = r.read(&mut sink).await;
    });

    let server = RunningServer::start(base_config()).await.unwrap();
    let cipher = CuteBiCipher::new(PASSWORD.as_bytes());
    let enc = cipher.encrypt_host(&target.to_string());
    let mut client = wait_connected(server.addr()).await;
    client
        .write_all(
            format!("CONNECT host HTTP/1.1\r\nHost: mclient.alipay.com\r\nMeng: {enc}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();

    // 读响应头 + 紧随其后的 banner（可能同段返回）
    let mut acc = Vec::new();
    let mut tmp = [0u8; 512];
    let deadline = Duration::from_secs(3);
    let sub = 0usize;
    loop {
        let n =
            timeout(deadline, client.read(&mut tmp)).await.expect("no data at all").expect("read");
        if n == 0 {
            break;
        }
        acc.extend_from_slice(&tmp[..n]);
        if acc.windows(4).any(|w| w == b"\r\n\r\n") {
            // 头之后的部分即 banner，需要解密
            let idx = acc.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
            if acc.len() > idx {
                let mut tail = acc[idx..].to_vec();
                cipher.crypt_in_place(&mut tail, sub);
                assert!(
                    tail.starts_with(b"SSH-2.0"),
                    "sticky banner lost: got {:?}",
                    String::from_utf8_lossy(&tail)
                );
                break;
            }
        }
    }
    server.stop().await;
}

/// P0 回归（旧服务端）：短前缀（不足 8 字节）不能被误判成 httpUDP
#[tokio::test]
async fn short_get_prefix_is_not_misread_as_udp() {
    let server = RunningServer::start(base_config()).await.unwrap();
    let mut client = wait_connected(server.addr()).await;
    // 只发 "GET" 然后停住：服务端应等到握手超时后关闭，而不是当 UDP 会话跑起来
    client.write_all(b"GET").await.unwrap();
    let mut buf = [0u8; 16];
    let res = timeout(Duration::from_millis(300), client.read(&mut buf)).await;
    assert!(res.is_err(), "server must not reply as if this were a UDP session");
    server.stop().await;
}

/// 配置错误必须拒绝启动，不能静默变成无口令开放代理
#[test]
fn broken_config_refuses_to_start() {
    let dir = std::env::temp_dir().join(format!("cns-broken-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.json");
    std::fs::write(&path, r#"{"listen_addr": [":1254"] "proxy_key": "Meng"}"#).unwrap();
    let err = Config::from_file(&path).unwrap_err();
    assert!(err.to_string().contains("invalid JSON"), "{err}");

    // 合法但危险语义的配置文件也要能读出来
    std::fs::write(
        &path,
        r#"{"listen_addr":[":1254"],"encrypt_password":"p","tcp_timeout":300,"udp_timeout":30}"#,
    )
    .unwrap();
    let cfg = Config::from_file(&path).unwrap();
    assert!(!cfg.ipv6_only);
    assert!(!cfg.allow_private_targets);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn per_ip_limit_rejects_excess_connections() {
    let mut cfg = base_config();
    cfg.max_connections_per_ip = 2;
    let server = RunningServer::start(cfg).await.unwrap();

    let mut conns = Vec::new();
    for _ in 0..6 {
        conns.push(wait_connected(server.addr()).await);
    }
    // 全部连接都来自 127.0.0.1：只有 2 个会真正进入会话处理，
    // 其余在 accept 阶段就被丢弃（对客户端表现为立刻 EOF）
    let mut accepted = 0usize;
    for c in conns.iter_mut() {
        let mut buf = [0u8; 4];
        match timeout(Duration::from_millis(200), c.read(&mut buf)).await {
            Ok(Ok(0)) => {}             // 立刻被拒
            Ok(Ok(_)) => accepted += 1, // 收到数据说明进入了会话
            Ok(Err(_)) => {}
            Err(_) => accepted += 1, // 挂着没数据 = 已被接纳在等请求
        }
    }
    // 允许一定时序抖动，只断言不是「全部放行」
    assert!(accepted <= 4, "per-IP limit not enforced: {accepted} of 6 behaved as accepted");
    drop(conns);
    server.stop().await;
}

#[tokio::test]
async fn httpdns_is_refused_unless_enabled() {
    let mut cfg = base_config();
    cfg.enable_httpdns = false;
    let server = RunningServer::start(cfg).await.unwrap();
    let mut client = wait_connected(server.addr()).await;
    client
        .write_all(b"GET /vip.py?dn=www.baidu.com&type=A HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 128];
    let n = timeout(Duration::from_secs(2), client.read(&mut buf))
        .await
        .expect("no reply")
        .expect("read");
    let text = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(text.contains("403"), "expected refusal, got: {text}");
    server.stop().await;
}

#[tokio::test]
async fn httpdns_returns_record_when_enabled() {
    let mut cfg = base_config();
    cfg.enable_httpdns = true;
    // 上游指向一个不会答的端口，但查询目标是字面 IP → Resolver 直接返回，不依赖网络
    cfg.dns_upstream = vec!["127.0.0.1:1".to_string()];
    let server = RunningServer::start(cfg).await.unwrap();
    let mut client = wait_connected(server.addr()).await;
    client.write_all(b"GET /vip.py?dn=1.1.1.1&type=A HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
    let mut buf = [0u8; 512];
    let n = timeout(Duration::from_secs(2), client.read(&mut buf))
        .await
        .expect("no reply")
        .expect("read");
    let text = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(text.contains("200 OK"), "{text}");
    assert!(text.ends_with("1.1.1.1,60"), "{text}");
    server.stop().await;
}

/// httpUDP 隧道：走真实服务端 UdpTunnel（此前该路径只有老客户端能触达）
#[tokio::test]
async fn httpudp_tunnel_forwards_datagrams() {
    use bytes::{Bytes, BytesMut};
    use cns_core::protocol::{HttpUdpCodec, UdpPacket};
    use tokio::net::UdpSocket;
    use tokio_util::codec::{Decoder, Encoder};

    // 目标 UDP 回显端
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    tokio::spawn(async move {
        let mut b = [0u8; 1024];
        loop {
            if let Ok((n, from)) = peer.recv_from(&mut b).await {
                let _ = peer.send_to(&b[..n], from).await;
            }
        }
    });

    let server = RunningServer::start(base_config()).await.unwrap();
    let cipher = CuteBiCipher::new(PASSWORD.as_bytes());

    // httpUDP 免流头（客户端 render_udp_header 的等价形式）
    let mut client = wait_connected(server.addr()).await;
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: mclient.alipay.com\r\nhttpUDP: on\r\n\r\n")
        .await
        .unwrap();

    // 读 200
    let mut acc = BytesMut::new();
    let mut tmp = [0u8; 512];
    while !acc.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = timeout(Duration::from_secs(2), client.read(&mut tmp))
            .await
            .expect("no 200")
            .expect("read");
        if n == 0 {
            break;
        }
        acc.extend_from_slice(&tmp[..n]);
    }
    let text = String::from_utf8_lossy(&acc).to_string();
    assert!(text.contains("200"), "{text}");

    // 发一帧 httpUDP
    let mut codec = HttpUdpCodec::new();
    let mut frame = BytesMut::new();
    codec
        .encode(
            UdpPacket { peer: peer_addr, payload: Bytes::from_static(b"dlv-udp-hello") },
            &mut frame,
        )
        .unwrap();
    let mut wire = frame.to_vec();
    cipher.crypt_in_place(&mut wire, 0);
    client.write_all(&wire).await.unwrap();

    // 读回一帧：解密游标必须延续（服务端 s2c 方向也从 0 开始连续混淆）
    let mut buf = BytesMut::new();
    let mut in_sub = 0usize;
    let mut got = None;
    let started = std::time::Instant::now();
    while got.is_none() && started.elapsed() < Duration::from_secs(3) {
        let mut r = [0u8; 2048];
        match timeout(Duration::from_millis(800), client.read(&mut r)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(m)) => {
                let mut chunk = r[..m].to_vec();
                in_sub = cipher.crypt_in_place(&mut chunk, in_sub);
                buf.extend_from_slice(&chunk);
                got = codec.decode(&mut buf).ok().flatten();
            }
        }
    }
    let got = got.expect("no httpUDP reply within deadline");
    assert_eq!(got.peer, peer_addr);
    assert_eq!(&got.payload[..], b"dlv-udp-hello");
    server.stop().await;
}
