//! 客户端 TCP 会话：本地应用 <-> CNS 服务端。
//!
//! 数据泵复用 `cns_core::transport::pump`（与服务端同一份实现），这里只负责
//! 发起并校验免流 HTTP 握手。

use crate::config::ClientConfig;
use cns_core::crypto::CuteBiCipher;
use cns_core::transport::{
    connect_any_mss, pump_bidirectional_with_prefill, read_response_head, response_is_ok,
    BufferPool,
};
use std::io;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

pub struct CnsClientTunnel;

impl CnsClientTunnel {
    /// 与 CNS 服务端握手，然后建立双向代理泵。
    ///
    /// 修复清单：
    /// * 旧实现只 `read()` 一次 1024 字节就认定拿到完整响应，HTTP 响应被拆包时直接失败；
    /// * 响应头之后粘在同一 TCP 段里的数据（目标服务器率先推送的 banner 等）
    ///   被整包丢弃 —— 现在作为 `prefill_to_a` 交给 pump，并按本方向游标 0 解密，
    ///   后续数据继续沿同一条密钥流，不会错位。
    pub async fn handle_tcp_proxy<S>(
        local_stream: S,
        target_host: String,
        config: ClientConfig,
        cipher: CuteBiCipher,
        pool: BufferPool,
    ) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    {
        // tun_mtu 非 0 时在 connect 之前钳 MSS —— MTU 黑洞（大文件传到固定字节数就卡死）
        // 的用户态解法，与 README 承诺的字段对齐；默认 0 = 保持原行为。
        let mut server_stream =
            connect_any_mss(&config.cns_server, config.enable_tfo, config.tun_mtu).await?;

        // 混淆目标地址并组装 HTTP 伪装头
        let encrypted_target =
            if cipher.is_empty() { target_host.clone() } else { cipher.encrypt_host(&target_host) };
        // 必须带超时：`enable_tfo=true`（默认）时 TCP_FASTOPEN_CONNECT 让 connect()
        // 不产生 SYN，真正的建连发生在这一次 write 上。没有超时的话，一旦路由黑洞，
        // 单个会话会卡到内核超时（实测可达 ~127 s），期间一直占着并发 permit。
        timeout(config.timeout(), server_stream.write_all(&config.render_fake_header(&encrypted_target)))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "handshake write timed out")
            })??;

        // 严格流式读取响应头
        let (head, sticky) = read_response_head(
            &mut server_stream,
            config.timeout(),
            config.max_handshake_response(),
        )
        .await?;
        if !response_is_ok(&head) {
            let text = String::from_utf8_lossy(&head).to_string();
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("CNS handshake failed: {}", text.trim()),
            ));
        }

        // 借用共享池：BufferPool 内部是 Arc，按引用传给 pump 即可
        pump_bidirectional_with_prefill(
            local_stream,
            server_stream,
            cipher,
            config.timeout(),
            &pool,
            // 本地应用侧没有握手残余
            Vec::new(),
            // 服务端响应之后的粘包（密文，由 pump 按本方向游标解密）
            sticky.to_vec(),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cns_core::transport::BufferPool;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    const KEY: &[u8] = b"tunnel-test-key";

    fn config_for(server: SocketAddr) -> ClientConfig {
        ClientConfig {
            socks5_listen: String::new(),
            dns_listen: String::new(),
            tproxy_listen: None,
            gid: None,
            cns_server: server.to_string(),
            cns_password: String::from_utf8(KEY.to_vec()).unwrap(),
            proxy_key: "Meng".to_string(),
            udp_flag: "httpUDP".to_string(),
            header_host: "mclient.alipay.com".to_string(),
            custom_header: None,
            enable_tfo: false,
            timeout_seconds: 3,
            ..Default::default()
        }
    }

    /// 一个「够用」的 CNS 服务端替身：解析伪装头 -> 回 200 -> 与目标做双向搬运。
    /// 用真实 cns-core API 而非手搓协议，减少测试自身的假象。
    async fn fake_cns_server(
        listener: TcpListener,
        cipher: Arc<CuteBiCipher>,
        target_addr: SocketAddr,
    ) {
        let Ok((mut cns, _)) = listener.accept().await else {
            return;
        };
        // 读明文伪装头
        let mut acc: Vec<u8> = Vec::new();
        let mut t = [0u8; 512];
        let header_end;
        loop {
            let n = cns.read(&mut t).await.unwrap_or(0);
            if n == 0 {
                return;
            }
            acc.extend_from_slice(&t[..n]);
            if let Some(idx) = acc.windows(4).position(|w| w == b"\r\n\r\n") {
                header_end = idx + 4;
                break;
            }
            if acc.len() > 8192 {
                return;
            }
        }
        let idx = header_end;
        // 头之后的残余属于「客户端 -> 目标」方向，从游标 0 解密
        let mut client_prefill = acc[idx..].to_vec();
        if !cipher.is_empty() {
            cipher.crypt_in_place(&mut client_prefill, 0);
        }

        cns.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.unwrap();

        let target = TcpStream::connect(target_addr).await.unwrap();
        let c2 = Arc::clone(&cipher);
        let c3 = Arc::clone(&cipher);
        let (mut cr, mut cw) = cns.into_split();
        let (mut tr, mut tw) = target.into_split();

        // 残余之后的游标 = 已消耗字节数 mod 展开表长
        let fwd_sub =
            if client_prefill.is_empty() { 0 } else { client_prefill.len() % c2.key_len().max(1) };
        let fwd = async move {
            let prefill = client_prefill;
            if !prefill.is_empty() {
                // 已在上面按游标 0 解出明文，这里直接送目标
                let _ = tw.write_all(&prefill).await;
            }
            let mut buf = vec![0u8; 4096];
            let mut sub = fwd_sub;
            loop {
                let n = match cr.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let mut chunk = buf[..n].to_vec();
                if !c2.is_empty() {
                    sub = c2.crypt_in_place(&mut chunk, sub);
                }
                if tw.write_all(&chunk).await.is_err() {
                    break;
                }
            }
        };

        let rev = async move {
            let mut buf = vec![0u8; 4096];
            let mut sub = 0usize;
            loop {
                let n = match tr.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let mut chunk = buf[..n].to_vec();
                if !c3.is_empty() {
                    sub = c3.crypt_in_place(&mut chunk, sub);
                }
                if cw.write_all(&chunk).await.is_err() {
                    break;
                }
            }
        };
        let _ = tokio::join!(fwd, rev);
    }

    async fn echo_target() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut b = vec![0u8; 8192];
                    loop {
                        match s.read(&mut b).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&b[..n]).await.is_err() {
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

    use tokio::net::TcpStream;

    #[tokio::test]
    async fn proxy_roundtrip_with_handshake_residue() {
        let target = echo_target().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cns_addr = listener.local_addr().unwrap();
        let cipher = Arc::new(CuteBiCipher::new(KEY));
        let c = Arc::clone(&cipher);

        tokio::spawn(async move {
            fake_cns_server(listener, c, target).await;
        });

        let (mut app, local) = tokio::io::duplex(8192);
        let cfg = config_for(cns_addr);
        let pool = BufferPool::new();
        let cipher2 = (*cipher).clone();
        let handle = tokio::spawn(async move {
            let target_str = target.to_string();
            CnsClientTunnel::handle_tcp_proxy(local, target_str, cfg, cipher2, pool).await
        });

        let payload = b"GET /echo HTTP/1.1\r\nHost: mock\r\n\r\n";
        app.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        timeout(std::time::Duration::from_secs(5), app.read_exact(&mut got))
            .await
            .expect("no echo through tunnel")
            .expect("read");
        assert_eq!(&got, payload);

        drop(app);
        let _ = handle.await;
    }

    /// 关键回归：目标端先推数据且与 200 响应粘在同一段，旧实现会丢这段数据
    #[tokio::test]
    async fn server_first_banner_survives_sticky_response() {
        let banner: &[u8] = b"SSH-2.0-OpenSSH_9.9\r\n";
        let cipher = Arc::new(CuteBiCipher::new(KEY));

        // 目标端：一连上就先推 banner
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = target_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = target_listener.accept().await.unwrap();
            let _ = s.write_all(banner).await;
            let mut sink = [0u8; 64];
            let _ = s.read(&mut sink).await;
        });

        // 假 CNS 服务端：把 banner 加密后与 200 响应写进同一段
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cns_addr = listener.local_addr().unwrap();
        {
            let c = Arc::clone(&cipher);
            let mut enc_banner = banner.to_vec();
            c.crypt_in_place(&mut enc_banner, 0);
            tokio::spawn(async move {
                let (mut cns, _) = listener.accept().await.unwrap();
                let mut acc: Vec<u8> = Vec::new();
                let mut t = [0u8; 512];
                loop {
                    let n = cns.read(&mut t).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    acc.extend_from_slice(&t[..n]);
                    if acc.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                // 响应头 + 残余 一次写出
                let mut out: Vec<u8> = b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec();
                out.extend_from_slice(&enc_banner);
                cns.write_all(&out).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            });
        }

        let (mut app, local) = tokio::io::duplex(8192);
        let cfg = config_for(cns_addr);
        let pool = BufferPool::new();
        let c = Arc::clone(&cipher);
        tokio::spawn(async move {
            let _ = CnsClientTunnel::handle_tcp_proxy(
                local,
                target.to_string(),
                cfg,
                (*c).clone(),
                pool,
            )
            .await;
        });

        let mut got = vec![0u8; banner.len()];
        timeout(std::time::Duration::from_secs(5), app.read_exact(&mut got))
            .await
            .expect("banner must not be lost")
            .expect("read");
        assert_eq!(&got, banner);
    }

    /// 服务端拒绝握手时必须报错而不是当作可用隧道
    #[tokio::test]
    async fn handshake_rejection_is_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cns_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut b = [0u8; 256];
                let _ = s.read(&mut b).await;
                let _ = s.write_all(b"HTTP/1.0 403 Forbidden\r\n\r\n").await;
            }
        });

        let (app, local) = tokio::io::duplex(1024);
        let cfg = config_for(cns_addr);
        let pool = BufferPool::new();
        let cipher = CuteBiCipher::new(KEY);
        let err = CnsClientTunnel::handle_tcp_proxy(
            local,
            "example.com:443".to_string(),
            cfg,
            cipher,
            pool,
        )
        .await
        .expect_err("must fail");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
        drop(app);
    }

    /// 明文伪装头里必须带上被混淆的目标（免流的根本），且目标解析正确
    #[tokio::test]
    async fn fake_header_carries_encrypted_target() {
        let seen = Arc::new(AtomicU64::new(0));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cns_addr = listener.local_addr().unwrap();
        let cipher = Arc::new(CuteBiCipher::new(KEY));
        let s = Arc::clone(&seen);
        let c = Arc::clone(&cipher);
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut b = [0u8; 1024];
            let n = sock.read(&mut b).await.unwrap_or(0);
            let text = String::from_utf8_lossy(&b[..n]).to_string();
            // 头必须是明文 HTTP + Meng 头，且值不等于明文目标（已被混淆）
            if text.starts_with("GET / HTTP/1.1\r\n")
                && text.contains("Host: mclient.alipay.com\r\n")
                && text.contains("Meng: ")
                && !text.contains("203.0.113.7:443")
            {
                // 反向解出目标验证
                if let Some(line) = text.lines().find(|l| l.starts_with("Meng:")) {
                    if let Some(val) = line.split(':').nth(1) {
                        if let Ok(host) = c.decrypt_host(val.trim().as_bytes()) {
                            if host == "203.0.113.7:443" {
                                s.store(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }
            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
        });

        let (app, local) = tokio::io::duplex(1024);
        let cfg = config_for(cns_addr);
        let pool = BufferPool::new();
        let cipher_owned = (*cipher).clone();
        let h = tokio::spawn(CnsClientTunnel::handle_tcp_proxy(
            local,
            "203.0.113.7:443".to_string(),
            cfg,
            cipher_owned,
            pool,
        ));
        // 立刻断开本地侧让会话结束
        drop(app);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), h).await;
        assert_eq!(seen.load(Ordering::Relaxed), 1, "obfuscated header wrong");
    }
}
