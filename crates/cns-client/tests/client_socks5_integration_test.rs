use cns_client::config::ClientConfig;
use cns_client::inbound::{Socks5Command, Socks5Handshake};
use cns_client::outbound::CnsClientTunnel;
use cns_core::crypto::CuteBiCipher;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn test_socks5_to_cns_server_end_to_end() {
    let password = "client_pwd_888";
    let cipher = CuteBiCipher::new(password.as_bytes());

    // 1. 目标真实 Echo 服务器 (Web/App)
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = target_listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let _ = stream.write_all(&buf[..n]).await;
    });

    // 2. 远端 CNS 服务端
    let cns_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cns_addr = cns_listener.local_addr().unwrap();

    let server_cipher = cipher.clone();
    tokio::spawn(async move {
        let (mut client_stream, _) = cns_listener.accept().await.unwrap();
        let parser = cns_core::protocol::HandshakeParser::new(
            "Meng",
            "httpUDP",
            server_cipher.clone(),
            true,
        );

        let mut header_buf = vec![0u8; 1024];
        let n = client_stream.read(&mut header_buf).await.unwrap();
        header_buf.truncate(n);

        let handshake = parser.parse(&header_buf).unwrap();
        client_stream.write_all(&handshake.response_header.unwrap()).await.unwrap();

        if let cns_core::protocol::SessionType::Tcp { target_host } = handshake.session_type {
            let target_stream = TcpStream::connect(target_host).await.unwrap();
            cns_server::tunnel::pump_tcp_stream(
                client_stream,
                target_stream,
                server_cipher,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        }
    });

    // 3. 本地 cns-client (SOCKS5 服务)
    let client_config = ClientConfig {
        socks5_listen: "127.0.0.1:0".to_string(),
        tproxy_listen: None,
        gid: None,
        cns_server: cns_addr.to_string(),
        cns_password: password.to_string(),
        proxy_key: "Meng".to_string(),
        udp_flag: "httpUDP".to_string(),
        header_host: "mclient.alipay.com".to_string(),
        custom_header: None,
        enable_tfo: true,
        timeout_seconds: 5,
    };

    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks5_addr = client_listener.local_addr().unwrap();

    let client_cipher = cipher.clone();
    let cfg = client_config.clone();
    tokio::spawn(async move {
        let (mut stream, _) = client_listener.accept().await.unwrap();
        let cmd = Socks5Handshake::handle(&mut stream).await.unwrap();
        if let Socks5Command::Connect { target } = cmd {
            CnsClientTunnel::handle_tcp_proxy(stream, &target, &cfg, &client_cipher).await.unwrap();
        }
    });

    // 4. 模拟本地任意应用程序通过标准 SOCKS5 发起访问
    let mut app = TcpStream::connect(socks5_addr).await.unwrap();

    // SOCKS5 握手认证
    app.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut auth_resp = [0u8; 2];
    app.read_exact(&mut auth_resp).await.unwrap();
    assert_eq!(auth_resp, [0x05, 0x00]);

    // SOCKS5 发送 CONNECT 请求
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    if let std::net::SocketAddr::V4(v4) = target_addr {
        req.extend_from_slice(&v4.ip().octets());
        req.extend_from_slice(&v4.port().to_be_bytes());
    } else {
        panic!("Mock server is IPv4");
    }

    app.write_all(&req).await.unwrap();

    let mut connect_resp = [0u8; 10];
    app.read_exact(&mut connect_resp).await.unwrap();
    assert_eq!(connect_resp[1], 0x00); // 成功连接

    // 5. 应用正常发送明文 HTTP/TCP 载荷
    let app_msg = b"GET /echo HTTP/1.1\r\nHost: mock-target.local\r\n\r\n";
    app.write_all(app_msg).await.unwrap();

    let mut app_recv = [0u8; 1024];
    let n = app.read(&mut app_recv).await.unwrap();

    // 验证经过 CNS 混淆免流加密隧道后，应用端透明无感收到了原始数据！
    assert_eq!(&app_recv[..n], app_msg);
}
