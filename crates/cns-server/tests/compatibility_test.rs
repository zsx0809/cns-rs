use cns_core::crypto::CuteBiCipher;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn test_full_pipeline_tcp_proxy() {
    let password = b"test_mock_password";
    let cipher = CuteBiCipher::new(password);

    // 1. 启动一个 Mock 目标服务器 (Target Echo Server)
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = target_listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let _ = stream.write_all(&buf[..n]).await;
    });

    // 2. 启动本地 CNS 服务端
    let cns_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cns_addr = cns_listener.local_addr().unwrap();

    let cipher_server = cipher.clone();
    tokio::spawn(async move {
        let (mut client_stream, _) = cns_listener.accept().await.unwrap();
        
        let parser = cns_core::protocol::HandshakeParser::new(
            "Meng",
            "httpUDP",
            cipher_server.clone(),
            true,
        );

        let mut header_buf = vec![0u8; 1024];
        let n = client_stream.read(&mut header_buf).await.unwrap();
        header_buf.truncate(n);

        let handshake = parser.parse(&header_buf).unwrap();
        client_stream.write_all(&handshake.response_header.unwrap()).await.unwrap();

        match handshake.session_type {
            cns_core::protocol::SessionType::Tcp { target_host } => {
                let target_stream = TcpStream::connect(target_host).await.unwrap();
                cns_server::tunnel::pump_tcp_stream(
                    client_stream,
                    target_stream,
                    cipher_server,
                    Duration::from_secs(5),
                ).await.unwrap();
            }
            _ => panic!("Expected TCP session"),
        }
    });

    // 3. 模拟免流客户端连入 CNS
    let mut client = TcpStream::connect(cns_addr).await.unwrap();

    let encrypted_target = cipher.encrypt_host(&target_addr.to_string());
    let req_header = format!(
        "CONNECT mclient.alipay.com:443 HTTP/1.1\r\nHost: mclient.alipay.com\r\nMeng: {}\r\n\r\n",
        encrypted_target
    );

    client.write_all(req_header.as_bytes()).await.unwrap();

    let mut resp_buf = [0u8; 1024];
    let n = client.read(&mut resp_buf).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
    assert!(resp_str.contains("200 Connection established"));

    // 4. 发送加密载荷
    let raw_payload = b"CuteBi-RS Ultra High Performance Test 2026";
    let mut send_payload = raw_payload.to_vec();
    cipher.crypt_in_place(&mut send_payload, 0);

    client.write_all(&send_payload).await.unwrap();

    // 5. 校验 Echo
    let mut recv_buf = [0u8; 1024];
    let n = client.read(&mut recv_buf).await.unwrap();
    let mut received = recv_buf[..n].to_vec();
    cipher.crypt_in_place(&mut received, 0);

    assert_eq!(&received, raw_payload);
}
