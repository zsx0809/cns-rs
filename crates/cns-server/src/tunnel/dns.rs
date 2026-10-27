use cns_core::crypto::CuteBiCipher;
use std::io;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::debug;

/// 原版 CuteBi HttpDNS 快速响应
pub async fn handle_http_dns(
    mut client: TcpStream,
    domain: &str,
    is_ipv6: bool,
) -> io::Result<()> {
    let lookup_target = format!("{}:80", domain);
    let mut resolved_ip: Option<String> = None;

    if let Ok(addrs) = tokio::net::lookup_host(&lookup_target).await {
        for addr in addrs {
            match addr.ip() {
                std::net::IpAddr::V4(v4) => {
                    if !is_ipv6 {
                        resolved_ip = Some(format!("{},60", v4));
                        break;
                    }
                }
                std::net::IpAddr::V6(v6) => {
                    if is_ipv6 {
                        resolved_ip = Some(format!("{},60", v6));
                        break;
                    }
                }
            }
        }
    }

    let response = if let Some(ip_str) = resolved_ip {
        format!(
            "HTTP/1.0 200 OK\r\nConnection: Close\r\nServer: CuteBi Linux Network httpDNS, (%>w<%)\r\nContent-Length: {}\r\n\r\n{}",
            ip_str.len(),
            ip_str
        )
    } else {
        "HTTP/1.0 404 Not Found\r\nConnection: Close\r\nServer: CuteBi Linux Network httpDNS, (%>w<%)\r\nContent-type: text/plain\r\n\r\nDNS Lookup Failed".to_string()
    };

    client.write_all(response.as_bytes()).await?;
    let _ = client.shutdown().await;
    Ok(())
}

/// 强化版 DNS TCP-over-UDP 处理 (支持首包粘包数据)
pub async fn handle_dns_tcp_over_udp(
    mut client: TcpStream,
    dns_server: &str,
    cipher: CuteBiCipher,
    timeout_duration: Duration,
    initial_data: Vec<u8>,
) -> io::Result<()> {
    let mut buffer = initial_data;

    // 确保读取到至少 2 字节长度前缀
    while buffer.len() < 2 {
        let mut tmp = [0u8; 512];
        let n = timeout(timeout_duration, client.read(&mut tmp))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS len read timeout"))??;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Client closed"));
        }
        buffer.extend_from_slice(&tmp[..n]);
    }

    // 解密前两字节
    let mut len_bytes = [buffer[0], buffer[1]];
    if !cipher.is_empty() {
        cipher.crypt_in_place(&mut len_bytes, 0);
    }
    let dns_pkg_len = u16::from_be_bytes(len_bytes) as usize;

    if dns_pkg_len > 4096 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "DNS package too large"));
    }

    let total_required = 2 + dns_pkg_len;

    // 确保读取到完整 DNS 请求报文
    while buffer.len() < total_required {
        let mut tmp = [0u8; 1024];
        let n = timeout(timeout_duration, client.read(&mut tmp))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS body read timeout"))??;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Client closed"));
        }
        buffer.extend_from_slice(&tmp[..n]);
    }

    // 提取并解密 DNS 请求报文体
    let mut query_payload = buffer[2..total_required].to_vec();
    if !cipher.is_empty() {
        cipher.crypt_in_place(&mut query_payload, 2);
    }

    // 通过本地 UDP Socket 向远端目标 DNS 发送
    let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
    timeout(timeout_duration, udp_socket.send_to(&query_payload, dns_server))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS send timed out"))??;

    // 接收远端 DNS 响应
    let mut resp_buf = vec![0u8; 4096];
    let (resp_len, _) = timeout(timeout_duration, udp_socket.recv_from(&mut resp_buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS recv timed out"))??;

    // 组装回传报文：[2 字节大端序长度] + [DNS 响应报文]
    let mut out_buf = Vec::with_capacity(2 + resp_len);
    out_buf.extend_from_slice(&(resp_len as u16).to_be_bytes());
    out_buf.extend_from_slice(&resp_buf[..resp_len]);

    if !cipher.is_empty() {
        cipher.crypt_in_place(&mut out_buf, 0);
    }

    timeout(timeout_duration, client.write_all(&out_buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS response timed out"))??;

    debug!("DNS query successfully answered: {} bytes", resp_len);
    Ok(())
}
