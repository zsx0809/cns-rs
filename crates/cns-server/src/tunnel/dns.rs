use cns_core::crypto::CuteBiCipher;
use std::io;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::debug;

pub async fn handle_dns_tcp_over_udp(
    mut client: TcpStream,
    dns_server: &str,
    cipher: CuteBiCipher,
    timeout_duration: Duration,
) -> io::Result<()> {
    let mut len_buf = [0u8; 2];
    timeout(timeout_duration, client.read_exact(&mut len_buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS read len timed out"))??;

    if !cipher.is_empty() {
        cipher.crypt_in_place(&mut len_buf, 0);
    }

    let dns_pkg_len = u16::from_be_bytes(len_buf) as usize;
    if dns_pkg_len > 4096 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "DNS package too large"));
    }

    let mut query_buf = vec![0u8; dns_pkg_len];
    timeout(timeout_duration, client.read_exact(&mut query_buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS read query timed out"))??;

    if !cipher.is_empty() {
        cipher.crypt_in_place(&mut query_buf, 2);
    }

    // 通过本地 UDP Socket 向远端 DNS 服务器转发查询
    let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
    timeout(timeout_duration, udp_socket.send_to(&query_buf, dns_server))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS send timed out"))??;

    let mut resp_buf = vec![0u8; 4096];
    let (resp_len, _) = timeout(timeout_duration, udp_socket.recv_from(&mut resp_buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS recv timed out"))??;

    // 回传格式：2 字节大端序长度 + DNS 响应报文
    let mut out_buf = Vec::with_capacity(2 + resp_len);
    out_buf.extend_from_slice(&(resp_len as u16).to_be_bytes());
    out_buf.extend_from_slice(&resp_buf[..resp_len]);

    if !cipher.is_empty() {
        cipher.crypt_in_place(&mut out_buf, 0);
    }

    timeout(timeout_duration, client.write_all(&out_buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS response timed out"))??;

    debug!("DNS query forwarded and responded successfully: {} bytes", resp_len);
    Ok(())
}
