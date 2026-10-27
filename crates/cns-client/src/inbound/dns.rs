use crate::config::ClientConfig;
use cns_core::crypto::CuteBiCipher;
use cns_core::transport::tune_tcp_stream;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::{debug, warn};

/// 本地 DNS 代理服务器：接收本地 UDP DNS 请求，包装成 tcpDNS 走免流隧道向 CNS 服务端查询
pub struct LocalDnsRelay;

impl LocalDnsRelay {
    pub async fn run(
        listen_addr: SocketAddr,
        config: Arc<ClientConfig>,
        cipher: Arc<CuteBiCipher>,
    ) -> io::Result<()> {
        let socket = Arc::new(UdpSocket::bind(listen_addr).await?);
        debug!("Local DNS Relay listening on UDP: {}", listen_addr);

        let mut buf = vec![0u8; 4096];
        loop {
            let (len, peer) = match socket.recv_from(&mut buf).await {
                Ok(res) => res,
                Err(e) => {
                    warn!("DNS relay recv_from error: {}", e);
                    continue;
                }
            };

            let query = buf[..len].to_vec();
            let sock_clone = Arc::clone(&socket);
            let cfg_clone = Arc::clone(&config);
            let cph_clone = Arc::clone(&cipher);

            tokio::spawn(async move {
                if let Err(e) = Self::forward_dns(sock_clone, peer, query, &cfg_clone, &cph_clone).await {
                    debug!("DNS query from [{}] failed: {}", peer, e);
                }
            });
        }
    }

    async fn forward_dns(
        socket: Arc<UdpSocket>,
        peer: SocketAddr,
        query: Vec<u8>,
        config: &ClientConfig,
        cipher: &CuteBiCipher,
    ) -> io::Result<()> {
        // 1. 连接 CNS 服务端
        let mut server_stream = TcpStream::connect(&config.cns_server).await?;
        tune_tcp_stream(&server_stream);

        // 2. 目标为 8.8.8.8:53，加密并包装 HTTP 握手头
        let target_host = "8.8.8.8:53";
        let encrypted_target = if !cipher.is_empty() {
            cipher.encrypt_host(target_host)
        } else {
            target_host.to_string()
        };

        let handshake_req = config.render_fake_header(&encrypted_target);
        server_stream.write_all(&handshake_req).await?;

        // 3. 读取服务端 HTTP 200 响应
        let mut resp_buf = [0u8; 1024];
        let n = timeout(config.timeout(), server_stream.read(&mut resp_buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS handshake timeout"))??;

        let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
        if !resp_str.starts_with("HTTP/1.1 200") && !resp_str.starts_with("HTTP/1.1 101") {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "DNS CNS handshake failed",
            ));
        }

        // 4. 组装并加密请求报文：[2 字节大端序长度] + [DNS 报文]
        let query_len = query.len() as u16;
        let mut packet = Vec::with_capacity(2 + query.len());
        packet.extend_from_slice(&query_len.to_be_bytes());
        packet.extend_from_slice(&query);

        if !cipher.is_empty() {
            cipher.crypt_in_place(&mut packet, 0);
        }

        server_stream.write_all(&packet).await?;

        // 5. 读取回复报文
        let mut len_buf = [0u8; 2];
        timeout(config.timeout(), server_stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS read resp len timeout"))??;

        if !cipher.is_empty() {
            cipher.crypt_in_place(&mut len_buf, 0);
        }

        let resp_pkg_len = u16::from_be_bytes(len_buf) as usize;
        if resp_pkg_len > 4096 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "DNS resp too large"));
        }

        let mut dns_resp_body = vec![0u8; resp_pkg_len];
        timeout(config.timeout(), server_stream.read_exact(&mut dns_resp_body))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS read resp body timeout"))??;

        if !cipher.is_empty() {
            cipher.crypt_in_place(&mut dns_resp_body, 2);
        }

        // 6. 将真实的 DNS 响应发回给手机应用
        socket.send_to(&dns_resp_body, peer).await?;
        debug!("DNS query resolved via CNS for [{}] ({} bytes)", peer, resp_pkg_len);

        Ok(())
    }
}
