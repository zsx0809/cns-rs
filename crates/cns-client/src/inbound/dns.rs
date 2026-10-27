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

pub struct DnsRelay {
    udp_socket: Arc<UdpSocket>,
    config: Arc<ClientConfig>,
    cipher: Arc<CuteBiCipher>,
}

impl DnsRelay {
    pub async fn bind(
        listen_addr: &str,
        config: Arc<ClientConfig>,
        cipher: Arc<CuteBiCipher>,
    ) -> io::Result<Self> {
        let socket = UdpSocket::bind(listen_addr).await?;
        debug!("DNS Inbound relay listening on UDP: {}", listen_addr);
        Ok(Self {
            udp_socket: Arc::new(socket),
            config,
            cipher,
        })
    }

    /// 启动 DNS 循环接收与免流中继
    pub async fn run(self) {
        let mut buf = vec![0u8; 4096];
        loop {
            match self.udp_socket.recv_from(&mut buf).await {
                Ok((len, peer)) => {
                    let query_data = buf[..len].to_vec();
                    let socket = Arc::clone(&self.udp_socket);
                    let cfg = Arc::clone(&self.config);
                    let cph = Arc::clone(&self.cipher);

                    tokio::spawn(async move {
                        if let Err(e) = Self::forward_query(socket, peer, query_data, cfg, cph).await {
                            debug!("DNS query forwarding failed from {}: {}", peer, e);
                        }
                    });
                }
                Err(e) => {
                    warn!("DNS relay recv_from error: {}", e);
                }
            }
        }
    }

    /// 单个 DNS 查询通过免流 TCP 隧道打到 CNS 服务端
    async fn forward_query(
        socket: Arc<UdpSocket>,
        peer: SocketAddr,
        query: Vec<u8>,
        config: Arc<ClientConfig>,
        cipher: Arc<CuteBiCipher>,
    ) -> io::Result<()> {
        let timeout_dur = config.timeout();

        // 1. 连接 CNS 服务端
        let mut server_stream = timeout(timeout_dur, TcpStream::connect(&config.cns_server))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS connect to CNS timed out"))??;
        tune_tcp_stream(&server_stream);

        // 2. 目标为标准 DNS 端口 (8.8.8.8:53)
        let dns_target = "8.8.8.8:53";
        let encrypted_target = if !cipher.is_empty() {
            cipher.encrypt_host(dns_target)
        } else {
            dns_target.to_string()
        };

        // 3. 发送带免流白名单伪装头的 HTTP 握手
        let handshake_req = config.render_fake_header(&encrypted_target);
        server_stream.write_all(&handshake_req).await?;

        // 4. 读取握手响应
        let mut resp_header_buf = [0u8; 1024];
        let n = timeout(timeout_dur, server_stream.read(&mut resp_header_buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS handshake response timed out"))??;

        let resp_str = String::from_utf8_lossy(&resp_header_buf[..n]);
        if !resp_str.starts_with("HTTP/1.1 200") && !resp_str.starts_with("HTTP/1.1 101") {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "DNS CNS handshake failed",
            ));
        }

        // 5. 按照 CNS dns_tcpOverUdp 协议发送数据：[2 字节大端序长度] + [DNS 原始报文]
        let query_len = query.len();
        let mut out_buf = Vec::with_capacity(2 + query_len);
        out_buf.extend_from_slice(&(query_len as u16).to_be_bytes());
        out_buf.extend_from_slice(&query);

        if !cipher.is_empty() {
            cipher.crypt_in_place(&mut out_buf, 0);
        }

        timeout(timeout_dur, server_stream.write_all(&out_buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS write query timed out"))??;

        // 6. 接收 CNS 服务端代理查回的 DNS 响应：[2 字节大端序长度] + [DNS 回包]
        let mut len_buf = [0u8; 2];
        timeout(timeout_dur, server_stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS read resp len timed out"))??;

        if !cipher.is_empty() {
            cipher.crypt_in_place(&mut len_buf, 0);
        }

        let resp_len = u16::from_be_bytes(len_buf) as usize;
        if resp_len > 4096 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "DNS resp too large"));
        }

        let mut dns_resp_buf = vec![0u8; resp_len];
        timeout(timeout_dur, server_stream.read_exact(&mut dns_resp_buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS read resp payload timed out"))??;

        if !cipher.is_empty() {
            cipher.crypt_in_place(&mut dns_resp_buf, 2);
        }

        // 7. 将解密后的真实 DNS 回包通过本地 UDP 原路发回给客户端
        socket.send_to(&dns_resp_buf, peer).await?;
        debug!("DNS query resolved and replied to {}: {} bytes", peer, resp_len);

        Ok(())
    }
}
