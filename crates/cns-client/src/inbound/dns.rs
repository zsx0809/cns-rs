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

        // 6. 将真实的 DNS 响应发回给手机应用 (优先使用 Raw Socket 伪造 8.8.8.8:53，确保移动端 socket 接收成功)
        if let Err(e) = Self::send_raw_dns_reply(peer, &dns_resp_body) {
            tracing::warn!("Raw DNS reply error: {}, falling back to socket.send_to", e);
            let _ = socket.send_to(&dns_resp_body, peer).await;
        } else {
            tracing::info!("Raw DNS reply sent successfully to [{}] as 8.8.8.8:53 ({} bytes)", peer, resp_pkg_len);
        }

        Ok(())
    }

    /// 通过 RAW 套接字精确构造源为 8.8.8.8:53 的真实 DNS 响应报文，彻底消灭 NAT 回包源端口不匹配丢包
    fn send_raw_dns_reply(peer: SocketAddr, payload: &[u8]) -> io::Result<()> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            if let SocketAddr::V4(peer_v4) = peer {
                let dest_ip = peer_v4.ip();
                let dest_port = peer_v4.port();
                let src_ip = std::net::Ipv4Addr::new(8, 8, 8, 8);
                let src_port = 53u16;

                let tot_len = (20 + 8 + payload.len()) as u16;
                let mut packet = Vec::with_capacity(tot_len as usize);

                // 1. IPv4 头部 (20 字节)
                packet.push(0x45); // Version 4, IHL 5
                packet.push(0x00); // DSCP/ECN
                packet.extend_from_slice(&tot_len.to_be_bytes());
                packet.extend_from_slice(&54321u16.to_be_bytes()); // Identification
                packet.extend_from_slice(&0u16.to_be_bytes()); // Flags / Fragment Offset
                packet.push(64); // TTL
                packet.push(17); // Protocol: UDP (17)
                packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum placeholder
                packet.extend_from_slice(&src_ip.octets());
                packet.extend_from_slice(&dest_ip.octets());

                // 计算 IPv4 Checksum
                let ip_csum = calc_checksum(&packet[..20]);
                packet[10..12].copy_from_slice(&ip_csum.to_be_bytes());

                // 2. UDP 头部 (8 字节)
                let udp_len = (8 + payload.len()) as u16;
                packet.extend_from_slice(&src_port.to_be_bytes());
                packet.extend_from_slice(&dest_port.to_be_bytes());
                packet.extend_from_slice(&udp_len.to_be_bytes());
                packet.extend_from_slice(&0u16.to_be_bytes()); // UDP Checksum (0 表示不校验)

                // 3. DNS 载荷
                packet.extend_from_slice(payload);

                // 4. 通过 Raw Socket 发送
                unsafe {
                    let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW);
                    if fd < 0 {
                        return Err(io::Error::last_os_error());
                    }

                    let one: libc::c_int = 1;
                    libc::setsockopt(
                        fd,
                        libc::IPPROTO_IP,
                        libc::IP_HDRINCL,
                        &one as *const _ as *const libc::c_void,
                        std::mem::size_of_val(&one) as libc::socklen_t,
                    );

                    let mut dst_sockaddr: libc::sockaddr_in = std::mem::zeroed();
                    dst_sockaddr.sin_family = libc::AF_INET as libc::sa_family_t;
                    dst_sockaddr.sin_port = dest_port.to_be();
                    std::ptr::copy_nonoverlapping(
                        dest_ip.octets().as_ptr(),
                        &mut dst_sockaddr.sin_addr as *mut _ as *mut u8,
                        4,
                    );

                    let ret = libc::sendto(
                        fd,
                        packet.as_ptr() as *const libc::c_void,
                        packet.len(),
                        0,
                        &dst_sockaddr as *const _ as *const libc::sockaddr,
                        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    );

                    libc::close(fd);

                    if ret < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    return Ok(());
                }
            }
        }
        Err(io::Error::new(io::ErrorKind::Other, "Raw socket unsupported or IPv6"))
    }
}

fn calc_checksum(buf: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = buf.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&rem) = chunks.remainder().first() {
        sum += (rem as u32) << 8;
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
