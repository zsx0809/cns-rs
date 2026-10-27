use crate::config::ClientConfig;
use cns_core::crypto::CuteBiCipher;
use cns_core::transport::tune_tcp_stream;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, Interest};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::{debug, warn};

/// 本地 DNS 代理服务器：接收本地 UDP DNS 请求，包装成 tcpDNS 走免流隧道向 CNS 服务端查询
/// 并利用 IP_RECVORIGDSTADDR 精确捕获原始目的 IP，回包时通过 Raw Socket 动态伪造源 IP
/// 同时在本地毫秒级过滤 AAAA (IPv6) 请求，解决双栈 CDN (如 GitHub Assets) 白底黑字与 IPv6 直连漏免问题
pub struct LocalDnsRelay;

impl LocalDnsRelay {
    pub async fn run(
        listen_addr: SocketAddr,
        config: Arc<ClientConfig>,
        cipher: Arc<CuteBiCipher>,
    ) -> io::Result<()> {
        let domain = match listen_addr {
            SocketAddr::V4(_) => socket2::Domain::IPV4,
            SocketAddr::V6(_) => socket2::Domain::IPV6,
        };

        let std_sock = socket2::Socket::new(
            domain,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        std_sock.set_nonblocking(true)?;
        std_sock.set_reuse_address(true)?;

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let one: libc::c_int = 1;
            unsafe {
                libc::setsockopt(
                    std_sock.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_RECVORIGDSTADDR,
                    &one as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&one) as libc::socklen_t,
                );
            }
        }

        std_sock.bind(&listen_addr.into())?;
        let socket = Arc::new(UdpSocket::from_std(std_sock.into())?);
        debug!("Local DNS Relay listening on UDP: {} (with IP_RECVORIGDSTADDR enabled)", listen_addr);

        let mut buf = vec![0u8; 4096];
        let mut ctrl_buf = [0u8; 512];

        loop {
            // 使用 try_io 驱动底层 libc recvmsg，由 Tokio 自动维护 epoll 就绪标志，绝无死循环空转
            let raw_fd = socket.as_raw_fd();
            let recv_res = socket.try_io(Interest::READABLE, || {
                recv_packet_with_orig_dst(raw_fd, &mut buf, &mut ctrl_buf)
            });

            let (len, peer, orig_dst) = match recv_res {
                Ok(res) => res,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if let Err(e) = socket.readable().await {
                        warn!("DNS relay readable wait error: {}", e);
                    }
                    continue;
                }
                Err(e) => {
                    warn!("DNS recv error: {}", e);
                    continue;
                }
            };

            let query = buf[..len].to_vec();

            // 智能拦截 AAAA (IPv6) 查询，直接本地秒回 NODATA 响应
            // 促使浏览器 / APP 毫秒级回退至纯 IPv4 走免流隧道，彻底消灭双栈 CDN 白底黑字
            if let Some(nodata_resp) = build_aaaa_nodata_response(&query) {
                let sock_clone = Arc::clone(&socket);
                tokio::spawn(async move {
                    if let Err(e) = Self::send_raw_dns_reply(peer, orig_dst, &nodata_resp) {
                        let _ = sock_clone.send_to(&nodata_resp, peer).await;
                        debug!("AAAA NODATA raw reply fallback to udp: {}", e);
                    }
                });
                continue;
            }

            let sock_clone = Arc::clone(&socket);
            let cfg_clone = Arc::clone(&config);
            let cph_clone = Arc::clone(&cipher);

            tokio::spawn(async move {
                if let Err(e) = Self::forward_dns(sock_clone, peer, orig_dst, query, &cfg_clone, &cph_clone).await {
                    debug!("DNS query from [{}] -> [{}] failed: {}", peer, orig_dst, e);
                }
            });
        }
    }

    async fn forward_dns(
        socket: Arc<UdpSocket>,
        peer: SocketAddr,
        orig_dst: SocketAddr,
        query: Vec<u8>,
        config: &ClientConfig,
        cipher: &CuteBiCipher,
    ) -> io::Result<()> {
        // 1. 连接 CNS 服务端
        let mut server_stream = TcpStream::connect(&config.cns_server).await?;
        tune_tcp_stream(&server_stream);

        // 2. 向上游公共 DNS 查询 (8.8.8.8:53)，确保海外 VPS 能稳定递归解析
        let upstream_dns = "8.8.8.8:53";
        let encrypted_target = if !cipher.is_empty() {
            cipher.encrypt_host(upstream_dns)
        } else {
            upstream_dns.to_string()
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

        // 6. 将真实的 DNS 响应发回给手机应用 (使用 Raw Socket 伪装为客户端原本请求的 orig_dst)
        if let Err(e) = Self::send_raw_dns_reply(peer, orig_dst, &dns_resp_body) {
            tracing::warn!("Raw DNS reply failed: {}, fallback to socket.send_to", e);
            let _ = socket.send_to(&dns_resp_body, peer).await;
        } else {
            tracing::debug!(
                "Raw DNS reply sent successfully to [{}] as [{}] ({} bytes)",
                peer,
                orig_dst,
                resp_pkg_len
            );
        }

        Ok(())
    }

    /// 通过 RAW 套接字精确构造源为客户端原始请求目标 (orig_dst) 的真实 DNS 响应报文
    fn send_raw_dns_reply(peer: SocketAddr, orig_dst: SocketAddr, payload: &[u8]) -> io::Result<()> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            if let (SocketAddr::V4(peer_v4), SocketAddr::V4(orig_v4)) = (peer, orig_dst) {
                let dest_ip = peer_v4.ip();
                let dest_port = peer_v4.port();
                let src_ip = orig_v4.ip();
                let src_port = orig_v4.port();

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
                let mut udp_hdr = Vec::with_capacity(8 + payload.len());
                udp_hdr.extend_from_slice(&src_port.to_be_bytes());
                udp_hdr.extend_from_slice(&dest_port.to_be_bytes());
                udp_hdr.extend_from_slice(&udp_len.to_be_bytes());
                udp_hdr.extend_from_slice(&0u16.to_be_bytes()); // Checksum placeholder
                udp_hdr.extend_from_slice(payload);

                // 计算完整 UDP Checksum (包含伪首部)
                let udp_csum = calc_udp_checksum(*src_ip, *dest_ip, &udp_hdr);
                udp_hdr[6..8].copy_from_slice(&udp_csum.to_be_bytes());

                packet.extend_from_slice(&udp_hdr);

                // 3. 通过 Raw Socket 发送
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

/// 检查是否为 AAAA (IPv6) 查询，若是则直接返回标准权威 NODATA 响应 (RCODE=0, ANCOUNT=0)
fn build_aaaa_nodata_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    // 检查 QDCOUNT == 1
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    if qdcount != 1 {
        return None;
    }
    // 跳过 Header (12 字节)，遍历 QNAME
    let mut offset = 12;
    while offset < query.len() {
        let len = query[offset] as usize;
        if len == 0 {
            offset += 1;
            break;
        }
        // 如果是压缩指针
        if (len & 0xc0) == 0xc0 {
            offset += 2;
            break;
        }
        offset += 1 + len;
    }

    // 此时 offset 应该指向 QTYPE (2 字节)
    if offset + 4 <= query.len() {
        let qtype = u16::from_be_bytes([query[offset], query[offset + 1]]);
        if qtype == 28 { // 28 即 AAAA (IPv6)
            let question_end = offset + 4;
            let mut resp = Vec::with_capacity(question_end);
            // 1. Transaction ID (原样复制)
            resp.extend_from_slice(&query[0..2]);
            // 2. Flags: 0x8180 (标准响应, No Error, Recursion Available)
            resp.extend_from_slice(&[0x81, 0x80]);
            // 3. QDCOUNT: 1
            resp.extend_from_slice(&[0x00, 0x01]);
            // 4. ANCOUNT: 0 (权威空结果，表示该域名无 IPv6 记录)
            resp.extend_from_slice(&[0x00, 0x00]);
            // 5. NSCOUNT: 0
            resp.extend_from_slice(&[0x00, 0x00]);
            // 6. ARCOUNT: 0
            resp.extend_from_slice(&[0x00, 0x00]);
            // 7. Question Section 原样保留
            resp.extend_from_slice(&query[12..question_end]);
            return Some(resp);
        }
    }
    None
}

/// 使用 libc::recvmsg 接收数据包并解析控制消息以提取原目标地址
fn recv_packet_with_orig_dst(
    raw_fd: std::os::unix::io::RawFd,
    buf: &mut [u8],
    ctrl_buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };

        let mut src_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };

        let mut msghdr = libc::msghdr {
            msg_name: &mut src_addr as *mut _ as *mut libc::c_void,
            msg_namelen: std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: ctrl_buf.as_mut_ptr() as *mut libc::c_void,
            msg_controllen: ctrl_buf.len() as libc::size_t,
            msg_flags: 0,
        };

        let n = unsafe { libc::recvmsg(raw_fd, &mut msghdr, libc::MSG_DONTWAIT) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        let peer_ip = Ipv4Addr::from(src_addr.sin_addr.s_addr.to_ne_bytes());
        let peer_port = u16::from_be(src_addr.sin_port);
        let peer = SocketAddr::V4(SocketAddrV4::new(peer_ip, peer_port));

        let orig_dst = unsafe { parse_orig_dst(&msghdr) }.unwrap_or_else(|| {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53))
        });

        Ok((n as usize, peer, orig_dst))
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        Err(io::Error::new(io::ErrorKind::Other, "Unsupported OS"))
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn parse_orig_dst(msghdr: &libc::msghdr) -> Option<SocketAddr> {
    let mut cmsg = libc::CMSG_FIRSTHDR(msghdr);
    while !cmsg.is_null() {
        let cm = &*cmsg;
        if cm.cmsg_level == libc::IPPROTO_IP && cm.cmsg_type == libc::IP_ORIGDSTADDR {
            let sin = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in;
            let ip_bytes = (*sin).sin_addr.s_addr.to_ne_bytes();
            let port = u16::from_be((*sin).sin_port);
            let ip = Ipv4Addr::from(ip_bytes);
            return Some(SocketAddr::V4(SocketAddrV4::new(ip, port)));
        }
        cmsg = libc::CMSG_NXTHDR(msghdr, cmsg);
    }
    None
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

fn calc_udp_checksum(src_ip: Ipv4Addr, dest_ip: Ipv4Addr, udp_hdr_and_payload: &[u8]) -> u16 {
    let mut sum = 0u32;
    let s = src_ip.octets();
    sum += u16::from_be_bytes([s[0], s[1]]) as u32;
    sum += u16::from_be_bytes([s[2], s[3]]) as u32;

    let d = dest_ip.octets();
    sum += u16::from_be_bytes([d[0], d[1]]) as u32;
    sum += u16::from_be_bytes([d[2], d[3]]) as u32;

    sum += 17u32; // IPPROTO_UDP
    let udp_len = udp_hdr_and_payload.len() as u16;
    sum += udp_len as u32;

    let mut chunks = udp_hdr_and_payload.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&rem) = chunks.remainder().first() {
        sum += (rem as u32) << 8;
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let res = !(sum as u16);
    if res == 0 {
        0xffff
    } else {
        res
    }
}
