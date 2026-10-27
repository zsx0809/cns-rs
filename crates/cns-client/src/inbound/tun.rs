use crate::config::ClientConfig;
use cns_core::crypto::CuteBiCipher;
use cns_core::transport::tune_tcp_stream;
use std::fs::{File, OpenOptions};
use std::io;
use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, error, info};

const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const TUNSETIFF: libc::c_int = 0x400454ca;

/// 原生 Linux / Android 极简高性能 Micro-TUN 设备
pub struct TunDevice {
    async_fd: AsyncFd<File>,
    pub name: String,
}

impl TunDevice {
    pub fn create(dev_name: &str) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .or_else(|_| OpenOptions::new().read(true).write(true).open("/dev/tun"))?;

        // 设为非阻塞模式以配合 Tokio 异步
        unsafe {
            let flags = libc::fcntl(file.as_raw_fd(), libc::F_GETFL, 0);
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        // 调用 TUNSETIFF 注册虚拟网卡
        #[repr(C)]
        struct Ifreq {
            ifr_name: [u8; 16],
            ifr_flags: libc::c_short,
            _padding: [u8; 22],
        }

        let mut ifr: Ifreq = unsafe { std::mem::zeroed() };
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        let name_bytes = dev_name.as_bytes();
        let len = name_bytes.len().min(15);
        ifr.ifr_name[..len].copy_from_slice(&name_bytes[..len]);

        unsafe {
            let ret = libc::ioctl(file.as_raw_fd(), TUNSETIFF as libc::c_int, &ifr);
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        let registered_name = String::from_utf8_lossy(&ifr.ifr_name[..len]).to_string();
        info!("Successfully allocated virtual TUN device: [{}]", registered_name);

        let async_fd = AsyncFd::new(file)?;
        Ok(Self {
            async_fd,
            name: registered_name,
        })
    }

    pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.async_fd.readable().await?;
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::read(
                        inner.get_ref().as_raw_fd(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(res) => return res,
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.async_fd.writable().await?;
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::write(
                        inner.get_ref().as_raw_fd(),
                        buf.as_ptr() as *const libc::c_void,
                        buf.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(res) => return res,
                Err(_would_block) => continue,
            }
        }
    }
}

/// 运行纯 Rust 极简 Micro-TUN 引擎
pub struct MicroTunRunner;

impl MicroTunRunner {
    pub async fn start(
        dev_name: &str,
        config: Arc<ClientConfig>,
        cipher: Arc<CuteBiCipher>,
    ) -> io::Result<()> {
        let tun = Arc::new(TunDevice::create(dev_name)?);
        info!("Micro-TUN Engine started on interface: {}", dev_name);

        let tun_reader = Arc::clone(&tun);
        let tun_writer = Arc::clone(&tun);

        tokio::spawn(async move {
            let mut packet = vec![0u8; 2048];
            loop {
                let n = match tun_reader.read(&mut packet).await {
                    Ok(n) => n,
                    Err(e) => {
                        error!("TUN read error: {}", e);
                        continue;
                    }
                };

                let raw = &packet[..n];
                // 仅处理 IPv4 报文 (首字节高 4 位为 4)
                if raw.is_empty() || (raw[0] >> 4) != 4 {
                    continue;
                }

                let ihl = (raw[0] & 0x0f) as usize * 4;
                if raw.len() < ihl {
                    continue;
                }

                let protocol = raw[9];
                // 如果是 UDP 报文 (protocol == 17)
                if protocol == 17 && raw.len() >= ihl + 8 {
                    let udp_header = &raw[ihl..ihl + 8];
                    let src_port = u16::from_be_bytes([udp_header[0], udp_header[1]]);
                    let dst_port = u16::from_be_bytes([udp_header[2], udp_header[3]]);

                    // 拦截 DNS 请求 (目标端口 53)
                    if dst_port == 53 {
                        let src_ip = Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]);
                        let dst_ip = Ipv4Addr::new(raw[16], raw[17], raw[18], raw[19]);
                        let dns_payload = raw[ihl + 8..].to_vec();

                        let writer = Arc::clone(&tun_writer);
                        let cfg = Arc::clone(&config);
                        let cph = Arc::clone(&cipher);

                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_dns_packet(
                                writer,
                                src_ip,
                                src_port,
                                dst_ip,
                                dns_payload,
                                &cfg,
                                &cph,
                            )
                            .await
                            {
                                debug!("TUN DNS resolve error: {}", e);
                            }
                        });
                    }
                }
            }
        });

        Ok(())
    }

    async fn handle_dns_packet(
        writer: Arc<TunDevice>,
        client_ip: Ipv4Addr,
        client_port: u16,
        dns_server_ip: Ipv4Addr,
        query_payload: Vec<u8>,
        config: &ClientConfig,
        cipher: &CuteBiCipher,
    ) -> io::Result<()> {
        // 1. 通过免流加密隧道向远端 CNS 服务器发起请求
        let mut server_stream = TcpStream::connect(&config.cns_server).await?;
        tune_tcp_stream(&server_stream);

        let target_host = format!("{}:53", dns_server_ip);
        let encrypted_target = if !cipher.is_empty() {
            cipher.encrypt_host(&target_host)
        } else {
            target_host
        };

        let handshake_req = config.render_fake_header(&encrypted_target);
        server_stream.write_all(&handshake_req).await?;

        // 2. 检查 200 OK 握手响应
        let mut resp_buf = [0u8; 1024];
        let n = timeout(config.timeout(), server_stream.read(&mut resp_buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS handshake timeout"))??;

        let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
        if !resp_str.starts_with("HTTP/1.1 200") && !resp_str.starts_with("HTTP/1.1 101") {
            return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "CNS handshake failed"));
        }

        // 3. 组装并加密 DNS 查询报文
        let mut req_packet = Vec::with_capacity(2 + query_payload.len());
        req_packet.extend_from_slice(&(query_payload.len() as u16).to_be_bytes());
        req_packet.extend_from_slice(&query_payload);

        if !cipher.is_empty() {
            cipher.crypt_in_place(&mut req_packet, 0);
        }
        server_stream.write_all(&req_packet).await?;

        // 4. 读取回复长度与载荷
        let mut len_buf = [0u8; 2];
        timeout(config.timeout(), server_stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS len timeout"))??;

        if !cipher.is_empty() {
            cipher.crypt_in_place(&mut len_buf, 0);
        }
        let ans_len = u16::from_be_bytes(len_buf) as usize;
        let mut ans_body = vec![0u8; ans_len];
        timeout(config.timeout(), server_stream.read_exact(&mut ans_body))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS body timeout"))??;

        if !cipher.is_empty() {
            cipher.crypt_in_place(&mut ans_body, 2);
        }

        // 5. 构造完美伪装的 IPv4 + UDP 数据包回传给客户端
        let ip_packet = build_udp_ipv4_packet(
            dns_server_ip, // 源 IP 严格设为应用当初查询的目标 DNS IP
            53,            // 源端口严格设为 53
            client_ip,     // 目标 IP
            client_port,   // 目标端口
            &ans_body,
        );

        writer.write(&ip_packet).await?;
        debug!(
            "Micro-TUN successfully answered DNS to {}:{} from {}:53 ({} bytes)",
            client_ip, client_port, dns_server_ip, ans_body.len()
        );

        Ok(())
    }
}

/// 组装带合法校验和的 IPv4 + UDP 原始数据包
fn build_udp_ipv4_packet(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let total_len = (20 + 8 + payload.len()) as u16;

    let mut buf = vec![0u8; total_len as usize];

    // 1. IPv4 头部
    buf[0] = 0x45; // Version 4, IHL 5
    buf[1] = 0x00; // DSCP / ECN
    buf[2..4].copy_from_slice(&total_len.to_be_bytes());
    buf[4..6].copy_from_slice(&0x1234u16.to_be_bytes()); // Identification
    buf[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF flag
    buf[8] = 64;   // TTL
    buf[9] = 17;   // Protocol UDP
    buf[10..12].copy_from_slice(&[0, 0]); // Checksum 占位
    buf[12..16].copy_from_slice(&src_ip.octets());
    buf[16..20].copy_from_slice(&dst_ip.octets());

    let ip_csum = calc_checksum(&buf[..20]);
    buf[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // 2. UDP 头部
    buf[20..22].copy_from_slice(&src_port.to_be_bytes());
    buf[22..24].copy_from_slice(&dst_port.to_be_bytes());
    buf[24..26].copy_from_slice(&udp_len.to_be_bytes());
    buf[26..28].copy_from_slice(&[0, 0]); // UDP Checksum (置 0 代表不校验或可选)

    // 3. UDP Payload
    buf[28..].copy_from_slice(payload);

    buf
}

/// 16 位 RFC 1071 校验和算法
fn calc_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        let word = u16::from_be_bytes([data[i], data[i + 1]]);
        sum += word as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}
