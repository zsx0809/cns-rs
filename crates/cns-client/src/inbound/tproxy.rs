use std::io;
use std::net::SocketAddr;
use tokio::net::TcpStream;

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::unix::io::AsRawFd;

/// 获取经过 Linux / Android iptables TPROXY / REDIRECT 劫持前的真实目标地址
pub fn get_original_dst(stream: &TcpStream, listen_port: u16) -> io::Result<SocketAddr> {
    // 1. TPROXY 模式原生判断：开启 IP_TRANSPARENT 后，stream 的 local_addr 即为真实目标地址！
    if let Ok(local) = stream.local_addr() {
        if local.port() != listen_port {
            return Ok(local);
        }
    }

    // 2. REDIRECT 模式回退判断：调用 SO_ORIGINAL_DST
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let fd = stream.as_raw_fd();

        // 尝试获取 IPv4 原始目标 (SOL_IP, SO_ORIGINAL_DST = 80)
        unsafe {
            let mut addr: libc::sockaddr_in = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            let ret = libc::getsockopt(
                fd,
                libc::SOL_IP,
                80, // SO_ORIGINAL_DST
                &mut addr as *mut _ as *mut libc::c_void,
                &mut len,
            );
            if ret == 0 {
                let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
                let port = u16::from_be(addr.sin_port);
                return Ok(SocketAddr::new(std::net::IpAddr::V4(ip), port));
            }

            // 尝试获取 IPv6 原始目标 (SOL_IPV6, IP6T_SO_ORIGINAL_DST = 80)
            let mut addr6: libc::sockaddr_in6 = std::mem::zeroed();
            let mut len6 = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            let ret6 = libc::getsockopt(
                fd,
                libc::SOL_IPV6,
                80, // IP6T_SO_ORIGINAL_DST
                &mut addr6 as *mut _ as *mut libc::c_void,
                &mut len6,
            );
            if ret6 == 0 {
                let ip = std::net::Ipv6Addr::from(addr6.sin6_addr.s6_addr);
                let port = u16::from_be(addr6.sin6_port);
                return Ok(SocketAddr::new(std::net::IpAddr::V6(ip), port));
            }
        }
    }

    // 未被 TPROXY/REDIRECT 劫持时，回退到对端地址
    stream.peer_addr()
}

/// 切换进程 GID（防回环机制，如 GID 3004）
pub fn apply_process_gid(gid: u32) -> io::Result<()> {
    #[cfg(unix)]
    unsafe {
        let ret = libc::setgid(gid as libc::gid_t);
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
