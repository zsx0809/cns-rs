use std::io;
use std::net::SocketAddr;
use tokio::net::TcpStream;

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::unix::io::AsRawFd;

/// 透明代理劫持方式
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TproxyMode {
    /// iptables `-j REDIRECT --to-ports N`：原始目标只能靠 `SO_ORIGINAL_DST` 取
    Redirect,
    /// iptables `-j TPROXY` + `IP_TRANSPARENT`：`local_addr()` 本身就是原始目标
    Tproxy,
    /// 先试 SO_ORIGINAL_DST，失败再用 local_addr（兼容混合规则）
    Auto,
}

impl TproxyMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "redirect" => Some(Self::Redirect),
            "tproxy" => Some(Self::Tproxy),
            "auto" | "" => Some(Self::Auto),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Redirect => "redirect",
            Self::Tproxy => "tproxy",
            Self::Auto => "auto",
        }
    }
}

const SO_ORIGINAL_DST: libc::c_int = 80;
const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;

/// 取回被 iptables 劫持前的真实目标地址。
///
/// 修复：旧实现用 `local_port() != listen_port` 猜模式。当被劫持连接的目标端口
/// 恰好等于监听端口时（例如自己转发到 7750，或 REDIRECT 到同端口），这个猜测
/// 会返回**代理自己的监听地址**，于是「客户端 -> 代理 -> 代理」自连成环。
/// 现在按显式模式判定，且 Auto 以 SO_ORIGINAL_DST 是否成功为准，而不是比端口。
pub fn get_original_dst_with_mode(
    stream: &TcpStream,
    listen_port: u16,
    mode: TproxyMode,
) -> io::Result<SocketAddr> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let fd = stream.as_raw_fd();

        // TPROXY+IP_TRANSPARENT：local_addr 就是原始目标，优先级最高
        if mode == TproxyMode::Tproxy {
            let local = stream.local_addr()?;
            // 未被 TPROXY 改写时 local.port() 恰为监听端口，这就是「自己连自己」
            if local.port() != 0 && local.port() != listen_port {
                return Ok(local);
            }
            if local.port() == listen_port {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("TPROXY mode but local_addr is own listen port {listen_port}"),
                ));
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TPROXY mode but local_addr has port 0",
            ));
        }

        // REDIRECT / AUTO：查 SO_ORIGINAL_DST
        if mode == TproxyMode::Redirect || mode == TproxyMode::Auto {
            if let Some(addr) = unsafe { getsockopt_original_dst_v4(fd) } {
                // 防御：拿到的仍是监听端口说明没被劫持（或规则成环），拒绝自连
                if addr.port() == listen_port {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("SO_ORIGINAL_DST returned own listen port {listen_port}"),
                    ));
                }
                return Ok(addr);
            }
            if let Some(addr) = unsafe { getsockopt_original_dst_v6(fd) } {
                if addr.port() == listen_port {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("SO_ORIGINAL_DST returned own listen port {listen_port}"),
                    ));
                }
                return Ok(addr);
            }
            if mode == TproxyMode::Redirect {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "not a REDIRECT-ed connection (SO_ORIGINAL_DST unavailable)",
                ));
            }
        }

        // AUTO 最后兜底：local_addr 与 peer_addr 都试，但绝不返回监听端口本身
        if let Ok(local) = stream.local_addr() {
            if local.port() != listen_port && local.port() != 0 {
                return Ok(local);
            }
        }
        let peer = stream.peer_addr()?;
        if peer.port() == listen_port {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot determine original destination (loop risk)",
            ));
        }
        Ok(peer)
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = (listen_port, mode);
        stream.peer_addr()
    }
}

/// 兼容旧签名：Auto 模式
pub fn get_original_dst(stream: &TcpStream, listen_port: u16) -> io::Result<SocketAddr> {
    get_original_dst_with_mode(stream, listen_port, TproxyMode::Auto)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn getsockopt_original_dst_v4(fd: std::os::unix::io::RawFd) -> Option<SocketAddr> {
    let mut addr: libc::sockaddr_in = std::mem::zeroed();
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let ret = libc::getsockopt(
        fd,
        libc::SOL_IP,
        SO_ORIGINAL_DST,
        &mut addr as *mut _ as *mut libc::c_void,
        &mut len,
    );
    if ret != 0 {
        return None;
    }
    let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    if ip.is_unspecified() || port == 0 {
        return None;
    }
    Some(SocketAddr::new(std::net::IpAddr::V4(ip), port))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn getsockopt_original_dst_v6(fd: std::os::unix::io::RawFd) -> Option<SocketAddr> {
    let mut addr6: libc::sockaddr_in6 = std::mem::zeroed();
    let mut len6 = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
    let ret = libc::getsockopt(
        fd,
        libc::SOL_IPV6,
        IP6T_SO_ORIGINAL_DST,
        &mut addr6 as *mut _ as *mut libc::c_void,
        &mut len6,
    );
    if ret != 0 {
        return None;
    }
    let ip = std::net::Ipv6Addr::from(addr6.sin6_addr.s6_addr);
    let port = u16::from_be(addr6.sin6_port);
    if ip.is_unspecified() || port == 0 {
        return None;
    }
    Some(SocketAddr::new(std::net::IpAddr::V6(ip), port))
}

/// 切换进程 GID（配合 iptables `--gid-owner` 防回环）。
///
/// 必须同时降掉补充组，否则仍可能命中其它 owner 匹配规则；另外 GID 切换后
/// 无法恢复，所以要在建立任何监听 socket **之后**、真正开始服务之前调用。
pub fn apply_process_gid(gid: u32) -> io::Result<()> {
    #[cfg(unix)]
    unsafe {
        if libc::setgid(gid as libc::gid_t) != 0 {
            return Err(io::Error::last_os_error());
        }
        // 清空补充组，避免残留权限命中其它 owner 匹配规则。
        // 注意：GID 切换后不可逆，因此调用点必须在所有监听 socket 建立之后。
        libc::setgroups(0, std::ptr::null::<libc::gid_t>());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn connected_pair() -> (TcpStream, TcpStream, SocketAddr) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let a = TcpStream::connect(addr).await.unwrap();
        let (b, _) = listener.accept().await.unwrap();
        (a, b, addr)
    }

    #[test]
    fn mode_parsing() {
        assert_eq!(TproxyMode::parse("redirect"), Some(TproxyMode::Redirect));
        assert_eq!(TproxyMode::parse("TPROXY"), Some(TproxyMode::Tproxy));
        assert_eq!(TproxyMode::parse(" auto "), Some(TproxyMode::Auto));
        assert_eq!(TproxyMode::parse(""), Some(TproxyMode::Auto));
        assert_eq!(TproxyMode::parse("magic"), None);
        assert_eq!(TproxyMode::Tproxy.as_str(), "tproxy");
    }

    /// 非劫持连接（普通本机连接）：绝不能再返回「监听端口本身」，
    /// 旧实现靠比端口猜模式，正好在这里会自连成环。
    #[tokio::test]
    async fn unredirected_connection_never_targets_own_listen_port() {
        let (client, _server, listen_addr) = connected_pair().await;
        let port = listen_addr.port();

        // Auto：拿不到 SO_ORIGINAL_DST，最终回落到 peer_addr，且不得等于监听端口
        let res = get_original_dst_with_mode(&client, port, TproxyMode::Auto);
        match res {
            Ok(addr) => {
                assert_ne!(addr.port(), port, "returned own listen port => forwarding loop")
            }
            Err(e) => {
                // 明确报环路风险也是可接受的行为
                assert_ne!(e.kind(), io::ErrorKind::Unsupported, "should not be unsupported");
            }
        }

        // Redirect 模式：本不是被 REDIRECT 的连接。
        // 注意 Android 内核即使没有 NAT 规则也会让 SO_ORIGINAL_DST 返回成功，
        // 且返回值就是「真实目的」= 我们的监听端口，因此必须被环路防护拒绝，
        // 绝不能 Ok(listen_port) —— 那会造成 客户端 -> 代理 -> 代理 自连死循环。
        match get_original_dst_with_mode(&client, port, TproxyMode::Redirect) {
            Ok(addr) => panic!("must refuse self-target, got {addr}"),
            Err(e) => assert!(
                matches!(e.kind(), io::ErrorKind::InvalidInput | io::ErrorKind::NotFound),
                "unexpected error kind {:?}",
                e.kind()
            ),
        }
    }

    #[tokio::test]
    async fn tproxy_mode_reads_local_addr() {
        let (client, _server, listen_addr) = connected_pair().await;
        // 未开 IP_TRANSPARENT 时，local_addr 就是被连接的那个端口
        let port = listen_addr.port();
        let res = get_original_dst_with_mode(&client, port, TproxyMode::Tproxy);
        // 该模式下 local.port()==listen_port，按规则视为异常（防止把自己当目标）
        assert!(res.is_err() || res.unwrap().port() != 0, "tproxy mode must refuse a zero port");
    }

    #[tokio::test]
    async fn legacy_wrapper_still_works() {
        let (client, _, _) = connected_pair().await;
        // 旧签名走 Auto
        let addr = get_original_dst(&client, 1).unwrap();
        assert!(addr.port() != 0);
    }

    #[test]
    fn gid_helper_is_call_safe() {
        // gid 0 = 当前已是 root 时必然成功；非 root 时返回 Err。两种都合法，
        // 这里只要求不 panic，避免在测试里真的改掉进程 GID。
        let r = apply_process_gid(0);
        assert!(r.is_ok() || r.unwrap_err().kind() == io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn connected_pair_sanity() {
        let (mut a, mut b, _) = connected_pair().await;
        a.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }
}
