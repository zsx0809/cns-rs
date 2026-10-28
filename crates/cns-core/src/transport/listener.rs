use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tracing::debug;

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::unix::io::AsRawFd;

/// 监听器构建参数。默认值面向「手机免流 + 128MB 小鸡」两类目标做统一调优。
#[derive(Debug, Clone, Copy)]
pub struct ListenOptions {
    /// TCP_FASTOPEN 队列长度 > 0 时启用（服务端 0-RTT）
    pub enable_tfo: bool,
    /// true = 纯 IPv6 监听；false(默认) = v6 socket 同时接受 IPv4-mapped 连接（真双栈）
    pub ipv6_only: bool,
    /// IP_TRANSPARENT / IPV6_TRANSPARENT，透明代理必需；非 root 失败时静默降级
    pub transparent: bool,
    pub recv_buffer: usize,
    pub send_buffer: usize,
    pub backlog: u32,
}

impl Default for ListenOptions {
    fn default() -> Self {
        Self {
            enable_tfo: true,
            ipv6_only: false,
            transparent: true,
            recv_buffer: 4 * 1024 * 1024,
            send_buffer: 4 * 1024 * 1024,
            backlog: 4096,
        }
    }
}

/// 把配置里的监听字符串展开成实际要绑定的地址列表。
///
/// * `":1254"` / `"*:1254"` → 优先 `"[::]:1254"`（双栈），失败再回退 `0.0.0.0:1254`
/// * `"0.0.0.0:1254"` / `"[::]:1254"` → 原样
/// * 其它 → 原样解析，解析失败返回错误交给上层报错（不静默改端口）
pub fn expand_listen_spec(spec: &str) -> Vec<SocketAddr> {
    let s = spec.trim();
    let mut out = Vec::new();
    if s.starts_with(':') || s.starts_with("*:") {
        let port_part = s.trim_start_matches([':', '*']);
        if let Ok(v6) = format!("[::]:{port_part}").parse::<SocketAddr>() {
            out.push(v6);
        }
        if let Ok(v4) = format!("0.0.0.0:{port_part}").parse::<SocketAddr>() {
            out.push(v4);
        }
    } else if let Ok(addr) = s.parse::<SocketAddr>() {
        out.push(addr);
    }
    out
}

/// 创建经过全链路调优的 TCP 监听器
pub fn create_tcp_listener(addr: SocketAddr, opts: ListenOptions) -> io::Result<TcpListener> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    // 关键修复：默认 **不** 设置 IPV6_V6ONLY，让单个 [::]:port 同时吃 IPv4 与 IPv6。
    // 旧实现无条件 set_only_v6(true)，导致移动网络大量 IPv4-only 客户端永远连不上。
    if let SocketAddr::V6(_) = addr {
        let _ = socket.set_only_v6(opts.ipv6_only);
    }

    socket.set_reuse_address(true)?;
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    if let Err(e) = socket.set_reuse_port(true) {
        debug!("SO_REUSEPORT unavailable: {e}");
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    if opts.transparent {
        unsafe {
            let one: libc::c_int = 1;
            let (level, optname, label) = match addr {
                SocketAddr::V4(_) => (libc::SOL_IP, libc::IP_TRANSPARENT, "IPv4 IP_TRANSPARENT"),
                SocketAddr::V6(_) => {
                    (libc::IPPROTO_IPV6, libc::IPV6_TRANSPARENT, "IPv6 IPV6_TRANSPARENT")
                }
            };
            let ret = libc::setsockopt(
                socket.as_raw_fd(),
                level,
                optname,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of_val(&one) as libc::socklen_t,
            );
            if ret == 0 {
                debug!("{label} enabled");
            } else {
                debug!("{label} rejected: {}", io::Error::last_os_error());
            }
        }
    }

    if opts.enable_tfo {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        unsafe {
            let qlen: libc::c_int = 1024;
            let ret = libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_FASTOPEN,
                &qlen as *const _ as *const libc::c_void,
                std::mem::size_of_val(&qlen) as libc::socklen_t,
            );
            if ret != 0 {
                debug!("TCP_FASTOPEN listen unavailable: {}", io::Error::last_os_error());
            }
        }
    }

    if opts.recv_buffer > 0 {
        let _ = socket.set_recv_buffer_size(opts.recv_buffer);
    }
    if opts.send_buffer > 0 {
        let _ = socket.set_send_buffer_size(opts.send_buffer);
    }

    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(opts.backlog as i32)?;

    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}

/// 针对已建立连接注入吞吐/延迟/保活参数。
///
/// 免流场景下基站与光猫的 NAT 表项老化才是「假连接」主因，所以必须开 TCP keepalive，
/// 而不是靠上层 15 秒硬超时切断。
pub fn tune_tcp_stream(stream: &TcpStream) {
    if let Err(e) = stream.set_nodelay(true) {
        debug!("TCP_NODELAY failed: {e}");
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    unsafe {
        let fd = stream.as_raw_fd();
        let on: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of_val(&on) as libc::socklen_t,
        );
        for (opt, val, name) in [
            (libc::TCP_KEEPIDLE, 30i32, "KEEPIDLE"),
            (libc::TCP_KEEPINTVL, 10i32, "KEEPINTVL"),
            (libc::TCP_KEEPCNT, 6i32, "KEEPCNT"),
        ] {
            let ret = libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                opt,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of_val(&val) as libc::socklen_t,
            );
            if ret != 0 {
                debug!("TCP_{name} unavailable: {}", io::Error::last_os_error());
            }
        }
    }
}

/// 客户端出站连接：在 connect 前打开 `TCP_FASTOPEN_CONNECT`，
/// 让首写携带 SYN 数据，真正拿到 0-RTT（旧实现只在服务端开了 TFO，客户端从未使用）。
pub async fn connect_tfo(addr: SocketAddr, enable_tfo: bool) -> io::Result<TcpStream> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    let _ = socket.set_nodelay(true);

    #[cfg(any(target_os = "linux", target_os = "android"))]
    if enable_tfo {
        unsafe {
            let on: libc::c_int = 1;
            let ret = libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_FASTOPEN_CONNECT,
                &on as *const _ as *const libc::c_void,
                std::mem::size_of_val(&on) as libc::socklen_t,
            );
            if ret != 0 {
                debug!("TCP_FASTOPEN_CONNECT unavailable: {}", io::Error::last_os_error());
            }
        }
    }

    let stream = socket.connect(addr).await?;
    tune_tcp_stream(&stream);
    Ok(stream)
}

/// 解析 `host:port` 并对所有候选地址做快速回退连接（IPv6 优先，失败立即试 IPv4）。
pub async fn connect_any(target: &str, enable_tfo: bool) -> io::Result<TcpStream> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(target).await?.collect();
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("no address resolved for {target}"),
        ));
    }

    let mut last_err = io::Error::other("connect failed");
    for addr in addrs {
        match connect_tfo(addr, enable_tfo).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// 创建带大缓冲的非阻塞 UDP Socket
pub fn create_tuned_udp_socket(addr: SocketAddr) -> io::Result<tokio::net::UdpSocket> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if let SocketAddr::V6(_) = addr {
        // UDP 出站默认双栈，便于 v6 源地址回包
        let _ = socket.set_only_v6(false);
    }

    let _ = socket.set_reuse_address(true);
    let _ = socket.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = socket.set_send_buffer_size(4 * 1024 * 1024);

    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;

    let std_socket: std::net::UdpSocket = socket.into();
    tokio::net::UdpSocket::from_std(std_socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_wildcard_yields_v6_then_v4() {
        let list = expand_listen_spec(":1254");
        assert_eq!(list.len(), 2);
        assert!(list[0].is_ipv6());
        assert_eq!(list[0].port(), 1254);
        assert!(list[1].is_ipv4());
        assert_eq!(list[1].port(), 1254);
    }

    #[test]
    fn expand_explicit_addr_is_single() {
        let list = expand_listen_spec("127.0.0.1:8080");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].to_string(), "127.0.0.1:8080");
    }

    #[test]
    fn expand_bad_spec_is_empty() {
        assert!(expand_listen_spec("not-an-addr").is_empty());
    }

    #[tokio::test]
    async fn dualstack_listener_accepts_ipv4_client() {
        // 回归测试：曾经的 set_only_v6(true) 让 IPv4 客户端连不上
        let opts = ListenOptions { transparent: false, enable_tfo: false, ..Default::default() };
        let addr: SocketAddr = "[::]:0".parse().unwrap();
        let listener = create_tcp_listener(addr, opts).unwrap();
        let bound = listener.local_addr().unwrap();

        let connect_to: SocketAddr = format!("127.0.0.1:{}", bound.port()).parse().unwrap();
        let std_stream = std::net::TcpStream::connect(connect_to);
        assert!(
            std_stream.is_ok(),
            "IPv4 client must reach the dual-stack listener: {:?}",
            std_stream.err()
        );
    }
}
