use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::debug;

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::unix::io::AsRawFd;

/// 创建经过全链路高性能调优的 TCP 监听器
pub fn create_tcp_listener(addr: SocketAddr, enable_tfo: bool) -> io::Result<TcpListener> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    // 纯正 IPv6 监听，不与 IPv4 端口争抢或映射混淆
    if let SocketAddr::V6(_) = addr {
        let _ = socket.set_only_v6(true);
    }

    // 端口复用
    socket.set_reuse_address(true)?;
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    {
        if let Err(e) = socket.set_reuse_port(true) {
            debug!("Failed to set SO_REUSEPORT: {}", e);
        }
    }

    // TCP Fast Open (0-RTT 握手)
    if enable_tfo {
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
                debug!("Failed to enable TCP_FASTOPEN via setsockopt");
            }
        }
    }

    // 缓冲区优化（调至 4MB，保证跨国高带宽不丢包）
    let _ = socket.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = socket.set_send_buffer_size(4 * 1024 * 1024);

    // 绑定并监听
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(4096)?;

    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}

/// 针对已建立的 TCP 连接注入最佳吞吐与延迟参数
pub fn tune_tcp_stream(stream: &TcpStream) {
    if let Err(e) = stream.set_nodelay(true) {
        debug!("Failed to set TCP_NODELAY: {}", e);
    }
}

/// 创建带 4MB 缓冲的非阻塞 UDP Socket
pub fn create_tuned_udp_socket(addr: SocketAddr) -> io::Result<UdpSocket> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if let SocketAddr::V6(_) = addr {
        let _ = socket.set_only_v6(false);
    }

    let _ = socket.set_reuse_address(true);
    let _ = socket.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = socket.set_send_buffer_size(4 * 1024 * 1024);

    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;

    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket)
}
