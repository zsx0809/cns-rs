use cns_core::transport::connect_any;
use std::io;
use std::net::{IpAddr, SocketAddr};
use tokio::net::{TcpStream, UdpSocket};

/// 回源守卫：拒绝把流量代理到本机、内网、云元数据等非公网地址。
///
/// CNS 的协议设计是「客户端在 HTTP 头里指定任意目标」，服务端无守卫即成为
/// 面向内网的 SSRF 跳板（打路由器、打 169.254.169.254 偷实例凭据）。
#[derive(Clone, Copy, Debug)]
pub struct Guard {
    pub allow_private: bool,
}

impl Guard {
    pub fn new(allow_private: bool) -> Self {
        Self { allow_private }
    }

    pub fn check_ip(&self, ip: IpAddr) -> io::Result<()> {
        if self.allow_private {
            return Ok(());
        }
        if crate::config::is_restricted_ip(ip) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "target {ip} is restricted (loopback/private/link-local/metadata); \
                         enable allow_private_targets or allow_target_cidrs to permit it"
                ),
            ));
        }
        Ok(())
    }

    /// 域名目标必须先解析再校验：否则 `http://internal-host/` 会绕过 IP 检查
    pub async fn resolve_and_check(&self, target: &str) -> io::Result<Vec<SocketAddr>> {
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(target).await?.collect();
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("no address resolved for {target}"),
            ));
        }
        if !self.allow_private {
            let ok: Vec<SocketAddr> = addrs
                .iter()
                .filter(|a| !crate::config::is_restricted_ip(a.ip()))
                .copied()
                .collect();
            if ok.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("all resolved addresses for {target} are restricted"),
                ));
            }
            return Ok(ok);
        }
        Ok(addrs)
    }
}

pub struct DirectOutbound;

impl DirectOutbound {
    /// 建立到目标服务器的直连（带 SSRF 守卫与 TFO）
    pub async fn dial_tcp(target: &str, guard: Guard, enable_tfo: bool) -> io::Result<TcpStream> {
        let addrs = if let Ok(addr) = target.parse::<SocketAddr>() {
            guard.check_ip(addr.ip())?;
            vec![addr]
        } else {
            guard.resolve_and_check(target).await?
        };

        let mut last_err = io::Error::other("dial failed");
        for addr in addrs {
            match connect_any(&addr.to_string(), enable_tfo).await {
                Ok(stream) => {
                    // 二次确认：连接建立后的真实远端地址也必须合法
                    if let Ok(peer) = stream.peer_addr() {
                        guard.check_ip(peer.ip())?;
                    }
                    return Ok(stream);
                }
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    /// 创建用于转发 UDP/DNS 的本地套接字。
    ///
    /// `prefer_v6` 时绑定 v6 双栈 socket；否则绑定 v4。旧实现固定 `[::]:0`，
    /// 在禁用 IPv6 的容器/小鸡上直接失败导致 UDP 隧道全灭。
    pub async fn bind_udp(prefer_v6: bool) -> io::Result<UdpSocket> {
        let v6: SocketAddr = "[::]:0".parse().unwrap();
        let v4: SocketAddr = "0.0.0.0:0".parse().unwrap();

        let first = if prefer_v6 { v6 } else { v4 };
        let second = if prefer_v6 { v4 } else { v6 };

        match cns_core::transport::create_tuned_udp_socket(first) {
            Ok(sock) => Ok(sock),
            Err(e1) => cns_core::transport::create_tuned_udp_socket(second).map_err(|e2| {
                io::Error::other(format!("udp bind failed: primary={e1}, fallback={e2}"))
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_blocks_private_allows_public() {
        let g = Guard::new(false);
        assert!(g.check_ip("127.0.0.1".parse().unwrap()).is_err());
        assert!(g.check_ip("169.254.169.254".parse().unwrap()).is_err());
        assert!(g.check_ip("10.0.0.5".parse().unwrap()).is_err());
        assert!(g.check_ip("1.1.1.1".parse().unwrap()).is_ok());

        let open = Guard::new(true);
        assert!(open.check_ip("127.0.0.1".parse().unwrap()).is_ok());
    }

    #[tokio::test]
    async fn dial_refuses_loopback_before_connecting() {
        let g = Guard::new(false);
        let err = DirectOutbound::dial_tcp("127.0.0.1:9", g, false).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn bind_udp_fallback_succeeds() {
        // 无论是否支持 v6，两种偏好都必须能拿到一个可用 socket
        for prefer_v6 in [true, false] {
            let sock = DirectOutbound::bind_udp(prefer_v6).await.unwrap();
            assert!(sock.local_addr().is_ok());
        }
    }
}
