use crate::crypto::CuteBiCipher;
use std::io;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SessionType {
    /// 普通 TCP 隧道代理，附带解析出的目标 host (如 "example.com:443") 与是否启用异或加解密
    Tcp {
        target_host: String,
        is_encrypted: bool,
    },
    /// UDP 隧道会话 (httpUDP)
    Udp,
    /// DNS 优化查询 (:53 端口)
    DnsTcpOverUdp { target_host: String },
    /// HttpDNS 快速响应查询 (dn=域名)
    HttpDns { domain: String, is_ipv6: bool },
}

#[derive(Debug)]
pub struct HandshakeResult {
    pub session_type: SessionType,
    pub response_header: Option<Vec<u8>>,
    /// 握手时在 HTTP Header (\r\n\r\n) 之后收到的粘包载荷
    pub remaining_data: Vec<u8>,
}

/// HTTP 握手解析器
pub struct HandshakeParser {
    proxy_key: String,
    udp_flag: String,
    cipher: CuteBiCipher,
    enable_dns_tcp_over_udp: bool,
}

/// 规范化目标 Host 与端口，兼容 IPv4 / IPv6 (带方括号与不带方括号) / 域名
pub fn normalize_target_host(raw_target: &str) -> String {
    let target = raw_target.trim();
    if target.is_empty() {
        return "127.0.0.1:80".to_string();
    }

    // 1. 如果能直接解析为标准 SocketAddr (如 127.0.0.1:22 或 [::1]:22 或 [2001:db8::1]:22)
    if let Ok(sock) = target.parse::<std::net::SocketAddr>() {
        return sock.to_string();
    }

    // 2. 如果包含方括号 [2001:db8::1]:22 或 [2001:db8::1]
    if target.starts_with('[') {
        if let Some(bracket_end) = target.find(']') {
            let after = &target[bracket_end + 1..];
            if after.starts_with(':') {
                return target.to_string();
            } else {
                return format!("{}:80", target);
            }
        }
    }

    // 3. 处理未带方括号但带端口的 IPv6 (如 2001:db8::1:22)
    // 优先尝试将最后一个冒号视为端口分割符
    if let Some(last_colon) = target.rfind(':') {
        let ip_part = &target[..last_colon];
        let port_part = &target[last_colon + 1..];
        if let Ok(port) = port_part.parse::<u16>() {
            if let Ok(v6) = ip_part.parse::<std::net::Ipv6Addr>() {
                return format!("[{}]:{}", v6, port);
            }
        }
    }

    // 4. 如果能解析为纯 IP 地址（未带端口，如 ::1 或 1.1.1.1）
    if let Ok(ip) = target.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => format!("{}:80", v4),
            std::net::IpAddr::V6(v6) => format!("[{}]:80", v6),
        };
    }

    // 5. 纯域名或 IPv4:Port
    if !target.contains(':') {
        format!("{}:80", target)
    } else {
        target.to_string()
    }
}

impl HandshakeParser {
    pub fn new(
        proxy_key: &str,
        udp_flag: &str,
        cipher: CuteBiCipher,
        enable_dns_tcp_over_udp: bool,
    ) -> Self {
        Self {
            proxy_key: proxy_key.to_string(),
            udp_flag: udp_flag.to_string(),
            cipher,
            enable_dns_tcp_over_udp,
        }
    }

    pub fn is_http_request(header: &[u8]) -> bool {
        const HTTP_METHODS: &[&[u8]] = &[
            b"CONNECT ", b"GET ", b"POST ", b"HEAD ", b"PUT ",
            b"DELETE ", b"OPTIONS ", b"TRACE ", b"PATCH ", b"WRAPPED ",
        ];
        HTTP_METHODS.iter().any(|&m| header.starts_with(m))
    }

    pub fn build_response(header: &[u8]) -> Vec<u8> {
        let header_str = String::from_utf8_lossy(header);
        if header_str.contains("WebSocket") || header_str.contains("websocket") {
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: CuteBi Network Tunnel, (%>w<%)\r\n\r\n".to_vec()
        } else if header.starts_with(b"CON") {
            b"HTTP/1.1 200 Connection established\r\nServer: CuteBi Network Tunnel, (%>w<%)\r\nConnection: keep-alive\r\n\r\n".to_vec()
        } else {
            b"HTTP/1.1 200 OK\r\nServer: CuteBi Network Tunnel, (%>w<%)\r\nConnection: keep-alive\r\n\r\n".to_vec()
        }
    }

    /// 提取目标地址并判定是否需要流式异或解密
    /// 返回 Option<(规范化后的目标地址, 是否走 CuteBi 异或加密)>
    pub fn extract_target(&self, header: &[u8]) -> Option<(String, bool)> {
        // 1. 优先从专用免流头 (如 Proxy-Key: Meng) 提取
        let pattern = format!("\n{}: ", self.proxy_key);
        let pattern_bytes = pattern.as_bytes();

        let proxy_val = header
            .windows(pattern_bytes.len())
            .position(|w| w.eq_ignore_ascii_case(pattern_bytes))
            .map(|pos| {
                let start = pos + pattern_bytes.len();
                let end = header[start..]
                    .iter()
                    .position(|&b| b == b'\r' || b == b'\n')
                    .map(|offset| start + offset)
                    .unwrap_or(header.len());
                &header[start..end]
            });

        if let Some(raw_val) = proxy_val {
            if !raw_val.is_empty() {
                // 如果配置了加密密钥，尝试解密
                if !self.cipher.is_empty() {
                    if let Ok(decrypted) = self.cipher.decrypt_host(raw_val) {
                        return Some((normalize_target_host(&decrypted), true));
                    }
                }
                // 若无密码或解密失败但为可读明文（如明文配置），作为免加密直通模式
                if let Ok(plain_host) = String::from_utf8(raw_val.to_vec()) {
                    let trimmed = plain_host.trim();
                    if !trimmed.is_empty() {
                        return Some((normalize_target_host(trimmed), false));
                    }
                }
            }
        }

        // 2. 回退机制：标准 HTTP CONNECT 请求行 (解决安卓 SSH 客户端等通过 HTTP Proxy 直连)
        // 典型格式: CONNECT 127.0.0.1:22 HTTP/1.1 或 CONNECT [2001:db8::1]:22 HTTP/1.1
        if header.starts_with(b"CONNECT ") {
            let rest = &header[8..];
            if let Some(space_pos) = rest.iter().position(|&b| b == b' ' || b == b'\r' || b == b'\n') {
                if let Ok(connect_target) = String::from_utf8(rest[..space_pos].to_vec()) {
                    let trimmed = connect_target.trim();
                    if !trimmed.is_empty() {
                        // 标准 CONNECT 协议客户端不支持私有异或变换，采用纯透明直通
                        return Some((normalize_target_host(trimmed), false));
                    }
                }
            }
        }

        // 3. 回退机制：标准 Host 头部 (若存在端口)
        let host_pattern = b"\nHost: ";
        if let Some(pos) = header
            .windows(host_pattern.len())
            .position(|w| w.eq_ignore_ascii_case(host_pattern))
        {
            let start = pos + host_pattern.len();
            let end = header[start..]
                .iter()
                .position(|&b| b == b'\r' || b == b'\n')
                .map(|offset| start + offset)
                .unwrap_or(header.len());
            if let Ok(host_val) = String::from_utf8(header[start..end].to_vec()) {
                let trimmed = host_val.trim();
                if trimmed.contains(':') && !trimmed.contains("alipay.com") && !trimmed.contains("10010.com") {
                    return Some((normalize_target_host(trimmed), false));
                }
            }
        }

        None
    }

    pub fn parse(&self, raw_buf: &[u8]) -> io::Result<HandshakeResult> {
        if !Self::is_http_request(raw_buf) {
            return Ok(HandshakeResult {
                session_type: SessionType::Udp,
                response_header: None,
                remaining_data: raw_buf.to_vec(),
            });
        }

        // 寻找 HTTP 头部结束符 \r\n\r\n
        let (header_slice, remaining) = match raw_buf.windows(4).position(|w| w == b"\r\n\r\n") {
            Some(idx) => (&raw_buf[..idx + 4], &raw_buf[idx + 4..]),
            None => (raw_buf, &[][..]),
        };

        let header_str = String::from_utf8_lossy(header_slice);

        // 优先判断 HttpDNS (请求中包含 dn=domain)
        if let Some(dn_pos) = header_slice.windows(3).position(|w| w == b"dn=") {
            let dn_start = dn_pos + 3;
            let dn_bytes = &header_slice[dn_start..];
            let dn_end = dn_bytes
                .iter()
                .position(|&b| b == b'&' || b == b' ' || b == b'\r' || b == b'\n')
                .unwrap_or(dn_bytes.len());
            let domain = String::from_utf8_lossy(&dn_bytes[..dn_end]).trim().to_string();
            let is_ipv6 = header_str.contains("type=AAAA");

            return Ok(HandshakeResult {
                session_type: SessionType::HttpDns { domain, is_ipv6 },
                response_header: None,
                remaining_data: Vec::new(),
            });
        }

        let resp = Self::build_response(header_slice);

        // 判断是否为 httpUDP 模式
        if header_str.contains(&self.udp_flag) {
            return Ok(HandshakeResult {
                session_type: SessionType::Udp,
                response_header: Some(resp),
                remaining_data: remaining.to_vec(),
            });
        }

        // 解析目标 Host 与加解密模式
        let (formatted_host, is_encrypted) = self.extract_target(header_slice).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Failed to parse target host from HTTP header")
        })?;

        if self.enable_dns_tcp_over_udp && formatted_host.ends_with(":53") {
            Ok(HandshakeResult {
                session_type: SessionType::DnsTcpOverUdp { target_host: formatted_host },
                response_header: Some(resp),
                remaining_data: remaining.to_vec(),
            })
        } else {
            Ok(HandshakeResult {
                session_type: SessionType::Tcp {
                    target_host: formatted_host,
                    is_encrypted,
                },
                response_header: Some(resp),
                remaining_data: remaining.to_vec(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_target_host() {
        assert_eq!(normalize_target_host("127.0.0.1:22"), "127.0.0.1:22");
        assert_eq!(normalize_target_host("example.com"), "example.com:80");
        assert_eq!(normalize_target_host("example.com:443"), "example.com:443");
        assert_eq!(normalize_target_host("[::1]:22"), "[::1]:22");
        assert_eq!(normalize_target_host("::1"), "[::1]:80");
        assert_eq!(normalize_target_host("2001:db8::1:22"), "[2001:db8::1]:22");
        assert_eq!(normalize_target_host("[2001:db8::1]:22"), "[2001:db8::1]:22");
    }

    #[test]
    fn test_standard_connect_ssh_proxy() {
        let parser = HandshakeParser::new("Meng", "httpUDP", CuteBiCipher::new(b"tstkey"), true);
        let connect_req = b"CONNECT 2001:db8::1:22 HTTP/1.1\r\nHost: 2001:db8::1:22\r\nUser-Agent: Termius\r\n\r\n";
        let res = parser.parse(connect_req).unwrap();
        match res.session_type {
            SessionType::Tcp { target_host, is_encrypted } => {
                assert_eq!(target_host, "[2001:db8::1]:22");
                assert_eq!(is_encrypted, false);
            }
            _ => panic!("Expected TCP session"),
        }
        let resp_str = String::from_utf8(res.response_header.unwrap()).unwrap();
        assert!(resp_str.starts_with("HTTP/1.1 200 Connection established"));
    }

    #[test]
    fn test_cutebi_encrypted_tcp_proxy() {
        let cipher = CuteBiCipher::new(b"tstkey");
        let enc_host = cipher.encrypt_host("1.1.1.1:443");
        let parser = HandshakeParser::new("Meng", "httpUDP", cipher, true);

        let req = format!("GET / HTTP/1.1\r\nHost: mclient.alipay.com\r\nMeng: {}\r\n\r\n", enc_host);
        let res = parser.parse(req.as_bytes()).unwrap();
        match res.session_type {
            SessionType::Tcp { target_host, is_encrypted } => {
                assert_eq!(target_host, "1.1.1.1:443");
                assert_eq!(is_encrypted, true);
            }
            _ => panic!("Expected TCP session"),
        }
    }
}
