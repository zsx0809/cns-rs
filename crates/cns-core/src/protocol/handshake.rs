use crate::crypto::CuteBiCipher;
use std::io;

#[derive(Debug, PartialEq, Eq)]
pub enum SessionType {
    /// 普通 TCP 隧道代理，附带解析出的目标 host (如 "example.com:443")
    Tcp { target_host: String },
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

    pub fn extract_proxy_host(&self, header: &[u8]) -> Option<String> {
        let pattern = format!("\n{}: ", self.proxy_key);
        let pattern_bytes = pattern.as_bytes();

        let pos = header.windows(pattern_bytes.len()).position(|window| window.eq_ignore_ascii_case(pattern_bytes))?;
        let value_start = pos + pattern_bytes.len();
        
        let value_end = header[value_start..]
            .iter()
            .position(|&b| b == b'\r' || b == b'\n')
            .map(|offset| value_start + offset)
            .unwrap_or(header.len());

        let raw_val = &header[value_start..value_end];
        if raw_val.is_empty() {
            return None;
        }

        if !self.cipher.is_empty() {
            match self.cipher.decrypt_host(raw_val) {
                Ok(h) => Some(h),
                Err(_) => None,
            }
        } else {
            String::from_utf8(raw_val.to_vec()).ok()
        }
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

        // 解析目标 Host
        let target_host = self.extract_proxy_host(header_slice).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Failed to parse target host from HTTP header")
        })?;

        let formatted_host = if !target_host.contains(':') {
            format!("{}:80", target_host)
        } else {
            target_host
        };

        if self.enable_dns_tcp_over_udp && formatted_host.ends_with(":53") {
            Ok(HandshakeResult {
                session_type: SessionType::DnsTcpOverUdp { target_host: formatted_host },
                response_header: Some(resp),
                remaining_data: remaining.to_vec(),
            })
        } else {
            Ok(HandshakeResult {
                session_type: SessionType::Tcp { target_host: formatted_host },
                response_header: Some(resp),
                remaining_data: remaining.to_vec(),
            })
        }
    }
}
