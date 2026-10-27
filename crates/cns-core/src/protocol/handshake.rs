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
}

#[derive(Debug)]
pub struct HandshakeResult {
    pub session_type: SessionType,
    pub response_header: Option<Vec<u8>>,
    /// 握手时多读出的非 HTTP 头部数据（残留 payload）
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

    /// 判断是否是 HTTP 请求方法前缀
    pub fn is_http_request(header: &[u8]) -> bool {
        const HTTP_METHODS: &[&[u8]] = &[
            b"CONNECT ", b"GET ", b"POST ", b"HEAD ", b"PUT ",
            b"DELETE ", b"OPTIONS ", b"TRACE ", b"PATCH ", b"WRAPPED ",
        ];
        HTTP_METHODS.iter().any(|&m| header.starts_with(m))
    }

    /// 构造 HTTP 伪装响应头
    pub fn build_response(header: &[u8]) -> Vec<u8> {
        let header_str = String::from_utf8_lossy(header);
        if header_str.contains("WebSocket") || header_str.contains("websocket") {
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: CuteBi Network Tunnel, (%>w<%)\r\n\r\n".to_vec()
        } else if header.starts_with(b"CON") {
            b"HTTP/1.1 200 Connection established\r\nServer: CuteBi Network Tunnel, (%>w<%)\r\nConnection: keep-alive\r\n\r\n".to_vec()
        } else {
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nServer: CuteBi Network Tunnel, (%>w<%)\r\nConnection: keep-alive\r\n\r\n".to_vec()
        }
    }

    /// 从 HTTP 请求头中提取指定的 proxy_key (例如 "Meng" 或 "Host")
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

    /// 核心解析逻辑
    pub fn parse(&self, header_buf: &[u8]) -> io::Result<HandshakeResult> {
        if !Self::is_http_request(header_buf) {
            // 非 HTTP 协议头，直接作为无头 httpUDP 会话处理
            return Ok(HandshakeResult {
                session_type: SessionType::Udp,
                response_header: None,
                remaining_data: header_buf.to_vec(),
            });
        }

        let resp = Self::build_response(header_buf);
        let header_str = String::from_utf8_lossy(header_buf);

        // 判断是否为 httpUDP 模式
        if header_str.contains(&self.udp_flag) {
            return Ok(HandshakeResult {
                session_type: SessionType::Udp,
                response_header: Some(resp),
                remaining_data: Vec::new(),
            });
        }

        // 普通 TCP 隧道代理：解析目标 Host
        let target_host = self.extract_proxy_host(header_buf).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Failed to parse target host from HTTP header")
        })?;

        // 规范化端口 (如 "example.com" 补充默认 ":80")
        let formatted_host = if !target_host.contains(':') {
            format!("{}:80", target_host)
        } else {
            target_host
        };

        if self.enable_dns_tcp_over_udp && formatted_host.ends_with(":53") {
            Ok(HandshakeResult {
                session_type: SessionType::DnsTcpOverUdp { target_host: formatted_host },
                response_header: Some(resp),
                remaining_data: Vec::new(),
            })
        } else {
            Ok(HandshakeResult {
                session_type: SessionType::Tcp { target_host: formatted_host },
                response_header: Some(resp),
                remaining_data: Vec::new(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_detection_and_responses() {
        assert!(HandshakeParser::is_http_request(b"GET / HTTP/1.1\r\n"));
        assert!(HandshakeParser::is_http_request(b"CONNECT mclient.alipay.com:443 HTTP/1.1\r\n"));
        assert!(!HandshakeParser::is_http_request(&[0, 10, 0, 0, 0, 1]));

        let get_resp = HandshakeParser::build_response(b"GET / HTTP/1.1\r\n");
        assert!(get_resp.starts_with(b"HTTP/1.1 200 OK"));

        let conn_resp = HandshakeParser::build_response(b"CONNECT example.com HTTP/1.1\r\n");
        assert!(conn_resp.starts_with(b"HTTP/1.1 200 Connection established"));

        let ws_resp = HandshakeParser::build_response(b"GET / HTTP/1.1\r\nUpgrade: websocket\r\n");
        assert!(ws_resp.starts_with(b"HTTP/1.1 101 Switching Protocols"));
    }

    #[test]
    fn test_parse_tcp_with_encrypted_host() {
        let cipher = CuteBiCipher::new(b"test_mock_password");
        let parser = HandshakeParser::new("Meng", "httpUDP", cipher.clone(), true);

        let target = "1.1.1.1:853";
        let encrypted_target = cipher.encrypt_host(target);

        let req = format!(
            "GET / HTTP/1.1\r\nHost: mclient.alipay.com\r\nMeng: {}\r\n\r\n",
            encrypted_target
        );

        let result = parser.parse(req.as_bytes()).unwrap();
        match result.session_type {
            SessionType::Tcp { target_host } => {
                assert_eq!(target_host, target);
            }
            _ => panic!("Expected TCP session"),
        }
        assert!(result.response_header.is_some());
    }

    #[test]
    fn test_parse_udp_session() {
        let cipher = CuteBiCipher::new(b"test_mock_password");
        let parser = HandshakeParser::new("Meng", "httpUDP", cipher, true);

        let req = b"GET / HTTP/1.1\r\nHost: mclient.alipay.com\r\nhttpUDP: on\r\n\r\n";
        let result = parser.parse(req).unwrap();
        assert_eq!(result.session_type, SessionType::Udp);
    }
}
