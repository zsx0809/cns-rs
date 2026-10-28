use crate::crypto::CuteBiCipher;
use std::io;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SessionType {
    /// 普通 TCP 隧道代理，附带解析出的规范化目标 host (如 "example.com:443" 或 "[2001:db8::1]:22")
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

/// HTTP 方法前缀，同时用于「首字节尚不足以判定」时的最长匹配长度
const HTTP_METHODS: &[&[u8]] = &[
    b"CONNECT ",
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"TRACE ",
    b"PATCH ",
    b"WRAPPED ",
];

/// 判定为 HTTP 请求所需的最小字节数（最长方法名 `OPTIONS ` = 8）
pub const MIN_HTTP_PROBE_LEN: usize = 8;

/// 握手缓冲区的硬上限，防 Slowloris 式内存占用
pub const MAX_HANDSHAKE_BYTES: usize = 16 * 1024;

/// 规范化目标 Host 与端口，兼容 IPv4 / IPv6 (带方括号与不带方括号) / 域名。
///
/// `default_port` 取代旧实现里写死的 `:80`：CONNECT + TLS 场景只给域名时，
/// 落到 80 会直接卡死，交由调用方按会话语义决定。
pub fn normalize_target_host_with_port(raw_target: &str, default_port: u16) -> String {
    let target = raw_target.trim();
    if target.is_empty() {
        return String::new();
    }

    // 1. 能直接解析为标准 SocketAddr (如 127.0.0.1:22 / [::1]:22 / [2001:db8::1]:22)
    if let Ok(sock) = target.parse::<std::net::SocketAddr>() {
        return sock.to_string();
    }

    // 2. 带方括号：[2001:db8::1]:22 或 [2001:db8::1]
    if target.starts_with('[') {
        if let Some(bracket_end) = target.find(']') {
            let after = &target[bracket_end + 1..];
            if after.starts_with(':') {
                return target.to_string();
            }
            return format!("{target}:{default_port}");
        }
    }

    // 3. 未带方括号但带端口的 IPv6 (如 2001:db8::1:22)
    if let Some(last_colon) = target.rfind(':') {
        let ip_part = &target[..last_colon];
        let port_part = &target[last_colon + 1..];
        if let Ok(port) = port_part.parse::<u16>() {
            if let Ok(v6) = ip_part.parse::<std::net::Ipv6Addr>() {
                return format!("[{v6}]:{port}");
            }
        }
    }

    // 4. 纯 IP 地址（未带端口，如 ::1 或 1.1.1.1）
    if let Ok(ip) = target.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => format!("{v4}:{default_port}"),
            std::net::IpAddr::V6(v6) => format!("[{v6}]:{default_port}"),
        };
    }

    // 5. 纯域名或 IPv4:Port
    if !target.contains(':') {
        format!("{target}:{default_port}")
    } else {
        target.to_string()
    }
}

/// 兼容旧签名：默认端口 80
pub fn normalize_target_host(raw_target: &str) -> String {
    normalize_target_host_with_port(raw_target, 80)
}

/// 握手解析器
pub struct HandshakeParser {
    proxy_key: String,
    udp_flag: String,
    cipher: CuteBiCipher,
    enable_dns_tcp_over_udp: bool,
    /// 无目标头时的缺省端口（CONNECT/TLS 会话应为 443）
    default_port: u16,
    /// 伪装域名列表（如 mclient.alipay.com）：这些 Host 只用于迷惑 DPI，绝不作为真实目标
    decoy_hosts: Vec<String>,
    /// 响应头 Server 标识，保持与原版特征串兼容
    server_tag: String,
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
            default_port: 80,
            decoy_hosts: vec!["alipay.com".to_string(), "10010.com".to_string()],
            server_tag: "CuteBi Network Tunnel, (%>w<%)".to_string(),
        }
    }

    /// 使用完整配置构造（伪装域名不再硬编码在代码里）
    pub fn with_options(
        proxy_key: &str,
        udp_flag: &str,
        cipher: CuteBiCipher,
        enable_dns_tcp_over_udp: bool,
        header_host: &str,
        default_port: u16,
    ) -> Self {
        let mut parser = Self::new(proxy_key, udp_flag, cipher, enable_dns_tcp_over_udp);
        parser.default_port = if default_port == 0 { 80 } else { default_port };

        let host = header_host.trim().to_string();
        if !host.is_empty() && !parser.decoy_hosts.iter().any(|d| host.ends_with(d.as_str())) {
            parser.decoy_hosts.push(host);
        }
        parser
    }

    /// 是否为已知的 HTTP 请求起始
    pub fn is_http_request(header: &[u8]) -> bool {
        HTTP_METHODS.iter().any(|&m| header.starts_with(m))
    }

    /// 前缀太短、还无法断定是不是 HTTP：调用方应继续读取而不是立刻判为 UDP。
    ///
    /// 修复：旧实现在只收到 `"GET"` 这 3 字节时 `is_http_request` 返回 false，
    /// 于是把 TCP 会话误判成 httpUDP。
    pub fn is_undecided_http(header: &[u8]) -> bool {
        if header.len() >= MIN_HTTP_PROBE_LEN || header.is_empty() {
            return false;
        }
        HTTP_METHODS.iter().any(|&m| m.starts_with(header) || header.starts_with(m))
    }

    pub fn build_response(&self, header: &[u8]) -> Vec<u8> {
        let header_str = String::from_utf8_lossy(header);
        let server = self.server_tag.as_str();
        if header_str.contains("WebSocket") || header_str.contains("websocket") {
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {server}\r\n\r\n"
            )
            .into_bytes()
        } else if header.starts_with(b"CON") {
            format!("HTTP/1.1 200 Connection established\r\nServer: {server}\r\nConnection: keep-alive\r\n\r\n").into_bytes()
        } else {
            format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nServer: {server}\r\nConnection: keep-alive\r\n\r\n").into_bytes()
        }
    }

    fn read_header_value<'a>(&self, header: &'a [u8], pattern: &[u8]) -> Option<&'a [u8]> {
        header.windows(pattern.len()).position(|w| w.eq_ignore_ascii_case(pattern)).map(|pos| {
            let start = pos + pattern.len();
            let end = header[start..]
                .iter()
                .position(|&b| b == b'\r' || b == b'\n')
                .map(|offset| start + offset)
                .unwrap_or(header.len());
            &header[start..end]
        })
    }

    fn is_decoy_host(&self, host: &str) -> bool {
        // 带端口的伪装域（如 mclient.alipay.com:80）同样要排除
        let bare = host.split(':').next().unwrap_or(host);
        self.decoy_hosts.iter().any(|d| bare == d || bare.ends_with(&format!(".{d}")))
    }

    /// 从 HTTP 请求头中提取并规范化目标主机地址 (对齐原版 Go 的 getProxyHost 语义)
    pub fn extract_target(&self, header: &[u8]) -> Option<String> {
        // 1. 优先从专用免流头 (如 Proxy-Key: Meng) 提取
        let pattern = format!("\n{}: ", self.proxy_key);
        if let Some(raw_val) = self.read_header_value(header, pattern.as_bytes()) {
            if !raw_val.is_empty() {
                // 配置了混淆口令时先解出 Host
                if !self.cipher.is_empty() {
                    if let Ok(decrypted) = self.cipher.decrypt_host(raw_val) {
                        let host = normalize_target_host_with_port(&decrypted, self.default_port);
                        if !host.is_empty() {
                            return Some(host);
                        }
                    }
                } else if let Ok(plain_host) = String::from_utf8(raw_val.to_vec()) {
                    let host =
                        normalize_target_host_with_port(plain_host.trim(), self.default_port);
                    if !host.is_empty() {
                        return Some(host);
                    }
                }
            }
        }

        // 2. CONNECT 请求行的权威目标（`CONNECT host:port HTTP/1.1`）
        if let Some(rest) = header.strip_prefix(b"CONNECT ") {
            if let Some(space_pos) =
                rest.iter().position(|&b| b == b' ' || b == b'\r' || b == b'\n')
            {
                if let Ok(connect_target) = String::from_utf8(rest[..space_pos].to_vec()) {
                    let host = normalize_target_host_with_port(connect_target.trim(), 443);
                    if !host.is_empty() && !self.is_decoy_host(&host) {
                        return Some(host);
                    }
                }
            }
        }

        // 3. 回退：从 Host 头提取（跳过伪装域名）
        if let Some(raw_val) = self.read_header_value(header, b"\nHost: ") {
            if let Ok(host_val) = String::from_utf8(raw_val.to_vec()) {
                let trimmed = host_val.trim();
                if !trimmed.is_empty() && !self.is_decoy_host(trimmed) {
                    return Some(normalize_target_host_with_port(trimmed, self.default_port));
                }
            }
        }

        None
    }

    pub fn parse(&self, raw_buf: &[u8]) -> io::Result<HandshakeResult> {
        if !Self::is_http_request(raw_buf) {
            if Self::is_undecided_http(raw_buf) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "handshake prefix too short to classify",
                ));
            }
            return Ok(HandshakeResult {
                session_type: SessionType::Udp,
                response_header: None,
                remaining_data: raw_buf.to_vec(),
            });
        }

        // 寻找 HTTP 头部结束符 \r\n\r\n
        let (header_slice, remaining) = match find_header_end(raw_buf) {
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

        let resp = self.build_response(header_slice);

        // 判断是否为 httpUDP 模式
        if header_str.contains(&self.udp_flag) {
            return Ok(HandshakeResult {
                session_type: SessionType::Udp,
                response_header: Some(resp),
                remaining_data: remaining.to_vec(),
            });
        }

        // 解析目标 Host
        let formatted_host = self.extract_target(header_slice).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Failed to parse target host from HTTP header",
            )
        })?;

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

/// 返回 `\r\n\r\n` 的起始下标
pub fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
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
    fn test_normalize_target_host_custom_default_port() {
        assert_eq!(normalize_target_host_with_port("example.com", 443), "example.com:443");
        assert_eq!(normalize_target_host_with_port("[2001:db8::1]", 8443), "[2001:db8::1]:8443");
        assert_eq!(normalize_target_host_with_port("", 443), "");
    }

    #[test]
    fn test_undecided_short_http_prefix() {
        assert!(HandshakeParser::is_undecided_http(b"GET"));
        assert!(HandshakeParser::is_undecided_http(b"CONNE"));
        assert!(!HandshakeParser::is_undecided_http(b"GET / HTTP/1.1\r\n"));
        assert!(!HandshakeParser::is_undecided_http(b"\x00\x01\x02\x03"));
    }

    #[test]
    fn test_parse_requires_decision_or_udp() {
        // 3 字节 "GET" 必须报 WouldBlock 而不是误判 UDP
        let parser = HandshakeParser::new("Meng", "httpUDP", CuteBiCipher::empty(), true);
        let err = parser.parse(b"GET").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);

        // 明显非 HTTP 才判 UDP
        let res = parser.parse(&[0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70]).unwrap();
        assert_eq!(res.session_type, SessionType::Udp);
    }

    #[test]
    fn test_standard_connect_ssh_proxy() {
        let parser = HandshakeParser::new("Meng", "httpUDP", CuteBiCipher::new(b"tstkey"), true);
        let connect_req =
            b"CONNECT 2001:db8::1:22 HTTP/1.1\r\nHost: 2001:db8::1:22\r\nUser-Agent: Termius\r\n\r\n";
        let res = parser.parse(connect_req).unwrap();
        match res.session_type {
            SessionType::Tcp { target_host } => {
                assert_eq!(target_host, "[2001:db8::1]:22");
            }
            other => panic!("Expected TCP session, got {other:?}"),
        }
        let resp_str = String::from_utf8(res.response_header.unwrap()).unwrap();
        assert!(resp_str.starts_with("HTTP/1.1 200 Connection established"));
    }

    #[test]
    fn test_cutebi_encrypted_tcp_proxy() {
        let cipher = CuteBiCipher::new(b"tstkey");
        let enc_host = cipher.encrypt_host("1.1.1.1:443");
        let parser = HandshakeParser::new("Meng", "httpUDP", cipher, true);

        let req = format!("GET / HTTP/1.1\r\nHost: mclient.alipay.com\r\nMeng: {enc_host}\r\n\r\n");
        let res = parser.parse(req.as_bytes()).unwrap();
        match res.session_type {
            SessionType::Tcp { target_host } => {
                assert_eq!(target_host, "1.1.1.1:443");
            }
            other => panic!("Expected TCP session, got {other:?}"),
        }
        let resp_str = String::from_utf8(res.response_header.unwrap()).unwrap();
        assert!(resp_str.contains("Transfer-Encoding: chunked"));
    }

    #[test]
    fn test_connect_to_decoy_host_falls_back_to_proxy_key() {
        // CONNECT 请求行若只是伪装域，绝不能真的去连它
        let cipher = CuteBiCipher::new(b"tstkey");
        let parser = HandshakeParser::new("Meng", "httpUDP", cipher.clone(), true);
        let enc = cipher.encrypt_host("93.184.216.34:443");
        let req = format!(
            "CONNECT mclient.alipay.com:443 HTTP/1.1\r\nHost: mclient.alipay.com\r\nMeng: {enc}\r\n\r\n"
        );
        let res = parser.parse(req.as_bytes()).unwrap();
        match res.session_type {
            SessionType::Tcp { target_host } => {
                assert_eq!(target_host, "93.184.216.34:443");
            }
            other => panic!("Expected TCP session, got {other:?}"),
        }
    }

    #[test]
    fn test_custom_decoy_host_not_used_as_target() {
        let parser = HandshakeParser::with_options(
            "Meng",
            "httpUDP",
            CuteBiCipher::empty(),
            true,
            "custom-decoy.example",
            80,
        );
        // 无 Proxy-Key 头，只有伪装 Host → 必须解析失败而不是连到伪装域
        let req = b"GET / HTTP/1.1\r\nHost: custom-decoy.example:80\r\n\r\n";
        assert!(parser.parse(req).is_err());

        // 真实域名的 Host 仍可用
        let req2 = b"GET / HTTP/1.1\r\nHost: www.real-target.com:443\r\n\r\n";
        match parser.parse(req2).unwrap().session_type {
            SessionType::Tcp { target_host } => {
                assert_eq!(target_host, "www.real-target.com:443")
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn test_httpdns_and_udp_flag_classification() {
        let parser = HandshakeParser::new("Meng", "httpUDP", CuteBiCipher::empty(), true);
        match parser
            .parse(b"GET /vip.py?dn=www.baidu.com&type=A HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap()
            .session_type
        {
            SessionType::HttpDns { domain, is_ipv6 } => {
                assert_eq!(domain, "www.baidu.com");
                assert!(!is_ipv6);
            }
            other => panic!("unexpected {other:?}"),
        }

        match parser
            .parse(b"GET / HTTP/1.1\r\nHost: x\r\nhttpUDP: on\r\n\r\n")
            .unwrap()
            .session_type
        {
            SessionType::Udp => {}
            other => panic!("unexpected {other:?}"),
        }

        // :53 目标走 tcpDNS
        match parser
            .parse(b"CONNECT 8.8.8.8:53 HTTP/1.1\r\nHost: 8.8.8.8:53\r\n\r\n")
            .unwrap()
            .session_type
        {
            SessionType::DnsTcpOverUdp { target_host } => {
                assert_eq!(target_host, "8.8.8.8:53")
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn test_sticky_packet_after_header_is_preserved() {
        let parser = HandshakeParser::new("Meng", "httpUDP", CuteBiCipher::empty(), true);
        let mut raw = b"CONNECT 1.2.3.4:443 HTTP/1.1\r\nHost: 1.2.3.4:443\r\n\r\n".to_vec();
        raw.extend_from_slice(b"TLS-CLIENTHELLO-BYTES");
        let res = parser.parse(&raw).unwrap();
        assert_eq!(res.remaining_data, b"TLS-CLIENTHELLO-BYTES");
    }

    #[test]
    fn test_find_header_end() {
        assert_eq!(find_header_end(b"ab\r\ncd\r\n\r\nxy"), Some(6));
        assert_eq!(find_header_end(b"no terminator"), None);
    }
}
