//! cns-rs · 流量首包嗅探模块（纯 Rust 零依赖）
//!
//! 职责：从入站 TCP 首包原始字节流中嗅探目标信息（TLS SNI 或 HTTP Host）。
//! 解决问题：当 Linux/Android 内核通过 REDIRECT 劫持连接后，套接字只能获取到目标 IP，
//! 缺少真实域名。对于 CDN/多域名共享 IP 节点，直连 IP 经常导致握手失败或无法访问。
//! 通过嗅探 TLS ClientHello 的 SNI 或 HTTP 的 Host，可以还原真实目标域名。

use std::io;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};

/// 嗅探结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniffResult {
    /// 嗅探到 TLS ClientHello 并提取出 SNI 域名
    Tls { sni: String },
    /// 嗅探到 HTTP 请求并提取出目标 Host
    Http { host: String, is_absolute_uri: bool },
    /// 未能嗅探出已知协议（纯二进制、非 HTTP/TLS 协议或首包长度不足）
    Unknown,
}

pub struct Sniffer;

impl Sniffer {
    /// 从原始字节切片中嗅探目标信息
    pub fn sniff(buf: &[u8]) -> SniffResult {
        if buf.is_empty() {
            return SniffResult::Unknown;
        }

        // 1. 优先尝试嗅探 TLS SNI
        if let Some(sni) = Self::sniff_tls_sni(buf) {
            return SniffResult::Tls { sni };
        }

        // 2. 尝试嗅探 HTTP Host
        if let Some((host, is_absolute_uri)) = Self::sniff_http_host(buf) {
            return SniffResult::Http {
                host,
                is_absolute_uri,
            };
        }

        SniffResult::Unknown
    }

    /// 解析 TLS ClientHello 并提取 Server Name Indication (SNI)
    pub fn sniff_tls_sni(buf: &[u8]) -> Option<String> {
        // TLS Record Header 至少 5 字节: [ContentType: 0x16][LegacyVersion: 0x03, 0x01/0x03][Length: 2B]
        if buf.len() < 5 || buf[0] != 0x16 || buf[1] != 0x03 {
            return None;
        }

        let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        let mut pos = 5;
        if buf.len() < pos + record_len {
            return None;
        }

        // Handshake Header 至少 4 字节: [HandshakeType: 0x01 (ClientHello)][Length: 3B]
        if buf.len() <= pos || buf[pos] != 0x01 {
            return None;
        }
        pos += 4; // 跳过 HandshakeType(1) + Length(3)

        // ClientHello: [ClientVersion: 2B][Random: 32B]
        if buf.len() < pos + 34 {
            return None;
        }
        pos += 2; // 跳过 ClientVersion
        pos += 32; // 跳过 Random

        // Session ID: [SessionIDLen: 1B][SessionID: N]
        if buf.len() <= pos {
            return None;
        }
        let session_id_len = buf[pos] as usize;
        pos += 1 + session_id_len;

        // Cipher Suites: [CipherSuitesLen: 2B BE][CipherSuites: N]
        if buf.len() <= pos + 1 {
            return None;
        }
        let cipher_suites_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
        pos += 2 + cipher_suites_len;

        // Compression Methods: [CompMethodsLen: 1B][CompMethods: N]
        if buf.len() <= pos {
            return None;
        }
        let comp_len = buf[pos] as usize;
        pos += 1 + comp_len;

        // Extensions: [ExtensionsLen: 2B BE][Extensions: N]
        if buf.len() <= pos + 1 {
            return None;
        }
        let extensions_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
        pos += 2;

        let extensions_end = pos + extensions_len;
        if buf.len() < extensions_end {
            return None;
        }

        // 遍历所有 TLS 扩展
        while pos + 4 <= extensions_end {
            let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            let ext_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
            pos += 4;

            // 0x0000 = server_name (SNI) 扩展
            if ext_type == 0x0000 {
                if pos + 2 > extensions_end || pos + ext_len > extensions_end {
                    return None;
                }
                // ServerNameList: [ListLen: 2B BE]
                let mut p = pos + 2;
                let ext_limit = pos + ext_len;
                while p + 3 <= ext_limit {
                    let name_type = buf[p];
                    let name_len = u16::from_be_bytes([buf[p + 1], buf[p + 2]]) as usize;
                    p += 3;
                    // name_type == 0x00 表示 host_name
                    if name_type == 0x00 && p + name_len <= ext_limit {
                        let sni_bytes = &buf[p..p + name_len];
                        if let Ok(sni) = std::str::from_utf8(sni_bytes) {
                            return Some(sni.to_string());
                        }
                    }
                    p += name_len;
                }
            }
            pos += ext_len;
        }

        None
    }

    /// 纯字节级解析 HTTP 请求行与头部，提取 Host
    pub fn sniff_http_host(buf: &[u8]) -> Option<(String, bool)> {
        let trimmed = trim_start(buf);
        let methods: &[&[u8]] = &[
            b"GET ",
            b"POST ",
            b"HEAD ",
            b"PUT ",
            b"DELETE ",
            b"CONNECT ",
            b"OPTIONS ",
            b"PATCH ",
            b"TRACE ",
        ];

        if !methods.iter().any(|m| trimmed.starts_with(m)) {
            return None;
        }

        let mut lines = trimmed.split(|&b| b == b'\n');

        // 1. 检查首行请求行是否存在绝对 URI（如 GET http://target:port/path HTTP/1.1）
        let mut target_from_uri: Option<String> = None;
        if let Some(first_line_raw) = lines.next() {
            let line = trim_cr(first_line_raw);
            let parts: Vec<&[u8]> = line.split(|&b| b == b' ').filter(|p| !p.is_empty()).collect();
            if parts.len() >= 2 {
                let uri = parts[1];
                if starts_with_ignore_ascii_case(uri, b"http://") {
                    let rest = &uri[7..];
                    let host_bytes = match rest.iter().position(|&b| b == b'/' || b == b'?' || b == b'#') {
                        Some(pos) => &rest[..pos],
                        None => rest,
                    };
                    let host_clean = trim_bytes(host_bytes);
                    if !host_clean.is_empty() {
                        target_from_uri = Some(String::from_utf8_lossy(host_clean).to_string());
                    }
                }
            }
        }

        // 2. 逐行查找 Host: xxx 头部
        let mut target_from_header: Option<String> = None;
        for line_raw in lines {
            let line = trim_cr(line_raw);
            if line.is_empty() {
                // Header 结束
                break;
            }
            if starts_with_ignore_ascii_case(line, b"host:") {
                let host_val = trim_bytes(&line[5..]);
                if !host_val.is_empty() {
                    target_from_header = Some(String::from_utf8_lossy(host_val).to_string());
                    break;
                }
            }
        }

        if let Some(uri_host) = target_from_uri {
            return Some((uri_host, true));
        }

        if let Some(header_host) = target_from_header {
            return Some((header_host, false));
        }

        None
    }
}

fn trim_start(buf: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < buf.len() && (buf[i] == b' ' || buf[i] == b'\r' || buf[i] == b'\n' || buf[i] == b'\t') {
        i += 1;
    }
    &buf[i..]
}

fn trim_cr(buf: &[u8]) -> &[u8] {
    if let Some(&b'\r') = buf.last() {
        &buf[..buf.len() - 1]
    } else {
        buf
    }
}

fn trim_bytes(mut buf: &[u8]) -> &[u8] {
    while let Some(&b) = buf.first() {
        if b == b' ' || b == b'\t' || b == b'\r' || b == b'\n' {
            buf = &buf[1..];
        } else {
            break;
        }
    }
    while let Some(&b) = buf.last() {
        if b == b' ' || b == b'\t' || b == b'\r' || b == b'\n' {
            buf = &buf[..buf.len() - 1];
        } else {
            break;
        }
    }
    buf
}

fn starts_with_ignore_ascii_case(buf: &[u8], prefix: &[u8]) -> bool {
    if buf.len() < prefix.len() {
        return false;
    }
    buf[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// 首包预读的上限（8 KiB，覆盖现代后量子胖 ClientHello）
pub const PEEK_LIMIT: usize = 8192;

/// 首包读取的超时（超时后按已读内容继续决策，杜绝半开连接挂起）
pub const PEEK_TIMEOUT: Duration = Duration::from_secs(2);

fn peek_is_complete(buf: &[u8]) -> bool {
    if buf.len() >= PEEK_LIMIT {
        return true;
    }
    // HTTP 头结束
    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
        return true;
    }
    // TLS：记录头齐了且整条记录都到齐
    if buf.len() >= 5 && buf[0] == 0x16 && buf[1] == 0x03 {
        let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        if buf.len() >= 5 + record_len {
            return true;
        }
    }
    false
}

/// 循环读取入站首包用于嗅探
pub async fn read_peek_bounded<R: AsyncRead + Unpin>(
    r: &mut R,
    limit: usize,
    total_timeout: Duration,
) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; limit];
    let mut filled = 0usize;
    let deadline = tokio::time::Instant::now() + total_timeout;

    loop {
        if filled >= limit || peek_is_complete(&buf[..filled]) {
            break;
        }
        let step = tokio::time::timeout_at(deadline, r.read(&mut buf[filled..])).await;
        match step {
            Ok(Ok(0)) => break, // 对端 EOF
            Ok(Ok(n)) => filled += n,
            Ok(Err(e)) => {
                if filled == 0 {
                    return Err(e);
                }
                break;
            }
            Err(_) => break, // 超时：按已读内容降级决策
        }
    }
    buf.truncate(filled);
    Ok(buf)
}
