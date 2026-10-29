use crate::protocol::{find_header_end, HandshakeParser};
use bytes::BytesMut;
use std::io;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

/// 单次 read 的搬运粒度
const READ_CHUNK: usize = 1024;

/// 流式读取直到出现 `\r\n\r\n`、连接 EOF、或超过 `max_bytes`。
///
/// 返回 `(原始字节, 是否读到完整头部)`。原始字节包含头部之后的粘包载荷，
/// 交由调用方决定如何继续处理。
///
/// 修复要点：
/// * 旧实现只读一次 1KB 就交给 `parse`，HTTP 头跨多个 TCP 段时（4G/5G 常态）直接失败；
/// * 客户端 DNS 路径把「响应头之后的字节」连同整包一起丢弃，导致后续 `read_exact` 死等超时。
pub async fn read_until_header_end<S>(
    stream: &mut S,
    per_read_timeout: Duration,
    max_bytes: usize,
) -> io::Result<(BytesMut, bool)>
where
    S: AsyncReadExt + Unpin,
{
    let mut buf = BytesMut::with_capacity(READ_CHUNK * 2);
    let mut tmp = [0u8; READ_CHUNK];

    loop {
        if buf.len() >= max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "handshake buffer exceeded limit",
            ));
        }

        let n = timeout(per_read_timeout, stream.read(&mut tmp))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake read timed out"))??;

        if n == 0 {
            // 对端关闭：把已读到的内容交回，由调用方判定（非 HTTP 的 UDP 首包也走这里）
            return Ok((buf, false));
        }

        buf.extend_from_slice(&tmp[..n]);

        if find_header_end(&buf).is_some() {
            return Ok((buf, true));
        }

        // 硬上限：无头部结束符却持续膨胀 = Slowloris / 畸形流量
        if buf.len() >= max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "handshake buffer exceeded limit without header terminator",
            ));
        }

        // 尚未成形的短 HTTP 前缀继续读；明确不是 HTTP 的字节流（httpUDP 首帧）立刻返回，
        // 避免把二进制 UDP 帧当成「半截 HTTP 头」一直等到超时。
        if !HandshakeParser::is_undecided_http(&buf) && !HandshakeParser::is_http_request(&buf) {
            return Ok((buf, false));
        }
    }
}

/// 读取服务端 HTTP 握手响应，返回 `(状态行, 头部之后的粘包数据)`。
///
/// `head` 为 `\r\n\r\n` 之前的完整响应头（不含分隔符）。
pub async fn read_response_head<S>(
    stream: &mut S,
    per_read_timeout: Duration,
    max_bytes: usize,
) -> io::Result<(Vec<u8>, BytesMut)>
where
    S: AsyncReadExt + Unpin,
{
    // 响应方向必须单独一套循环：`read_until_header_end` 里的
    // `is_undecided_http / is_http_request` 是**请求**启发式（HTTP_METHODS 表），
    // 而响应以 `HTTP/1.1` 开头——既不是方法前缀、长度又 ≥ MIN_HTTP_PROBE_LEN，
    // 于是一旦响应头被拆到两个 TCP 段里就会被判成「不是 HTTP」并直接报
    // UnexpectedEof。握手成败因此与 TCP 首段切点强相关，是最难查的一类随机失败。
    let mut raw = BytesMut::with_capacity(READ_CHUNK * 2);
    let mut tmp = [0u8; READ_CHUNK];
    loop {
        if raw.len() >= max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "handshake response exceeded limit without header terminator",
            ));
        }
        let n = timeout(per_read_timeout, stream.read(&mut tmp))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake read timed out"))??;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before response header completed",
            ));
        }
        raw.extend_from_slice(&tmp[..n]);
        if find_header_end(&raw).is_some() {
            break;
        }
        // 前缀已足以否定 HTTP：立刻失败，不留 60 秒超时的黑箱
        if raw.len() >= 5 && !raw.starts_with(b"HTTP/") {
            let snip = String::from_utf8_lossy(&raw[..raw.len().min(32)]).to_string();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("handshake response is not HTTP: {snip:?}"),
            ));
        }
    }
    let idx = find_header_end(&raw).expect("loop exits only on terminator");
    let mut rest = raw;
    let head = rest.split_to(idx + 4).to_vec();
    Ok((head, rest))
}

/// 校验响应状态是否为 2xx / 1xx 隧道成功
pub fn response_is_ok(head: &[u8]) -> bool {
    let s = String::from_utf8_lossy(head);
    s.starts_with("HTTP/1.1 200")
        || s.starts_with("HTTP/1.1 101")
        || s.starts_with("HTTP/1.0 200")
        || s.starts_with("HTTP/1.1 204")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn reads_split_headers() {
        // 模拟 HTTP 头被拆成多个 TCP 段
        let raw = b"CONNECT 1.1.1.1:443 HT"
            .iter()
            .chain(b"TP/1.1\r\nHost: 1.1.1.1:443\r\n\r\n")
            .copied()
            .collect::<Vec<u8>>();
        let cursor = std::io::Cursor::new(raw);
        let mut stream = BufReader::new(cursor);
        let (head, rest) =
            read_response_head(&mut stream, Duration::from_secs(1), 8192).await.unwrap();
        assert!(String::from_utf8_lossy(&head).starts_with("CONNECT 1.1.1.1:443"));
        assert!(rest.is_empty());
    }

    #[tokio::test]
    async fn keeps_sticky_payload() {
        let mut raw = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        raw.extend_from_slice(b"AFTERTHEHEAD");
        let mut stream = std::io::Cursor::new(raw);
        let (head, rest) =
            read_response_head(&mut stream, Duration::from_secs(1), 8192).await.unwrap();
        assert!(response_is_ok(&head));
        assert_eq!(&rest[..], b"AFTERTHEHEAD");
    }

    #[tokio::test]
    async fn non_http_bytes_return_immediately() {
        // httpUDP 二进制首帧不能被当成半截 HTTP 头等超时
        let raw = vec![0u8, 20, 0, 0, 0, 1, 1, 1, 1, 1, 0, 53, b'x', b'y'];
        let mut stream = std::io::Cursor::new(raw);
        let (buf, complete) =
            read_until_header_end(&mut stream, Duration::from_secs(5), 8192).await.unwrap();
        assert!(!complete);
        assert!(!buf.is_empty());
    }

    #[tokio::test]
    async fn oversized_buffer_is_rejected() {
        let raw = vec![b'A'; 4096];
        let mut stream = std::io::Cursor::new(raw);
        let err =
            read_until_header_end(&mut stream, Duration::from_secs(1), 512).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
