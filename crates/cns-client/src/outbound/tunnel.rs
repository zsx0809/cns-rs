use crate::config::ClientConfig;
use cns_core::crypto::CuteBiCipher;
use cns_core::transport::tune_tcp_stream;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const BUFFER_SIZE: usize = 32 * 1024;

pub struct CnsClientTunnel;

impl CnsClientTunnel {
    /// 与 CNS 服务端握手并建立 TCP 代理数据泵
    pub async fn handle_tcp_proxy(
        mut local_stream: TcpStream,
        target_host: &str,
        config: &ClientConfig,
        cipher: &CuteBiCipher,
    ) -> io::Result<()> {
        // 1. 连接 CNS 服务端
        let mut server_stream = TcpStream::connect(&config.cns_server).await?;
        tune_tcp_stream(&server_stream);

        // 2. 加密目标地址并组装 HTTP 伪装握手
        let encrypted_target = if !cipher.is_empty() {
            cipher.encrypt_host(target_host)
        } else {
            target_host.to_string()
        };

        let handshake_req = config.render_fake_header(&encrypted_target);
        server_stream.write_all(&handshake_req).await?;

        // 3. 读取并校验服务端的 HTTP 握手响应
        let mut resp_buf = [0u8; 1024];
        let n = timeout(config.timeout(), server_stream.read(&mut resp_buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Handshake timed out"))??;

        let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
        if !resp_str.starts_with("HTTP/1.1 200") && !resp_str.starts_with("HTTP/1.1 101") {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("CNS handshake failed with response: {}", resp_str.trim()),
            ));
        }

        // 提取响应头后粘包跟随的 Server-First 初始数据（如目标 SSH 服务器率先推送的 SSH-2.0 Banner 等）
        let initial_server_data = if let Some(pos) = resp_buf[..n].windows(4).position(|w| w == b"\r\n\r\n") {
            let remain_start = pos + 4;
            if remain_start < n {
                resp_buf[remain_start..n].to_vec()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // 4. 双向流式原位异或数据泵
        let (mut local_read, mut local_write) = local_stream.split();
        let (mut server_read, mut server_write) = server_stream.split();

        let cipher_c2s = cipher.clone();
        let cipher_s2c = cipher.clone();
        let timeout_dur = config.timeout();

        // 本地应用 -> CNS 服务端 (加密方向)
        let local_to_server = async move {
            let mut buf = vec![0u8; BUFFER_SIZE];
            let mut pass_sub = 0;
            loop {
                let n = match timeout(timeout_dur, local_read.read(&mut buf)).await {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) => return Err(e),
                    Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "Local read timed out")),
                };

                if !cipher_c2s.is_empty() {
                    pass_sub = cipher_c2s.crypt_in_place(&mut buf[..n], pass_sub);
                }

                timeout(timeout_dur, server_write.write_all(&buf[..n]))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Server write timed out"))??;
            }
            let _ = server_write.shutdown().await;
            Ok::<(), io::Error>(())
        };

        // CNS 服务端 -> 本地应用 (解密方向)
        let server_to_local = async move {
            let mut buf = vec![0u8; BUFFER_SIZE];
            let mut pass_sub = 0;

            // 优先解密并转发握手响应中附带的 Server-First 初始载荷（如 SSH Banner）
            if !initial_server_data.is_empty() {
                let mut init_buf = initial_server_data;
                if !cipher_s2c.is_empty() {
                    pass_sub = cipher_s2c.crypt_in_place(&mut init_buf, pass_sub);
                }
                timeout(timeout_dur, local_write.write_all(&init_buf))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Initial local write timed out"))??;
            }

            loop {
                let n = match timeout(timeout_dur, server_read.read(&mut buf)).await {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) => return Err(e),
                    Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "Server read timed out")),
                };

                if !cipher_s2c.is_empty() {
                    pass_sub = cipher_s2c.crypt_in_place(&mut buf[..n], pass_sub);
                }

                timeout(timeout_dur, local_write.write_all(&buf[..n]))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Local write timed out"))??;
            }
            let _ = local_write.shutdown().await;
            Ok::<(), io::Error>(())
        };

        // 双向流独立协同传输，支持 TCP 半关闭 (Half-Close)，绝不因单向 EOF 强行掐断另一向数据
        let _ = tokio::try_join!(local_to_server, server_to_local);

        Ok(())
    }
}
