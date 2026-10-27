use cns_core::crypto::CuteBiCipher;
use cns_core::protocol::{HttpUdpCodec, UdpPacket};
use bytes::BytesMut;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::codec::{Decoder, Encoder};
use tracing::{debug, warn};

const UDP_QUEUE_SIZE: usize = 2048;
const MAX_BATCH_BYTES: usize = 32 * 1024; // 32KB 微聚合阈值

pub struct UdpTunnel {
    client: TcpStream,
    udp_socket: Arc<UdpSocket>,
    cipher: CuteBiCipher,
    timeout_duration: Duration,
}

impl UdpTunnel {
    pub fn new(
        client: TcpStream,
        udp_socket: UdpSocket,
        cipher: CuteBiCipher,
        timeout_duration: Duration,
    ) -> Self {
        Self {
            client,
            udp_socket: Arc::new(udp_socket),
            cipher,
            timeout_duration,
        }
    }

    /// 启动 UDP 隧道生命周期
    pub async fn run(self, initial_data: Vec<u8>) -> io::Result<()> {
        let (mut c_read, mut c_write) = self.client.into_split();
        let (tx, mut rx) = mpsc::channel::<UdpPacket>(UDP_QUEUE_SIZE);

        let socket_recv = Arc::clone(&self.udp_socket);
        let socket_send = Arc::clone(&self.udp_socket);

        let cipher_c2s = self.cipher.clone();
        let cipher_s2c = self.cipher;

        let udp_timeout = self.timeout_duration;

        // 1. 专职 UDP 接收任务：从目标网络接收 UDP 报文，快速塞入异步队列
        let udp_recv_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let (len, peer) = match timeout(udp_timeout, socket_recv.recv_from(&mut buf)).await {
                    Ok(Ok(res)) => res,
                    Ok(Err(e)) => {
                        debug!("UDP socket recv_from error: {}", e);
                        break;
                    }
                    Err(_) => {
                        debug!("UDP socket recv idle timeout");
                        break;
                    }
                };

                let packet = UdpPacket {
                    peer,
                    payload: bytes::Bytes::copy_from_slice(&buf[..len]),
                };

                // 背压防卡顿：若队列已满，跳过最旧包以维持直播实时低时延
                if let Err(mpsc::error::TrySendError::Full(dropped)) = tx.try_send(packet) {
                    debug!("UDP queue full, dropped real-time packet: {} bytes", dropped.payload.len());
                }
            }
        });

        // 2. 专职 TCP 冲水任务：从队列批量拉取包，微聚合打包加密，推送到客户端
        let tcp_send_task = tokio::spawn(async move {
            let mut codec = HttpUdpCodec::new();
            let mut batch_buf = BytesMut::with_capacity(MAX_BATCH_BYTES);
            let mut pass_sub = 0;

            while let Some(packet) = rx.recv().await {
                batch_buf.clear();
                let _ = codec.encode(packet, &mut batch_buf);

                // 微聚合：如果队列中还有就绪的报文且未达到阈值，一并取出合并打包
                while batch_buf.len() < MAX_BATCH_BYTES {
                    match rx.try_recv() {
                        Ok(more_pkt) => {
                            let _ = codec.encode(more_pkt, &mut batch_buf);
                        }
                        Err(_) => break,
                    }
                }

                if !cipher_s2c.is_empty() {
                    pass_sub = cipher_s2c.crypt_in_place(&mut batch_buf, pass_sub);
                }

                if let Err(e) = timeout(udp_timeout, c_write.write_all(&batch_buf)).await {
                    debug!("TCP write to client failed: {:?}", e);
                    break;
                }
            }
            let _ = c_write.shutdown().await;
        });

        // 3. 专职客户端接收任务：从客户端 TCP 读取流，解密并由 codec 解包，打向互联网目标
        let tcp_recv_task = tokio::spawn(async move {
            let mut codec = HttpUdpCodec::new();
            let mut in_buffer = BytesMut::with_capacity(65535);
            let mut read_buf = vec![0u8; 32768];
            let mut pass_sub = 0;

            // 如果握手阶段有多余的数据，先处理
            if !initial_data.is_empty() {
                let mut data = initial_data;
                if !cipher_c2s.is_empty() {
                    pass_sub = cipher_c2s.crypt_in_place(&mut data, pass_sub);
                }
                in_buffer.extend_from_slice(&data);
                while let Ok(Some(pkt)) = codec.decode(&mut in_buffer) {
                    let _ = socket_send.send_to(&pkt.payload, pkt.peer).await;
                }
            }

            loop {
                let n = match timeout(udp_timeout, c_read.read(&mut read_buf)).await {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) => {
                        debug!("TCP read from client error: {}", e);
                        break;
                    }
                    Err(_) => {
                        debug!("TCP client idle timeout");
                        break;
                    }
                };

                let mut chunk = &mut read_buf[..n];
                if !cipher_c2s.is_empty() {
                    pass_sub = cipher_c2s.crypt_in_place(&mut chunk, pass_sub);
                }

                in_buffer.extend_from_slice(chunk);

                while let Ok(Some(pkt)) = codec.decode(&mut in_buffer) {
                    if let Err(e) = socket_send.send_to(&pkt.payload, pkt.peer).await {
                        warn!("Failed to send UDP packet to {}: {}", pkt.peer, e);
                    }
                }
            }
        });

        // 任意子任务退出时，级联结束整个会话
        tokio::select! {
            _ = udp_recv_task => {},
            _ = tcp_send_task => {},
            _ = tcp_recv_task => {},
        }

        Ok(())
    }
}
