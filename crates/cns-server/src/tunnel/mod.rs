pub mod dns;
pub mod tcp;
pub mod udp;

pub use cns_core::transport::{BufferPool, PUMP_BUFFER_SIZE};
pub use dns::{handle_dns_tcp_over_udp, handle_http_dns};
pub use tcp::{pump_tcp_stream, pump_tcp_stream_with_pool};
pub use udp::{UdpTunnel, UdpTunnelStats};
