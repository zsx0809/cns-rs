pub mod dns;
pub mod tcp;
pub mod udp;

pub use dns::{handle_dns_tcp_over_udp, handle_http_dns};
pub use tcp::pump_tcp_stream;
pub use udp::UdpTunnel;
