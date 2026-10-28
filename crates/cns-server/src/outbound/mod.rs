pub mod direct;
pub mod resolver;

pub use direct::{DirectOutbound, Guard};
pub use resolver::{parse_dns_response, Resolver, ResolverOptions};
