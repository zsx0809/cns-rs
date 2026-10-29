pub mod direct;
pub mod resolver;

pub use direct::{DirectOutbound, Guard, FAKEIP_LEAK_MSG};
pub use resolver::{parse_dns_response, Resolver, ResolverOptions};
