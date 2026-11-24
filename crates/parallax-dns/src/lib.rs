//! Parallax's DNS server.
//!
//! One address serves every tier, and every answer depends on who asks: a
//! query from a tunnel address gets an answer only for names that tier may
//! reach (its granted networks' zones, its granted services' hostnames, and
//! public names where the template has `dns.public`). Everything else is
//! refused. Home zones are forwarded to the home resolvers and their answers
//! rewritten into mapped space; public names go to the public resolver, and
//! answers pointing inward are dropped.
//!
//! It holds no records and doesn't recurse: it forwards, with a small cache.
//! It reads only the routes file `apply` generates
//! ([`parallax_core::generate::dns`]); the daemon runs it and has it re-read
//! the routes after each apply ([`Dns::reload_trigger`]).

mod answer;
mod error;
mod server;

pub use error::{Error, Result};
pub use server::Dns;
