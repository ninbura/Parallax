//! Parallax's DNS server.
//!
//! One address serves every tier, and every answer depends on who asks: a
//! query from a tunnel address gets an answer only for names that tier may
//! reach (its granted networks' zones, its granted services' hostnames, and
//! public names where the tier has `public_dns`). Everything else is
//! refused. Home zones are forwarded to the home resolvers and their answers
//! rewritten into mapped space; public names go to the public resolver, and
//! answers pointing inward are dropped.
//!
//! It holds no records and doesn't recurse: it forwards, with a small cache.
//! It answers by the routes `apply` generates
//! ([`parallax_core::generate::dns`]); the daemon runs it and hands it new
//! routes around each apply ([`Dns::reloader`], [`overlap`]).

mod answer;
mod error;
pub mod lookup;
mod server;

pub use error::{Error, Result};
pub use lookup::Lookup;
pub use server::{overlap, Dns, Reload};
