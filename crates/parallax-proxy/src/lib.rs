//! Parallax's HTTPS proxy.
//!
//! One address and port often serves many sites, so the firewall alone can't
//! limit a template to one of them. Tiers that reach an HTTPS service only
//! through `service` grants are redirected here instead. The proxy
//! terminates TLS with the operator's certificate for the hostname, checks
//! that the caller's tunnel address may use it and that every request names
//! it, and forwards to the configured upstream over verified TLS.
//!
//! It reads only the routes file `apply` generates
//! ([`parallax_core::generate::proxy`]); SIGHUP re-reads it, and the
//! certificate folder is re-checked every minute so renewals need no restart.

mod error;
mod server;

pub mod certs;
pub mod http;

pub use error::{Error, Result};
pub use server::{serve, Proxy};
