//! Parallax engine.
//!
//! `parallax-core` is a UI-agnostic library: it holds the policy model, its
//! validation, address allocation, the [`transport::Transport`] abstraction with
//! the WireGuard implementation, every generator (WireGuard server config,
//! nftables ruleset, dnsmasq shim, per-platform client configs, nginx
//! snippets), and plan/apply. All side effects go through the traits in
//! [`io`], so every piece of the engine is testable in memory.
//!
//! The crate has no global state and never touches the filesystem, the
//! network, or a process on its own.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, rust_2018_idioms)]

pub mod alloc;
pub mod apply;
pub mod date;
pub mod error;
pub mod generate;
pub mod io;
pub mod model;
pub mod netmap;
pub mod plan;
pub mod secret;
pub mod testing;
pub mod transport;
pub mod validate;

pub use error::{Error, Result};
pub use model::*;
pub use validate::Model;

/// Tailscale's carrier-grade NAT range; every Tailscale node has an address here.
pub const TAILSCALE_CGNAT: ipnet::Ipv4Net =
    ipnet::Ipv4Net::new_assert(std::net::Ipv4Addr::new(100, 64, 0, 0), 10);
