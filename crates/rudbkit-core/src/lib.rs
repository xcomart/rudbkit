//! Shared database connection configuration, independent of any UI.
#![warn(missing_docs)]
pub mod dialects;
pub mod products;
mod tunnel;
pub mod url;
pub use tunnel::{TunnelAuth, TunnelConfig};
pub mod save;
