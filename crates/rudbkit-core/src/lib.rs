//! Shared database connection configuration, independent of any UI.
#![warn(missing_docs)]
mod tunnel;
pub mod url;
pub use tunnel::{TunnelAuth, TunnelConfig};
pub mod save;
