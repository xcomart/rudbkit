//! Shared database connection configuration, independent of any UI.
#![warn(missing_docs)]
pub mod builtins;
pub mod dialects;
mod tunnel;
pub mod url;
pub use tunnel::{JumpHost, TunnelAuth, TunnelConfig};
pub mod save;
