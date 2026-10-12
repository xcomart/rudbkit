//! Shared JVM bootstrap and JNI bridge transport.
#![warn(missing_docs)]
mod error;
mod jvm;
pub use error::{Error, Result};
pub use jvm::{Jvm, JvmConfig, RuntimeIdentity, default_bridge_jar};
