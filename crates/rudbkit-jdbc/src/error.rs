//! Failures at the runtime boundary.
/// Result returned by the shared runtime.
pub type Result<T> = std::result::Result<T, Error>;
/// A failure starting or calling the JVM.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Startup failed.
    #[error("cannot start the JVM: {0}")]
    JvmStart(String),
    /// JNI rejected a call.
    #[error("JNI call failed: {0}")]
    Jni(String),
    /// A bridge returned an invalid response.
    #[error("malformed bridge response: {0}")]
    Protocol(String),
}
impl From<jni::errors::Error> for Error {
    fn from(error: jni::errors::Error) -> Self {
        Self::Jni(error.to_string())
    }
}
