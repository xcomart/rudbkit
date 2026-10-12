//! Connection validation and ordered persistence shared by connection dialogs.

/// The field or storage layer that rejected a save.
#[derive(Debug)]
pub enum SaveError<E> {
    /// A name must be present.
    Name,
    /// A JDBC URL must be present.
    Url,
    /// Saving the profile failed.
    Store(E),
    /// Saving a secret failed.
    Secret(E),
}

/// Validates the fields common to every database connection.
pub fn validate_connection<E>(name: &str, url: &str) -> Result<(), SaveError<E>> {
    if name.trim().is_empty() {
        return Err(SaveError::Name);
    }
    if url.trim().is_empty() {
        return Err(SaveError::Url);
    }
    Ok(())
}

/// Saves a valid profile before its secrets and returns this attempt's outcome.
///
/// A secret failure can leave the profile on disk. Callers keep the dialog open
/// for retry and must not open a connection until both callbacks succeed.
pub fn save_connection<E>(
    name: &str,
    url: &str,
    profile: impl FnOnce() -> Result<(), E>,
    secrets: impl FnOnce() -> Result<(), E>,
) -> Result<(), SaveError<E>> {
    validate_connection(name, url)?;
    profile().map_err(SaveError::Store)?;
    secrets().map_err(SaveError::Secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_fields_do_not_write_and_store_failure_does_not_write_secrets() {
        let result: Result<(), SaveError<()>> =
            save_connection(" ", "jdbc:x", || panic!(), || panic!());
        assert!(matches!(result, Err(SaveError::Name)));
        assert!(matches!(
            save_connection("x", "jdbc:x", || Err("disk"), || panic!()),
            Err(SaveError::Store("disk"))
        ));
    }
    #[test]
    fn a_failed_secret_write_does_not_poison_the_next_attempt() {
        assert!(matches!(
            save_connection("x", "jdbc:x", || Ok(()), || Err("locked")),
            Err(SaveError::Secret("locked"))
        ));
        let result: Result<(), SaveError<()>> =
            save_connection("x", "jdbc:x", || Ok(()), || Ok(()));
        assert!(result.is_ok());
    }
}
