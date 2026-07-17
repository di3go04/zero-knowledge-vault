// OS-level keychain integration for the desktop app.
//
// On macOS: Keychain Services (via Security framework)
// On Windows: Credential Manager (via winapi)
// On Linux: Secret Service (via libsecret)

// Placeholder: In production, use the `keyring` crate:
//   keyring = "3"
//
// Usage:
//   let entry = keyring::Entry::new("zk-vault", &user_id)?;
//   entry.set_password(&session_token)?;
//   let token = entry.get_password()?;
//   entry.delete_credential()?;

pub fn store_session_token(_user_id: &str, _token: &str) -> Result<(), String> {
    // TODO: Implement with `keyring` crate
    Ok(())
}

pub fn get_session_token(_user_id: &str) -> Result<Option<String>, String> {
    // TODO: Implement with `keyring` crate
    Ok(None)
}

pub fn delete_session_token(_user_id: &str) -> Result<(), String> {
    // TODO: Implement with `keyring` crate
    Ok(())
}
