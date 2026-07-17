// Native crypto helpers for desktop — Argon2id + AES-256-GCM
//
// These supplement the browser-side Web Crypto API for operations
// that benefit from native performance (Argon2id) or OS keychain access.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rand::RngCore;

/// Derives a master key using Argon2id with OWASP-recommended parameters.
/// Returns the raw 32-byte key.
pub fn derive_master_key(password: &str, salt: &[u8]) -> Result<Vec<u8>, String> {
    let argon2 = Argon2::default();
    let mut key = vec![0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Argon2id failed: {}", e))?;
    Ok(key)
}

/// Encrypts data with AES-256-GCM. Returns (ciphertext, nonce).
pub fn encrypt(plaintext: &[u8], key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("Key error: {}", e))?;
    let mut nonce_bytes = vec![0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("Encrypt failed: {}", e))?;
    Ok((ciphertext, nonce_bytes))
}

/// Decrypts data with AES-256-GCM.
pub fn decrypt(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("Key error: {}", e))?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decrypt failed: {}", e))
}
