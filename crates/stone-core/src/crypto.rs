//! End-to-end encryption.
//!
//! - A random 256-bit vault key encrypts everything (XChaCha20-Poly1305).
//! - The vault key is wrapped by a key derived from the owner's password
//!   with Argon2id; changing the password only rewraps.
//! - Setup prints a recovery key — a second wrap of the vault key.
//! - Path ids are keyed BLAKE3 hashes of normalized paths, and blob ids are
//!   keyed BLAKE3 hashes of plaintext, so the server sees only ciphertext and
//!   cannot confirm guesses about content.

use crate::error::{Result, StoneError};
use argon2::Argon2;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use zeroize::Zeroizing;

pub const VAULT_KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;

/// Argon2id parameters (OWASP-recommended baseline).
const ARGON_M_KIB: u32 = 64 * 1024; // 64 MiB
const ARGON_T: u32 = 3;
const ARGON_P: u32 = 1;

const KDF_PATH_ID: &[u8] = b"stone/path-id";
const KDF_BLOB_ID: &[u8] = b"stone/blob-id";
const KDF_VAULT_ID: &[u8] = b"stone/vault-id";

#[derive(Clone)]
pub struct VaultKey {
    pub bytes: Zeroizing<[u8; VAULT_KEY_LEN]>,
}

impl VaultKey {
    pub fn generate() -> Self {
        let mut bytes = [0u8; VAULT_KEY_LEN];
        rand::rng().fill_bytes(&mut bytes);
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    pub fn from_bytes(b: [u8; VAULT_KEY_LEN]) -> Self {
        Self {
            bytes: Zeroizing::new(b),
        }
    }

    pub fn from_b64(s: &str) -> Result<Self> {
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s.trim())
            .map_err(|e| StoneError::Crypto(format!("bad key b64: {e}")))?;
        let arr: [u8; VAULT_KEY_LEN] = raw
            .try_into()
            .map_err(|_| StoneError::Crypto("vault key must be 32 bytes".into()))?;
        Ok(Self::from_bytes(arr))
    }

    pub fn to_b64(&self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.bytes.as_slice())
    }

    /// Opaque vault id for the server: keyed hash of a fixed marker, so the
    /// server can't map it to a vault name.
    pub fn vault_id(&self) -> String {
        keyed_hex(&self.bytes, KDF_VAULT_ID, b"vault")
    }

    /// Path id: keyed BLAKE3 of the normalized path.
    pub fn path_id(&self, normalized_rel: &str) -> String {
        let k = self.derive(KDF_PATH_ID);
        let mut h = blake3::Hasher::new_keyed(&k);
        h.update(normalized_rel.as_bytes());
        hex::encode(&h.finalize().as_bytes()[..16])
    }

    /// Blob id: keyed BLAKE3 of the PLAINTEXT chunk (content-addressed but
    /// opaque — the server can't confirm guesses about content).
    pub fn blob_id(&self, plaintext_chunk: &[u8]) -> String {
        let k = self.derive(KDF_BLOB_ID);
        let mut h = blake3::Hasher::new_keyed(&k);
        h.update(plaintext_chunk);
        hex::encode(&h.finalize().as_bytes()[..16])
    }

    /// Encrypt one blob/chunk; wire format = nonce(24) || ciphertext.
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let cipher = XChaCha20Poly1305::new(self.bytes.as_slice().into());
        let mut nonce = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(XNonce::from_slice(&nonce), plaintext)
            .expect("encryption failed");
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    /// Decrypt nonce||ciphertext.
    pub fn decrypt(&self, blob: &[u8]) -> Result<Vec<u8>> {
        if blob.len() < NONCE_LEN + 16 {
            return Err(StoneError::Crypto("ciphertext too short".into()));
        }
        let cipher = XChaCha20Poly1305::new(self.bytes.as_slice().into());
        cipher
            .decrypt(XNonce::from_slice(&blob[..NONCE_LEN]), &blob[NONCE_LEN..])
            .map_err(|_| StoneError::Crypto("decryption failed".into()))
    }

    fn derive(&self, context: &[u8]) -> [u8; 32] {
        // BLAKE3 keyed derive: key = KDF(context, vault_key)
        let mut h = blake3::Hasher::new_derive_key(std::str::from_utf8(context).unwrap_or("stone"));
        h.update(self.bytes.as_slice());
        *h.finalize().as_bytes()
    }

    /// Wrap the vault key under a key derived from `password` via Argon2id.
    /// Returns (wrapped_b64, salt_b64).
    pub fn wrap(&self, password: &str) -> Result<(String, String)> {
        let mut salt = [0u8; 16];
        rand::rng().fill_bytes(&mut salt);
        self.wrap_with_salt(password, &salt)
    }

    pub fn wrap_with_salt(&self, password: &str, salt: &[u8; 16]) -> Result<(String, String)> {
        let kek = derive_kek(password, salt)?;
        let cipher = XChaCha20Poly1305::new((&kek).into());
        let mut nonce = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(XNonce::from_slice(&nonce), self.bytes.as_slice())
            .map_err(|_| StoneError::Crypto("wrap failed".into()))?;
        let mut wrapped = Vec::new();
        wrapped.extend_from_slice(&nonce);
        wrapped.extend_from_slice(&ct);
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        Ok((b64.encode(wrapped), b64.encode(salt)))
    }

    /// Unwrap a wrapped vault key.
    pub fn unwrap(wrapped_b64: &str, salt_b64: &str, password: &str) -> Result<Self> {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let wrapped = b64
            .decode(wrapped_b64)
            .map_err(|e| StoneError::Crypto(format!("bad wrapped key: {e}")))?;
        let salt_raw = b64
            .decode(salt_b64)
            .map_err(|e| StoneError::Crypto(format!("bad salt: {e}")))?;
        let salt: [u8; 16] = salt_raw
            .try_into()
            .map_err(|_| StoneError::Crypto("bad salt length".into()))?;
        let kek = derive_kek(password, &salt)?;
        if wrapped.len() < NONCE_LEN + 16 {
            return Err(StoneError::Crypto("wrapped key too short".into()));
        }
        let cipher = XChaCha20Poly1305::new((&kek).into());
        let pt = cipher
            .decrypt(XNonce::from_slice(&wrapped[..NONCE_LEN]), &wrapped[NONCE_LEN..])
            .map_err(|_| StoneError::Crypto("wrong password or corrupted key".into()))?;
        let arr: [u8; VAULT_KEY_LEN] = pt
            .try_into()
            .map_err(|_| StoneError::Crypto("unwrapped key has wrong length".into()))?;
        Ok(Self::from_bytes(arr))
    }

    /// Recovery key: 32 random bytes shown once to the owner; a copy of the
    /// vault key is wrapped with it and stored alongside the password wrap.
    pub fn generate_recovery_key() -> (String, [u8; 32]) {
        let mut rk = [0u8; 32];
        rand::rng().fill_bytes(&mut rk);
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rk);
        (encoded, rk)
    }
}

fn derive_kek(password: &str, salt: &[u8; 16]) -> Result<[u8; 32]> {
    let params = argon2::Params::new(ARGON_M_KIB, ARGON_T, ARGON_P, Some(32))
        .map_err(|e| StoneError::Crypto(format!("argon2 params: {e}")))?;
    let a2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut kek = [0u8; 32];
    a2.hash_password_into(password.as_bytes(), salt, &mut kek)
        .map_err(|e| StoneError::Crypto(format!("argon2: {e}")))?;
    Ok(kek)
}

fn keyed_hex(key: &[u8; 32], context: &[u8], data: &[u8]) -> String {
    let mut h = blake3::Hasher::new_derive_key(std::str::from_utf8(context).unwrap_or("stone"));
    h.update(key);
    h.update(data);
    hex::encode(&h.finalize().as_bytes()[..16])
}

/// Hash a device token for server-side verification (server stores only
/// the hash, not the token itself).
pub fn token_hash(token: &str) -> String {
    let h = blake3::hash(token.as_bytes());
    hex::encode(h.as_bytes())
}

/// Generate a device bearer token: `stn_dev_<48 url-safe chars>`.
pub fn new_device_token() -> String {
    let mut b = [0u8; 36];
    rand::rng().fill_bytes(&mut b);
    format!(
        "stn_dev_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
    )
}
