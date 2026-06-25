//! AES-256-CBC + base64 primitives for the KeePassHTTP protocol.
//! Ported from luban-mcp-server; error type adapted to crate StoreError.

use crate::error::{Result, StoreError};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rand::RngCore;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

pub fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn unb64(s: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(s)
        .map_err(|e| StoreError::Parse(format!("base64 decode: {e}")))
}

fn aes_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let enc = Aes256CbcEnc::new_from_slices(key, iv)
        .map_err(|e| StoreError::Request(format!("aes key/iv length: {e}")))?;
    Ok(enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
}

fn aes_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let dec = Aes256CbcDec::new_from_slices(key, iv)
        .map_err(|e| StoreError::Request(format!("aes key/iv length: {e}")))?;
    dec.decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|e| StoreError::Parse(format!("aes decrypt/unpad: {e}")))
}

/// Encrypt `value` under the association key with `nonce_b64` as the IV; returns base64.
pub fn encrypt_value(key_b64: &str, nonce_b64: &str, value: &str) -> Result<String> {
    let key = unb64(key_b64)?;
    let iv = unb64(nonce_b64)?;
    Ok(b64(&aes_encrypt(&key, &iv, value.as_bytes())?))
}

/// Decrypt a base64 ciphertext field under the association key with `nonce_b64` as the IV.
pub fn decrypt_value(key_b64: &str, nonce_b64: &str, enc_b64: &str) -> Result<String> {
    let key = unb64(key_b64)?;
    let iv = unb64(nonce_b64)?;
    let pt = aes_decrypt(&key, &iv, &unb64(enc_b64)?)?;
    String::from_utf8(pt).map_err(|e| StoreError::Parse(format!("utf8: {e}")))
}

/// Verifier = base64(encrypt(plaintext = the nonce base64 string, key, iv = nonce bytes)).
pub fn make_verifier(key_b64: &str, nonce_b64: &str) -> Result<String> {
    encrypt_value(key_b64, nonce_b64, nonce_b64)
}

/// True if `verifier_b64` decrypts (under key + nonce) back to the nonce string.
pub fn verify(key_b64: &str, nonce_b64: &str, verifier_b64: &str) -> bool {
    matches!(decrypt_value(key_b64, nonce_b64, verifier_b64), Ok(v) if v == nonce_b64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_key() -> String { b64(&[7u8; 32]) }
    fn fixed_nonce() -> String { b64(&[3u8; 16]) }

    #[test]
    fn value_round_trips() {
        let (k, n) = (fixed_key(), fixed_nonce());
        let enc = encrypt_value(&k, &n, "hello world").unwrap();
        assert_ne!(enc, "hello world");
        assert_eq!(decrypt_value(&k, &n, &enc).unwrap(), "hello world");
    }

    #[test]
    fn verifier_decrypts_to_nonce() {
        let (k, n) = (fixed_key(), fixed_nonce());
        let v = make_verifier(&k, &n).unwrap();
        assert_eq!(decrypt_value(&k, &n, &v).unwrap(), n);
        assert!(verify(&k, &n, &v));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let n = fixed_nonce();
        let v = make_verifier(&fixed_key(), &n).unwrap();
        let other_key = b64(&[9u8; 32]);
        assert!(!verify(&other_key, &n, &v));
    }

    #[test]
    fn random_bytes_has_requested_len() {
        assert_eq!(random_bytes(16).len(), 16);
        assert_eq!(random_bytes(32).len(), 32);
    }
}
