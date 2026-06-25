//! RFC6238 TOTP (SHA1, 30s period, 6 digits). Ported from luban-mcp-server.

use crate::error::{Result, StoreError};
use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// Generate a 6-digit TOTP for the given base32 secret at a specific unix timestamp.
pub fn totp_at(secret_b32: &str, unix_secs: u64) -> Result<String> {
    let key = base32::decode(
        base32::Alphabet::Rfc4648 { padding: false },
        &secret_b32.replace(' ', "").to_uppercase(),
    )
    .ok_or_else(|| StoreError::InvalidSecret("invalid base32".into()))?;
    if key.is_empty() {
        return Err(StoreError::InvalidSecret("empty secret".into()));
    }

    let counter: u64 = unix_secs / 30;
    let msg = counter.to_be_bytes();

    let mut mac = HmacSha1::new_from_slice(&key)
        .map_err(|e| StoreError::InvalidSecret(format!("hmac key: {e}")))?;
    mac.update(&msg);
    let hash = mac.finalize().into_bytes();

    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let bin_code = ((u32::from(hash[offset]) & 0x7f) << 24)
        | ((u32::from(hash[offset + 1]) & 0xff) << 16)
        | ((u32::from(hash[offset + 2]) & 0xff) << 8)
        | (u32::from(hash[offset + 3]) & 0xff);

    Ok(format!("{:06}", bin_code % 1_000_000))
}

/// Generate a TOTP for the current system time.
pub fn totp_now(secret_b32: &str) -> Result<String> {
    totp_at(secret_b32, now_secs())
}

/// Seconds remaining in the current 30s TOTP window.
pub fn time_remaining() -> u64 {
    30 - (now_secs() % 30)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn totp_rfc6238_vector_t59() {
        assert_eq!(totp_at(SECRET_B32, 59).unwrap(), "287082");
    }

    #[test]
    fn totp_rfc6238_vector_t1111111109() {
        assert_eq!(totp_at(SECRET_B32, 1111111109).unwrap(), "081804");
    }

    #[test]
    fn totp_rejects_bad_base32() {
        assert!(totp_at("not valid base32 !!!", 59).is_err());
    }

    #[test]
    fn time_remaining_in_range() {
        let r = time_remaining();
        assert!(r >= 1 && r <= 30);
    }
}
