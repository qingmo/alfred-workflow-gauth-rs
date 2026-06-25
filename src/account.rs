//! Account model. A backend yields `SecretMaterial` per account; codes resolve here
//! so the TOTP path is backend-independent.

use crate::error::Result;
use crate::totp;

/// What a store hands back for one account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretMaterial {
    /// base32 secret -> core computes the TOTP.
    Secret(String),
    /// already-generated 6-digit code (e.g. MacPass `{TOTP}` placeholder).
    Code(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    pub material: SecretMaterial,
}

impl Account {
    /// Resolve the current 6-digit code for this account.
    pub fn code(&self) -> Result<String> {
        match &self.material {
            SecretMaterial::Code(c) => Ok(c.clone()),
            SecretMaterial::Secret(s) => totp::totp_now(s),
        }
    }
}

/// Classify a stored password value: a bare 6-digit string is a live `Code`,
/// anything else is treated as a base32 `Secret`.
pub fn detect_material(value: &str) -> SecretMaterial {
    let v = value.trim();
    if v.len() == 6 && v.bytes().all(|b| b.is_ascii_digit()) {
        SecretMaterial::Code(v.to_string())
    } else {
        SecretMaterial::Secret(v.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_code_for_six_digits() {
        assert_eq!(detect_material("123456"), SecretMaterial::Code("123456".into()));
    }

    #[test]
    fn detects_secret_for_base32() {
        assert_eq!(
            detect_material("GEZDGNBVGY3TQOJQ"),
            SecretMaterial::Secret("GEZDGNBVGY3TQOJQ".into())
        );
    }

    #[test]
    fn five_or_seven_digits_is_secret() {
        assert!(matches!(detect_material("12345"), SecretMaterial::Secret(_)));
        assert!(matches!(detect_material("1234567"), SecretMaterial::Secret(_)));
    }

    #[test]
    fn code_account_returns_code_verbatim() {
        let a = Account { name: "x".into(), material: SecretMaterial::Code("000111".into()) };
        assert_eq!(a.code().unwrap(), "000111");
    }

    #[test]
    fn secret_account_computes_totp() {
        let a = Account {
            name: "x".into(),
            material: SecretMaterial::Secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into()),
        };
        let code = a.code().unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.bytes().all(|b| b.is_ascii_digit()));
    }
}
