//! HMAC-SHA256 webhook signing and verification.
//!
//! # Example
//!
//! ```rust
//! use philiprehberger_webhook_signature::sign;
//!
//! let signed = sign("hello world", "my-secret");
//! assert!(!signed.signature.is_empty());
//! ```

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Error types for webhook signature operations.
#[derive(Debug, Clone, PartialEq)]
pub enum SignatureError {
    /// The signature does not match.
    Mismatch,
    /// The signature has expired.
    Expired { age_secs: u64, max_age_secs: u64 },
    /// The header is malformed or missing required fields.
    InvalidHeader(String),
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureError::Mismatch => write!(f, "signature verification failed"),
            SignatureError::Expired { age_secs, max_age_secs } => {
                write!(f, "signature expired: age {}s exceeds max {}s", age_secs, max_age_secs)
            }
            SignatureError::InvalidHeader(msg) => write!(f, "invalid header: {}", msg),
        }
    }
}

impl std::error::Error for SignatureError {}

/// Result of signing a payload.
#[derive(Debug, Clone, PartialEq)]
pub struct SignedPayload {
    pub signature: String,
    pub timestamp: u64,
    pub body: String,
}

impl SignedPayload {
    /// Format as a header value: `t=timestamp,sha256=signature`.
    pub fn to_header(&self) -> String {
        format!("t={},sha256={}", self.timestamp, self.signature)
    }

    /// Get the age of this signed payload as a `Duration`.
    ///
    /// Returns `Duration::ZERO` if the timestamp is in the future.
    pub fn age(&self) -> Duration {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if self.timestamp > now {
            Duration::ZERO
        } else {
            Duration::from_secs(now - self.timestamp)
        }
    }
}

impl fmt::Display for SignedPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "t={},sha256={}", self.timestamp, self.signature)
    }
}

/// Sign a payload with the given secret.
pub fn sign(payload: &str, secret: &str) -> SignedPayload {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    sign_at(payload, secret, timestamp)
}

/// Sign a payload with a specific timestamp.
pub fn sign_at(payload: &str, secret: &str, timestamp: u64) -> SignedPayload {
    let message = format!("{}.{}", timestamp, payload);
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(message.as_bytes());
    let result = mac.finalize();
    let signature = hex::encode(result.into_bytes());

    SignedPayload {
        signature,
        timestamp,
        body: payload.to_string(),
    }
}

/// Verify a webhook signature. Set `max_age_secs` to 0 to disable age checking.
pub fn verify(
    payload: &str,
    secret: &str,
    signature: &str,
    timestamp: u64,
    max_age_secs: u64,
) -> Result<(), SignatureError> {
    if max_age_secs > 0 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let age = now.saturating_sub(timestamp);
        if age > max_age_secs {
            return Err(SignatureError::Expired {
                age_secs: age,
                max_age_secs,
            });
        }
    }

    let expected = sign_at(payload, secret, timestamp);

    let sig_bytes = signature.as_bytes();
    let expected_bytes = expected.signature.as_bytes();

    if sig_bytes.len() != expected_bytes.len() || sig_bytes.ct_eq(expected_bytes).unwrap_u8() != 1 {
        return Err(SignatureError::Mismatch);
    }

    Ok(())
}

/// Parse a webhook signature header in the format `t=timestamp,sha256=signature`.
pub fn parse_header(header: &str) -> Result<(String, u64), SignatureError> {
    let mut timestamp = None;
    let mut signature = None;

    for part in header.split(',') {
        let (key, value) = part.split_once('=').ok_or_else(|| {
            SignatureError::InvalidHeader("malformed header part".to_string())
        })?;

        match key.trim() {
            "t" => {
                timestamp = Some(value.trim().parse::<u64>().map_err(|_| {
                    SignatureError::InvalidHeader("invalid timestamp".to_string())
                })?);
            }
            "sha256" => {
                signature = Some(value.trim().to_string());
            }
            _ => {}
        }
    }

    let ts = timestamp.ok_or_else(|| SignatureError::InvalidHeader("missing timestamp".to_string()))?;
    let sig = signature.ok_or_else(|| SignatureError::InvalidHeader("missing sha256 signature".to_string()))?;

    Ok((sig, ts))
}

/// Verify a webhook signature directly from a header string.
///
/// Combines `parse_header()` and `verify()` into a single call.
pub fn verify_header(
    payload: &str,
    secret: &str,
    header: &str,
    max_age_secs: u64,
) -> Result<(), SignatureError> {
    let (signature, timestamp) = parse_header(header)?;
    verify(payload, secret, &signature, timestamp, max_age_secs)
}

/// Verify a webhook signature against multiple secrets (key rotation support).
///
/// Tries each secret in order and returns `Ok(())` on the first match.
/// Set `max_age_secs` to 0 to disable age checking.
pub fn verify_with_secrets(
    payload: &str,
    secrets: &[&str],
    signature: &str,
    timestamp: u64,
    max_age_secs: u64,
) -> Result<(), SignatureError> {
    if secrets.is_empty() {
        return Err(SignatureError::Mismatch);
    }

    if max_age_secs > 0 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let age = now.saturating_sub(timestamp);
        if age > max_age_secs {
            return Err(SignatureError::Expired {
                age_secs: age,
                max_age_secs,
            });
        }
    }

    let sig_bytes = signature.as_bytes();

    for secret in secrets {
        let expected = sign_at(payload, secret, timestamp);
        let expected_bytes = expected.signature.as_bytes();

        if sig_bytes.len() == expected_bytes.len() && sig_bytes.ct_eq(expected_bytes).unwrap_u8() == 1 {
            return Ok(());
        }
    }

    Err(SignatureError::Mismatch)
}

/// Verify a webhook signature header against multiple secrets (key rotation support).
///
/// Combines `parse_header()` and `verify_with_secrets()` into a single call.
pub fn verify_header_with_secrets(
    payload: &str,
    secrets: &[&str],
    header: &str,
    max_age_secs: u64,
) -> Result<(), SignatureError> {
    let (signature, timestamp) = parse_header(header)?;
    verify_with_secrets(payload, secrets, &signature, timestamp, max_age_secs)
}

/// Verify a webhook signature with clock skew tolerance.
///
/// Like `verify()`, but allows timestamps up to `tolerance_secs` in the future.
/// Set `max_age_secs` to 0 to disable age checking.
pub fn verify_relaxed(
    payload: &str,
    secret: &str,
    signature: &str,
    timestamp: u64,
    max_age_secs: u64,
    tolerance_secs: u64,
) -> Result<(), SignatureError> {
    let expected = sign_at(payload, secret, timestamp);

    let sig_bytes = signature.as_bytes();
    let expected_bytes = expected.signature.as_bytes();

    if sig_bytes.len() != expected_bytes.len() || sig_bytes.ct_eq(expected_bytes).unwrap_u8() != 1 {
        return Err(SignatureError::Mismatch);
    }

    if max_age_secs > 0 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if timestamp > now + tolerance_secs {
            return Err(SignatureError::Expired {
                age_secs: timestamp - now,
                max_age_secs,
            });
        }

        if now > timestamp && (now - timestamp) > max_age_secs {
            return Err(SignatureError::Expired {
                age_secs: now - timestamp,
                max_age_secs,
            });
        }
    }

    Ok(())
}

/// Reusable signer that binds a secret for convenient repeated signing.
#[derive(Debug, Clone)]
pub struct Signer {
    secret: String,
}

impl Signer {
    pub fn new(secret: &str) -> Self {
        Self {
            secret: secret.to_string(),
        }
    }

    /// Sign a payload using the bound secret.
    pub fn sign(&self, payload: &str) -> SignedPayload {
        crate::sign(payload, &self.secret)
    }

    /// Sign a payload with a specific timestamp.
    pub fn sign_at(&self, payload: &str, timestamp: u64) -> SignedPayload {
        crate::sign_at(payload, &self.secret, timestamp)
    }
}

/// Reusable verifier that binds a secret and max age for convenient repeated verification.
#[derive(Debug, Clone)]
pub struct Verifier {
    secret: String,
    secrets: Vec<String>,
    max_age_secs: u64,
}

impl Verifier {
    pub fn new(secret: &str, max_age_secs: u64) -> Self {
        Self {
            secret: secret.to_string(),
            secrets: vec![secret.to_string()],
            max_age_secs,
        }
    }

    /// Create a verifier with multiple secrets for key rotation support.
    pub fn new_with_secrets(secrets: Vec<String>, max_age_secs: u64) -> Self {
        let secret = secrets.first().cloned().unwrap_or_default();
        Self {
            secret,
            secrets,
            max_age_secs,
        }
    }

    /// Verify a signature with the bound secret and max age.
    pub fn verify(
        &self,
        payload: &str,
        signature: &str,
        timestamp: u64,
    ) -> Result<(), SignatureError> {
        crate::verify(payload, &self.secret, signature, timestamp, self.max_age_secs)
    }

    /// Verify a webhook signature directly from a header string.
    pub fn verify_header(&self, payload: &str, header: &str) -> Result<(), SignatureError> {
        crate::verify_header(payload, &self.secret, header, self.max_age_secs)
    }

    /// Verify a signature against all bound secrets.
    pub fn verify_with_secrets(
        &self,
        payload: &str,
        signature: &str,
        timestamp: u64,
    ) -> Result<(), SignatureError> {
        let secret_refs: Vec<&str> = self.secrets.iter().map(|s| s.as_str()).collect();
        crate::verify_with_secrets(payload, &secret_refs, signature, timestamp, self.max_age_secs)
    }

    /// Verify a webhook signature header against all bound secrets.
    pub fn verify_header_with_secrets(&self, payload: &str, header: &str) -> Result<(), SignatureError> {
        let secret_refs: Vec<&str> = self.secrets.iter().map(|s| s.as_str()).collect();
        crate::verify_header_with_secrets(payload, &secret_refs, header, self.max_age_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let signed = sign_at("test payload", "secret", 1000000);
        assert!(verify("test payload", "secret", &signed.signature, 1000000, 0).is_ok());
    }

    #[test]
    fn test_verify_mismatch() {
        let err = verify("test", "secret", "wrong", 1000000, 0).unwrap_err();
        assert_eq!(err, SignatureError::Mismatch);
    }

    #[test]
    fn test_verify_wrong_payload() {
        let signed = sign_at("correct", "secret", 1000000);
        let err = verify("wrong", "secret", &signed.signature, 1000000, 0).unwrap_err();
        assert_eq!(err, SignatureError::Mismatch);
    }

    #[test]
    fn test_verify_wrong_secret() {
        let signed = sign_at("test", "secret1", 1000000);
        let err = verify("test", "secret2", &signed.signature, 1000000, 0).unwrap_err();
        assert_eq!(err, SignatureError::Mismatch);
    }

    #[test]
    fn test_verify_expired() {
        let signed = sign_at("test", "secret", 1000);
        let err = verify("test", "secret", &signed.signature, 1000, 300).unwrap_err();
        match err {
            SignatureError::Expired { max_age_secs, .. } => {
                assert_eq!(max_age_secs, 300);
            }
            _ => panic!("expected Expired error"),
        }
    }

    #[test]
    fn test_verify_age_check_disabled() {
        let signed = sign_at("test", "secret", 1000);
        assert!(verify("test", "secret", &signed.signature, 1000, 0).is_ok());
    }

    #[test]
    fn test_parse_header() {
        let signed = sign_at("test", "secret", 12345);
        let header = signed.to_header();
        let (sig, ts) = parse_header(&header).unwrap();
        assert_eq!(ts, 12345);
        assert_eq!(sig, signed.signature);
    }

    #[test]
    fn test_parse_header_missing_timestamp() {
        let err = parse_header("sha256=abc123").unwrap_err();
        assert_eq!(
            err,
            SignatureError::InvalidHeader("missing timestamp".to_string())
        );
    }

    #[test]
    fn test_parse_header_missing_signature() {
        let err = parse_header("t=12345").unwrap_err();
        assert_eq!(
            err,
            SignatureError::InvalidHeader("missing sha256 signature".to_string())
        );
    }

    #[test]
    fn test_parse_header_malformed() {
        let err = parse_header("not-a-valid-header").unwrap_err();
        assert_eq!(
            err,
            SignatureError::InvalidHeader("malformed header part".to_string())
        );
    }

    #[test]
    fn test_parse_header_invalid_timestamp() {
        let err = parse_header("t=notanumber,sha256=abc").unwrap_err();
        assert_eq!(
            err,
            SignatureError::InvalidHeader("invalid timestamp".to_string())
        );
    }

    #[test]
    fn test_verify_header() {
        let signed = sign_at("test payload", "secret", 1000000);
        let header = signed.to_header();
        assert!(verify_header("test payload", "secret", &header, 0).is_ok());
    }

    #[test]
    fn test_verify_header_mismatch() {
        let signed = sign_at("test", "secret", 1000000);
        let header = signed.to_header();
        let err = verify_header("wrong payload", "secret", &header, 0).unwrap_err();
        assert_eq!(err, SignatureError::Mismatch);
    }

    #[test]
    fn test_verify_header_invalid() {
        let err = verify_header("test", "secret", "garbage", 0).unwrap_err();
        assert!(matches!(err, SignatureError::InvalidHeader(_)));
    }

    #[test]
    fn test_signed_payload_to_header_format() {
        let signed = sign_at("test", "secret", 99999);
        let header = signed.to_header();
        assert!(header.starts_with("t=99999,sha256="));
    }

    #[test]
    fn test_empty_payload() {
        let signed = sign_at("", "secret", 1000000);
        assert!(verify("", "secret", &signed.signature, 1000000, 0).is_ok());
    }

    #[test]
    fn test_empty_secret() {
        let signed = sign_at("test", "", 1000000);
        assert!(verify("test", "", &signed.signature, 1000000, 0).is_ok());
    }

    #[test]
    fn test_signature_error_display() {
        assert_eq!(
            format!("{}", SignatureError::Mismatch),
            "signature verification failed"
        );
        assert!(format!(
            "{}",
            SignatureError::Expired {
                age_secs: 500,
                max_age_secs: 300
            }
        )
        .contains("500s"));
        assert!(format!("{}", SignatureError::InvalidHeader("test".into())).contains("test"));
    }

    #[test]
    fn test_signed_payload_partial_eq() {
        let a = sign_at("test", "secret", 12345);
        let b = sign_at("test", "secret", 12345);
        assert_eq!(a, b);
        let c = sign_at("other", "secret", 12345);
        assert_ne!(a, c);
    }

    #[test]
    fn test_signed_payload_display() {
        let signed = sign_at("test", "secret", 99999);
        let display = format!("{}", signed);
        assert!(display.starts_with("t=99999,sha256="));
        assert_eq!(display, signed.to_header());
    }

    #[test]
    fn test_signature_error_clone() {
        let err = SignatureError::Expired { age_secs: 500, max_age_secs: 300 };
        let err2 = err.clone();
        assert_eq!(err, err2);
    }

    #[test]
    fn test_signer() {
        let signer = Signer::new("secret");
        let signed = signer.sign_at("test payload", 1000000);
        assert!(verify("test payload", "secret", &signed.signature, 1000000, 0).is_ok());
    }

    #[test]
    fn test_signer_sign() {
        let signer = Signer::new("secret");
        let signed = signer.sign("test payload");
        assert!(verify_header("test payload", "secret", &signed.to_header(), 300).is_ok());
    }

    #[test]
    fn test_verifier() {
        let verifier = Verifier::new("secret", 0);
        let signed = sign_at("test payload", "secret", 1000000);
        assert!(verifier.verify("test payload", &signed.signature, 1000000).is_ok());
    }

    #[test]
    fn test_verifier_header() {
        let verifier = Verifier::new("secret", 0);
        let signed = sign_at("test payload", "secret", 1000000);
        assert!(verifier.verify_header("test payload", &signed.to_header()).is_ok());
    }

    #[test]
    fn test_verifier_rejects_bad_signature() {
        let verifier = Verifier::new("secret", 0);
        let err = verifier.verify("test", "wrong", 1000000).unwrap_err();
        assert_eq!(err, SignatureError::Mismatch);
    }

    #[test]
    fn test_signer_and_verifier_roundtrip() {
        let signer = Signer::new("my-secret");
        let verifier = Verifier::new("my-secret", 300);
        let signed = signer.sign("webhook body");
        assert!(verifier.verify_header("webhook body", &signed.to_header()).is_ok());
    }

    #[test]
    fn test_signature_error_equality() {
        assert_eq!(SignatureError::Mismatch, SignatureError::Mismatch);
        assert_ne!(SignatureError::Mismatch, SignatureError::InvalidHeader("x".into()));
        assert_eq!(
            SignatureError::Expired { age_secs: 10, max_age_secs: 5 },
            SignatureError::Expired { age_secs: 10, max_age_secs: 5 }
        );
    }

    #[test]
    fn test_verify_with_secrets_matches_second_secret() {
        let payload = "test";
        let secret1 = "old-secret";
        let secret2 = "new-secret";
        let signed = sign_at(payload, secret2, 1000000);
        assert!(verify_with_secrets(payload, &[secret1, secret2], &signed.signature, signed.timestamp, 0).is_ok());
    }

    #[test]
    fn test_verify_with_secrets_no_match() {
        let signed = sign_at("test", "real-secret", 1000000);
        assert_eq!(
            verify_with_secrets("test", &["wrong1", "wrong2"], &signed.signature, signed.timestamp, 0),
            Err(SignatureError::Mismatch)
        );
    }

    #[test]
    fn test_verify_with_secrets_empty() {
        let signed = sign_at("test", "secret", 1000000);
        assert_eq!(
            verify_with_secrets("test", &[], &signed.signature, signed.timestamp, 0),
            Err(SignatureError::Mismatch)
        );
    }

    #[test]
    fn test_verify_header_with_secrets() {
        let secret = "my-secret";
        let signed = sign_at("payload", secret, 1000000);
        let header = signed.to_header();
        assert!(verify_header_with_secrets("payload", &["wrong", secret], &header, 0).is_ok());
    }

    #[test]
    fn test_verifier_with_secrets() {
        let secret = "current";
        let signed = sign_at("data", secret, 1000000);
        let v = Verifier::new_with_secrets(vec!["old".into(), secret.into()], 0);
        assert!(v.verify_with_secrets("data", &signed.signature, signed.timestamp).is_ok());
    }

    #[test]
    fn test_verifier_header_with_secrets() {
        let secret = "current";
        let signed = sign_at("data", secret, 1000000);
        let v = Verifier::new_with_secrets(vec!["old".into(), secret.into()], 0);
        assert!(v.verify_header_with_secrets("data", &signed.to_header()).is_ok());
    }

    #[test]
    fn test_signed_payload_age() {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let signed = sign_at("test", "secret", now - 10);
        let age = signed.age();
        assert!(age.as_secs() >= 9 && age.as_secs() <= 12);
    }

    #[test]
    fn test_signed_payload_age_future_timestamp() {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let signed = sign_at("test", "secret", now + 100);
        assert_eq!(signed.age(), Duration::ZERO);
    }

    #[test]
    fn test_verify_relaxed_allows_clock_skew() {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        // Timestamp 5 seconds in the future (simulating clock skew)
        let signed = sign_at("test", "secret", now + 5);
        // Normal verify with age check would consider this suspicious
        // verify_relaxed with 10s tolerance should accept it
        assert!(verify_relaxed("test", "secret", &signed.signature, signed.timestamp, 300, 10).is_ok());
    }

    #[test]
    fn test_verify_relaxed_rejects_beyond_tolerance() {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        // Timestamp 20 seconds in the future
        let signed = sign_at("test", "secret", now + 20);
        // With 10s tolerance, 20s future should be rejected
        assert!(verify_relaxed("test", "secret", &signed.signature, signed.timestamp, 300, 10).is_err());
    }

    #[test]
    fn test_verify_relaxed_age_check_disabled() {
        let signed = sign_at("test", "secret", 1000);
        // max_age_secs=0 disables check, so very old timestamp is fine
        assert!(verify_relaxed("test", "secret", &signed.signature, signed.timestamp, 0, 10).is_ok());
    }
}
