use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Error types for webhook signature operations.
#[derive(Debug)]
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
#[derive(Debug, Clone)]
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
        assert!(verify("test", "secret", "wrong", 1000000, 0).is_err());
    }

    #[test]
    fn test_parse_header() {
        let signed = sign_at("test", "secret", 12345);
        let header = signed.to_header();
        let (sig, ts) = parse_header(&header).unwrap();
        assert_eq!(ts, 12345);
        assert_eq!(sig, signed.signature);
    }
}
