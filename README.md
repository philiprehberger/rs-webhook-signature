# rs-webhook-signature

[![CI](https://github.com/philiprehberger/rs-webhook-signature/actions/workflows/ci.yml/badge.svg)](https://github.com/philiprehberger/rs-webhook-signature/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/philiprehberger-webhook-signature.svg)](https://crates.io/crates/philiprehberger-webhook-signature)
[![Last updated](https://img.shields.io/github/last-commit/philiprehberger/rs-webhook-signature)](https://github.com/philiprehberger/rs-webhook-signature/commits/main)

HMAC-SHA256 webhook signing and verification for Rust

## Installation

```toml
[dependencies]
philiprehberger-webhook-signature = "0.4.0"
```

## Usage

```rust
use philiprehberger_webhook_signature::sign;

let signed = sign("payload", "secret");
println!("{}", signed.to_header()); // "t=...,sha256=..."
```

### Verify a Signature

```rust
use philiprehberger_webhook_signature::verify_header;

verify_header("payload", "secret", &header, 300)?; // max age 300 seconds
```

Or with manual parsing:

```rust
use philiprehberger_webhook_signature::{verify, parse_header};

let (sig, ts) = parse_header(&header)?;
verify("payload", "secret", &sig, ts, 300)?;
```

### Error Handling

```rust
use philiprehberger_webhook_signature::SignatureError;

match verify(payload, secret, &sig, ts, 300) {
    Ok(()) => println!("Valid!"),
    Err(SignatureError::Mismatch) => eprintln!("Bad signature"),
    Err(SignatureError::Expired { age_secs, max_age_secs }) => {
        eprintln!("Expired: {}s > {}s", age_secs, max_age_secs);
    }
    Err(e) => eprintln!("Error: {}", e),
}
```

### Disable Age Check

```rust
verify(payload, secret, &sig, ts, 0)?; // no expiry check
```

### Reusable Signer and Verifier

```rust
use philiprehberger_webhook_signature::{Signer, Verifier};

let signer = Signer::new("my-secret");
let signed = signer.sign("webhook body");
println!("{}", signed); // "t=...,sha256=..."

let verifier = Verifier::new("my-secret", 300);
verifier.verify_header("webhook body", &signed.to_header())?;
```

### Key Rotation

Verify against multiple secrets during key rotation:

```rust
use philiprehberger_webhook_signature::{sign, verify_with_secrets};

let signed = sign("payload", "new-secret");

// Accepts signatures from either the old or new secret
let result = verify_with_secrets(
    "payload",
    &["old-secret", "new-secret"],
    &signed.signature,
    signed.timestamp,
    300,
);
assert!(result.is_ok());
```

### Signature Age

Check how old a signed payload is:

```rust
use philiprehberger_webhook_signature::sign;

let signed = sign("payload", "secret");
println!("Signature age: {:?}", signed.age());
```

### Clock Skew Tolerance

Allow a tolerance window for clock drift between signer and verifier:

```rust
use philiprehberger_webhook_signature::{sign, verify_relaxed};

let signed = sign("payload", "secret");
let result = verify_relaxed(
    "payload",
    "secret",
    &signed.signature,
    signed.timestamp,
    300,  // max_age_secs
    10,   // tolerance_secs
);
assert!(result.is_ok());
```

## API

| Function / Type | Description |
|-----------------|-------------|
| `sign(payload, secret)` | Sign a payload, returns `SignedPayload` |
| `sign_at(payload, secret, timestamp)` | Sign with a specific timestamp |
| `verify(payload, secret, signature, timestamp, max_age_secs)` | Verify a signature (set max_age to 0 to skip age check) |
| `parse_header(header)` | Parse a `t=...,sha256=...` header into signature and timestamp |
| `verify_header(payload, secret, header, max_age_secs)` | Parse and verify a header in one call |
| `Signer::new(secret)` | Create a reusable signer bound to a secret |
| `signer.sign(payload)` | Sign a payload using the bound secret |
| `signer.sign_at(payload, timestamp)` | Sign with a specific timestamp |
| `Verifier::new(secret, max_age_secs)` | Create a reusable verifier bound to a secret and max age |
| `verifier.verify(payload, signature, timestamp)` | Verify a signature |
| `verifier.verify_header(payload, header)` | Parse and verify a header |
| `verify_with_secrets(payload, secrets, sig, ts, max_age)` | Verify against multiple secrets (key rotation) |
| `verify_header_with_secrets(payload, secrets, header, max_age)` | Verify header against multiple secrets |
| `verify_relaxed(payload, secret, sig, ts, max_age, tolerance)` | Verify with clock skew tolerance |
| `Verifier::new_with_secrets(secrets, max_age)` | Create a reusable multi-secret verifier |
| `signed.age()` | Get the age of a signed payload as Duration |
| `SignedPayload` | Struct with `signature`, `timestamp`, `body` fields and `to_header()` |
| `SignatureError` | Enum: `Mismatch`, `Expired`, `InvalidHeader` |

## Development

```bash
cargo test
cargo clippy -- -D warnings
```

## Support

If you find this project useful:

⭐ [Star the repo](https://github.com/philiprehberger/rs-webhook-signature)

🐛 [Report issues](https://github.com/philiprehberger/rs-webhook-signature/issues?q=is%3Aissue+is%3Aopen+label%3Abug)

💡 [Suggest features](https://github.com/philiprehberger/rs-webhook-signature/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement)

❤️ [Sponsor development](https://github.com/sponsors/philiprehberger)

🌐 [All Open Source Projects](https://philiprehberger.com/open-source-packages)

💻 [GitHub Profile](https://github.com/philiprehberger)

🔗 [LinkedIn Profile](https://www.linkedin.com/in/philiprehberger)

## License

[MIT](LICENSE)
