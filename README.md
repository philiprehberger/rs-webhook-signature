# rs-webhook-signature

[![CI](https://github.com/philiprehberger/rs-webhook-signature/actions/workflows/ci.yml/badge.svg)](https://github.com/philiprehberger/rs-webhook-signature/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/philiprehberger-webhook-signature.svg)](https://crates.io/crates/philiprehberger-webhook-signature)
[![License](https://img.shields.io/github/license/philiprehberger/rs-webhook-signature)](LICENSE)

HMAC-SHA256 webhook signing and verification for Rust.

## Installation

```toml
[dependencies]
philiprehberger-webhook-signature = "0.3.4"
```

## Usage

### Sign a Payload

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

## License

MIT
