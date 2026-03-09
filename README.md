# rs-webhook-signature

HMAC-SHA256 webhook signing and verification for Rust.

## Installation

```toml
[dependencies]
philiprehberger-webhook-signature = "0.1"
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
use philiprehberger_webhook_signature::{verify, parse_header};

let (sig, ts) = parse_header(&header)?;
verify("payload", "secret", &sig, ts, 300)?; // max age 300 seconds
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

## License

MIT
