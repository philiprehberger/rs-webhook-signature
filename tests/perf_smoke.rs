//! Performance smoke test: sign and verify a 1 MiB payload under 500ms.

use std::time::{Duration, Instant};

use philiprehberger_webhook_signature::{sign, verify};

#[test]
fn sign_and_verify_one_mib_under_500ms() {
    let payload = "a".repeat(1024 * 1024);
    let secret = "perf-smoke-secret";

    let start = Instant::now();
    let signed = sign(&payload, secret);
    verify(&payload, secret, &signed.signature, signed.timestamp, 0)
        .expect("verification should succeed");
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(500),
        "sign + verify of 1 MiB payload took {:?}, expected < 500ms",
        elapsed
    );
}
