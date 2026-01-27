# Changelog

## 0.5.0 (2026-04-06)

- Upgrade `hmac` from 0.12 to 0.13
- Upgrade `sha2` from 0.10 to 0.11

## 0.4.0 (2026-04-06)

- Add `verify_with_secrets()` and `verify_header_with_secrets()` for multi-secret key rotation support
- Add `Verifier::new_with_secrets()` for reusable multi-secret verification
- Add `SignedPayload::age()` convenience method for checking signature age
- Add `verify_relaxed()` for verification with clock skew tolerance

## 0.3.9 (2026-03-31)

- Standardize README to 3-badge format with emoji Support section
- Update CI checkout action to v5 for Node.js 24 compatibility

## 0.3.8 (2026-03-27)

- Add GitHub issue templates, PR template, and dependabot configuration
- Update README badges and add Support section

## 0.3.7 (2026-03-22)

- Fix README compliance

## 0.3.6 (2026-03-20)

- Add crate-level doc comment with usage example

## 0.3.5 (2026-03-17)

- Add readme, rust-version, documentation to Cargo.toml
- Add Development section to README

## 0.3.4 (2026-03-16)

- Update install snippet to use full version

## 0.3.3 (2026-03-16)

- Add README badges
- Synchronize version across Cargo.toml, README, and CHANGELOG

## 0.3.0 (2026-03-13)

- Add `Signer` struct — binds a secret for convenient repeated signing
- Add `Verifier` struct — binds a secret and max age for convenient repeated verification
- Add `Clone` derive for `SignatureError`
- Add `PartialEq` derive for `SignedPayload`
- Add `Display` impl for `SignedPayload` — equivalent to `to_header()`

## 0.2.0 (2026-03-12)

- Add `verify_header()` convenience function that combines parsing and verification
- Add `PartialEq` derive for `SignatureError` for easier testing
- Expand test suite with coverage for expired signatures, invalid headers, edge cases

## 0.1.0 (2026-03-09)

- Initial release
