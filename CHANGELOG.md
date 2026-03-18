# Changelog

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
