# Contributing

## Development setup

You will need:

- Rust stable toolchain (edition 2021)
- `wasm32-unknown-unknown` target: `rustup target add wasm32-unknown-unknown`
- Wrangler CLI for local development and deployment
- `cargo-fuzz` for running fuzz targets

Build and test commands:

```bash
# Compile for the Cloudflare Workers target
cargo build --target wasm32-unknown-unknown --locked

# Run unit and integration tests
cargo test --all-features --locked

# Lint
cargo clippy --all-features -- -D warnings

# Run fuzz targets (requires cargo-fuzz)
cargo fuzz run fuzz_hmac_verification
```

## Code standards

All code must compile with `#![forbid(unsafe_code)]`. No `unwrap()` or `expect()` in library code; use proper error handling.

All comparisons of secret material (HMAC tags, API keys, tokens, signatures, auth hashes, challenges, nonces) must use `subtle::ConstantTimeEq::ct_eq()` or `hmac::Mac::verify_slice()`. Hand-rolled byte-by-byte loops are prohibited.

Use Australian English in all prose: organisation, authorised, behaviour, colour, centre, programme. Never use em dashes. Never list exactly three items in a row; use two, four, or five instead.

## Testing approach

Unit tests live alongside production code in `#[cfg(test)] mod tests` blocks. Integration tests live in `tests/`. Fuzz targets live in `fuzz/fuzz_targets/`.

Fuzz targets must call production functions where possible rather than reimplementing logic. When a production function is not `pub`, the fuzz copy must match the production implementation exactly, with a comment citing the source file and line range.

Property-based tests use `proptest` and are gated behind `#[cfg(not(target_arch = "wasm32"))]` since proptest does not compile to WASM.

## PR process

Open a pull request against `main`. The PR template includes a checklist; complete all items before requesting review. Every PR must pass CI (clippy, tests, WASM build) before merge.

Keep commits focused. One logical change per commit where practical.
