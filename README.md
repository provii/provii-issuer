# Issuer API

Rust Cloudflare Worker that handles credential issuance for the Provii protocol. Compiled to WebAssembly and deployed to Cloudflare's edge network.

## Source layout

| Path | Purpose |
| ---- | ------- |
| `src/lib.rs` | Worker entrypoint (`#[event(fetch)]`), security headers, CSP |
| `src/routes.rs` | HTTP route handlers for public API endpoints |
| `src/routes_sandbox_cred.rs` | Sandbox credential mint (`/v1/register-test-issuer`) |
| `src/session.rs` | Session orchestration and authentication helpers |
| `src/session_security.rs` | Session encryption, binding, secure ID generation |
| `src/storage.rs` | Typed wrappers around Cloudflare KV namespaces |
| `src/security/` | HMAC verification, header parsing, prefix rejection |
| `src/crypto.rs` | RedJubjub signing (KeyManager, RjSigner) |
| `src/kek.rs` | Key encryption key management (AES-GCM envelope) |
| `src/key_rotation.rs` | Signing key rotation lifecycle |
| `src/rate_limiting.rs` | Per-actor rate limiting via KV counters |
| `src/types.rs` | Shared request/response DTOs and validation |
| `src/validation.rs` | Schema URL validation, input normalisation |
| `src/error.rs` | `ApiError` enum and `Result` type alias |
| `src/audit.rs` | Structured audit logging via provii-audit |
| `src/logging.rs` | Console logging helpers with structured fields |
| `src/analytics.rs` | Structured event emission to Analytics Engine |
| `src/cors.rs` | Origin allowlist with wildcard subdomain support |
| `src/fetch_metadata.rs` | Sec-Fetch-* header validation |
| `src/ssrf_protection.rs` | SSRF guards for outbound requests |
| `src/hash.rs` | Privacy hashing utilities |
| `src/health.rs` | Health check and detailed subsystem probes |
| `src/openapi.rs` | OpenAPI 3.1 specification generator |
| `src/secret_cache.rs` | Per-isolate Secrets Store caching with TTL |
| `src/secret_fingerprint.rs` | 6-char public-safe secret fingerprints |
| `src/internal_admin.rs` | Rotation-drill admin endpoints |
| `src/internal_version.rs` | Internal version endpoint for service bindings |
| `src/bindings.rs` | KV namespace binding constants |
| `src/resource_lock.rs` | ResourceLockDO client helpers |
| `src/durable_objects/` | Durable Objects (NonceDO, ResourceLockDO) |
| `tools/` | Operational CLI binaries (officer admin, keygen, key rotation) |
| `wrangler.toml` | Deployment configuration (routes, KV bindings, Secrets Store) |

## Building

The worker targets `wasm32-unknown-unknown` and uses `worker-build` to produce an optimised bundle.

```bash
rustup target add wasm32-unknown-unknown  # once
cargo install worker-build               # once
cargo build --target wasm32-unknown-unknown
```

For the production build used by `wrangler deploy`:

```bash
worker-build --release
```

## Local development

```bash
wrangler dev
```

Wrangler starts a local dev server backed by miniflare. To point at real Cloudflare KV instances, ensure your environment variables are configured (see below).

## Environment setup

All infrastructure IDs (account IDs, zone IDs, KV namespace IDs) are provided via environment variables and referenced in `wrangler.toml` with `{{ VARIABLE_NAME }}` syntax. Never commit these IDs to version control.

Copy the environment template and fill in your Cloudflare IDs:

```bash
cp .env.example .env
```

Source variables and deploy:

```bash
source .env
npx wrangler deploy              # sandbox
npx wrangler deploy --env production
```

Sensitive runtime secrets (signing keys, HMAC secrets, KEK material) are stored in the Cloudflare Secrets Store, not in environment variables or KV.

## Tests

```bash
cargo test
cargo clippy --workspace --all-features
```

Unit tests cover pure Rust functions that compile for the host target. Integration tests require a Cloudflare Workers environment (`wrangler dev` or deployed sandbox).

## API documentation

| Resource | URL |
| -------- | --- |
| OpenAPI specification | `/v1/openapi.json` |
| Interactive docs | `/v1/docs` (Swagger UI) |
| JWKS (canonical) | `/.well-known/jwks.json` |
| JWKS (redirect) | `/v1/jwks.json` (301 to canonical) |

## Observability

Console output surfaces in Wrangler dev and the Cloudflare Workers dashboard. Structured audit events are persisted via `provii-audit` for compliance retention. Every request carries an `X-Request-ID` header for correlation across log lines.

## Licence

This project is licensed under the GNU Affero General Public Licence v3.0. See the [LICENSE](LICENSE) file for details.
