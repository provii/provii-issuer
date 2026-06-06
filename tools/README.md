# Operator Tools

This directory groups Rust binaries that support day-to-day operations of the
issuer service.

## Layout

| Tool | Description |
| ---- | ----------- |
| `generate-issuer-keys/` | Generates RedJubjub signing key pairs for seeding the `IS_KEYS` namespace |
| `admin-officer/` | Manage officer registrations (create, rotate secrets, deactivate accounts) |

Each tool is a standalone Cargo project targeting the host (not WebAssembly).

## Building a tool

```bash
cd tools/generate-issuer-keys
cargo build --release
```

Binaries are emitted under `target/release/`.

## Credentials and environment

Tools expect the same environment variables used by the worker (e.g., Cloudflare
API token, account ID). Export them before running a command or use a `.env`
file with your preferred shell tooling.

Example:

```bash
export CLOUDFLARE_ACCOUNT_ID=...
export CLOUDFLARE_API_TOKEN=...
./target/release/generate-issuer-keys --output keys.json
```

Consult each tool’s `--help` output for supported flags.
