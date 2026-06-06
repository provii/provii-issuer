# Examples

This directory contains Node.js scripts that exercise the issuer Worker APIs.
Each script is intentionally minimal and uses environment variables for secrets
so they can be wired into existing tooling.

## Prerequisites

- Node.js 18+
- A running issuer Worker (local `wrangler dev` or a deployed environment)

Install dependencies once:

```bash
npm install
```

## Scripts

| Script | Purpose |
| ------ | ------- |
| `register_officer.js` | Creates a new officer record by calling the admin endpoint or inserting into KV (depending on your setup) |
| `register_client.js` | Registers a client and provisions API key material |
| `generate_officer-cose.js` | Demonstrates COSE key generation for YubiKey flows |
| `client_usage.js` | Performs a sample issuance using a client API key |
| `test_issuance.js` | Full officer → session → credential issuance happy path |

Refer to each script for the exact environment variables it expects (e.g.,
`ISSUER_BASE_URL`, `OFFICER_KEY_ID`, `CLIENT_API_KEY`).

## Running a script

```bash
ISSUER_BASE_URL=http://127.0.0.1:8787 \
OFFICER_KEY_ID=officer-123 \
OFFICER_HMAC=... \
node test_issuance.js
```

Scripts emit verbose logs describing each step; they are useful smoke tests when
introducing changes to the worker.
