# Key Rotation Tool

Key and secret rotation tool for the Provii issuer, with zero downtime support.

## Features

- **Signing Key Rotation**: Zero-downtime rotation with automatic deprecation
- **HMAC Secret Rotation**: Graceful transition with dual-secret support
- **KEK Rotation**: Re-encryption of all secrets (manual process)
- **Dry-Run Mode**: Test operations without making changes
- **Audit Logging**: All operations logged for compliance
- **Rollback Support**: Automatic rollback on failure

## Installation

```bash
cd tools/key-rotation
cargo build --release
```

## Configuration

Set the following environment variables:

```bash
export CLOUDFLARE_ACCOUNT_ID="your-account-id"
export CLOUDFLARE_API_TOKEN="your-api-token"
export KV_KEYS_NAMESPACE_ID="namespace-id-for-keys"
export KV_OFFICERS_NAMESPACE_ID="namespace-id-for-officers"
export KV_CLIENTS_NAMESPACE_ID="namespace-id-for-clients"
export OPERATOR_ID="admin-user-id"
```

## Usage

### Rotate Signing Keypair

**Generate new keypair automatically:**

```bash
./key-rotation rotate-signing-key \
  --old-kid provii:2025-01 \
  --new-kid provii:2025-02 \
  --generate
```

**Provide specific keypair:**

```bash
./key-rotation rotate-signing-key \
  --old-kid provii:2025-01 \
  --new-kid provii:2025-02 \
  --new-sk <base64url-encoded-sk> \
  --new-vk <base64url-encoded-vk>
```

**Important:** After rotation, update the `DEFAULT_KID` environment variable.

### Rotate Officer HMAC Secret

**Step 1: Start rotation (both secrets valid):**

```bash
./key-rotation rotate-officer-hmac \
  --officer-id officer-123 \
  --generate
```

**Step 2: Finalize rotation (only new secret valid):**

```bash
./key-rotation finalize-officer-hmac \
  --officer-id officer-123
```

### Rotate Client HMAC Secret

**Step 1: Start rotation:**

```bash
./key-rotation rotate-client-hmac \
  --client-id client-456 \
  --generate
```

**Step 2: Finalize rotation:**

```bash
./key-rotation finalize-client-hmac \
  --client-id client-456
```

### Rotate KEK (Key Encryption Key)

**Note:** KEK rotation requires manual implementation for production use.

```bash
./key-rotation rotate-kek --generate
```

After generating a new KEK:
1. Update the `KEY_ENCRYPTION_KEY` Workers Secret
2. Re-encrypt all stored secrets manually or via custom script

### View Key Status

**List signing keys:**

```bash
./key-rotation list-signing-keys
```

**Show officer status:**

```bash
./key-rotation show-officer --officer-id officer-123
```

**Show client status:**

```bash
./key-rotation show-client --client-id client-456
```

### Dry Run Mode

Test any operation without making changes:

```bash
./key-rotation --dry-run rotate-signing-key \
  --old-kid provii:2025-01 \
  --new-kid provii:2025-02 \
  --generate
```

## Key Rotation Workflows

### Signing Key Rotation

1. **Generate new keypair** - Tool creates RedJubjub keypair
2. **Deprecate old key** - Old key marked as deprecated (still valid for verification)
3. **Activate new key** - New key becomes active for new signatures
4. **Update config** - Update DEFAULT_KID environment variable
5. **Monitor** - Old credentials verified with deprecated key, new ones use new key

**Rollback:** If issues occur, revert DEFAULT_KID to old value.

### HMAC Secret Rotation

1. **Start rotation** - New secret stored, both old and new valid
2. **Transition period** - Monitor for authentication failures
3. **Finalize** - Remove old secret, only new valid
4. **Complete** - All systems using new secret

**Rollback:** Before finalization, both secrets work.

### KEK Rotation

KEK rotation is a critical operation requiring:
1. Generate new 32-byte KEK
2. List all encrypted secrets in KV
3. Decrypt each with old KEK
4. Re-encrypt with new KEK
5. Update Workers Secret
6. Verify all operations

**Important:** This is currently a manual process requiring careful execution.

## Security Considerations

1. **Operator Audit Trail**: All operations logged with operator ID
2. **Dry-Run First**: Always test with --dry-run before production
3. **Backup Secrets**: Store old secrets securely before rotation
4. **Graceful Transitions**: HMAC rotation supports dual-secret validation
5. **Zero Downtime**: Signing key rotation preserves old key for verification

## Error Handling

The tool handles errors carefully:

- **Validation**: All inputs validated before execution
- **Rollback**: Automatic rollback on storage failures
- **Audit Trail**: All operations logged even on failure
- **Clear Messages**: User-friendly error messages with recovery steps

## Development

**Run tests:**

```bash
cargo test
```

**Build:**

```bash
cargo build --release
```

**Format:**

```bash
cargo fmt
```

## Architecture

The tool operates directly on Cloudflare KV via REST API:

```
CLI Tool → Cloudflare API → KV Namespaces
                                ├── KEYS
                                ├── OFFICERS
                                └── CLIENTS
```

Key features:
- Direct KV manipulation via API
- No Worker deployment required
- Supports all Cloudflare KV operations
- Compatible with envelope encryption

## Troubleshooting

**"Officer not found"**
- Verify officer ID is correct
- Check KV_OFFICERS_NAMESPACE_ID is set correctly

**"Failed to decode key"**
- Ensure base64url encoding (not standard base64)
- Check for proper padding removal

**"KEK rotation not implemented"**
- KEK rotation requires custom implementation
- Contact system administrator for manual process

## Examples

**Complete signing key rotation:**

```bash
# 1. Dry run first
./key-rotation --dry-run rotate-signing-key \
  --old-kid provii:2025-01 --new-kid provii:2025-02 --generate

# 2. Execute rotation
./key-rotation rotate-signing-key \
  --old-kid provii:2025-01 --new-kid provii:2025-02 --generate

# 3. Update environment
wrangler secret put DEFAULT_KID
# Enter: provii:2025-02
```

**Complete HMAC rotation:**

```bash
# 1. Start rotation
./key-rotation rotate-officer-hmac \
  --officer-id officer-123 --generate

# 2. Wait for transition period (24-48 hours recommended)

# 3. Finalize rotation
./key-rotation finalize-officer-hmac \
  --officer-id officer-123
```

## Licence

This project is licensed under the GNU Affero General Public Licence v3.0. See the root [LICENSE](../../LICENSE) file for details.

Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust.
