// register_client.js
const crypto = require('crypto');

// Generate secure API key and HMAC secret
const apiKey = crypto.randomBytes(32).toString('base64url');
const apiKeyHash = crypto.createHash('sha256').update(apiKey).digest('hex');
const hmacSecret = crypto.randomBytes(32);
const clientId = `client-${crypto.randomBytes(8).toString('hex')}`;

const client = {
    client_id: clientId,
    client_name: process.argv[2] || "Test Client",
    api_key_hash: apiKeyHash,
    hmac_secret: Array.from(hmacSecret),
    created_at: Math.floor(Date.now() / 1000),
    last_used: null,
    rate_limit: 1000, // requests per hour
    allowed_schemas: ["provii.age/0"],
    max_validity_days: 3650,
    active: true
};

// Write secrets to a chmod-600 file so they don't land in shell history,
// CI logs, or anyone tailing stdout. Public metadata (record shape, KV
// commands) goes to stdout for the operator's terminal.
const fs = require('fs');
const path = require('path');
const credPath = path.join(process.cwd(), `.client-${clientId}.secrets`);
fs.writeFileSync(
  credPath,
  [
    '# DO NOT COMMIT. DO NOT EMAIL. DO NOT PASTE INTO CHAT.',
    '# Move into 1Password / Vault, then rm this file.',
    `CLIENT_ID=${clientId}`,
    `API_KEY=${apiKey}`,
    `HMAC_SECRET_BASE64=${hmacSecret.toString('base64')}`,
    ''
  ].join('\n'),
  { mode: 0o600 }
);

console.log('Client Registration (public metadata only):');
console.log(JSON.stringify(client, null, 2));
console.log(`\nSecrets written to: ${credPath}`);
console.log('Move them to your password manager and delete the file.');
console.log('\nKV provisioning commands (paste into a shell with wrangler auth):');
console.log(`npx wrangler kv:key put --namespace-id=YOUR_CLIENTS_NS "client:id:${clientId}" '${JSON.stringify(client)}'`);
console.log(`npx wrangler kv:key put --namespace-id=YOUR_CLIENTS_NS "client:api:${apiKeyHash}" '${JSON.stringify(client)}'`);