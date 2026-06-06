// generate-officer-cose.js
const crypto = require('crypto');

// Generate P-256 key pair
const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
  namedCurve: 'P-256',
  publicKeyEncoding: { type: 'spki', format: 'der' },
  privateKeyEncoding: { type: 'pkcs8', format: 'der' }
});

// Extract raw public key coordinates (65 bytes: 0x04 + x + y)
const pubKeyDer = publicKey;
// Skip DER headers to get to the actual key
const rawPubKey = pubKeyDer.slice(-65);
const x = rawPubKey.slice(1, 33);
const y = rawPubKey.slice(33, 65);

// Build COSE key (CBOR-encoded)
// COSE key map for P-256:
// 1: 2 (kty: EC2)
// 3: -7 (alg: ES256)
// -1: x coordinate (32 bytes)
// -2: y coordinate (32 bytes)
// -3: 1 (crv: P-256)

// Simplified COSE construction (manually building CBOR)
const coseKey = Buffer.concat([
  Buffer.from([
    0xa5, // map(5)
    0x01, 0x02, // 1: 2 (kty: EC2)
    0x03, 0x26, // 3: -7 (alg: ES256)
    0x20, 0x01, // -1: x coordinate follows
    0x58, 0x20  // bytes(32)
  ]),
  x,
  Buffer.from([
    0x21, 0x02, // -2: y coordinate follows
    0x58, 0x20  // bytes(32)
  ]),
  y,
  Buffer.from([
    0x22, 0x01  // -3: 1 (crv: P-256)
  ])
]);

// Generate random credential ID
const credentialId = crypto.randomBytes(32);

// Create officer registration object
const officer = {
  officer_id: "officer-001",
  credential_id: Array.from(credentialId),
  public_key: Array.from(coseKey),
  created_at: Math.floor(Date.now() / 1000),
  last_used: null,
  active: true
};

console.log('Officer Registration JSON:');
console.log(JSON.stringify(officer, null, 2));

console.log('\n\nBase64URL encoded values for manual entry:');
console.log('Credential ID:', credentialId.toString('base64url'));
console.log('COSE Public Key:', coseKey.toString('base64url'));

// Create the KV storage key
console.log('\n\nKV Storage Key:');
console.log(`officer:cred:${credentialId.toString('base64url')}`);