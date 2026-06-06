// register_officer.js
const base64url = require('base64url');

// Example officer registration
const officer = {
  officer_id: "officer-001",
  credential_id: base64url.encode(Buffer.from("your-credential-id")),
  public_key: base64url.encode(Buffer.from("your-cose-public-key")),
  created_at: Math.floor(Date.now() / 1000),
  last_used: null,
  active: true
};

console.log(JSON.stringify(officer, null, 2));