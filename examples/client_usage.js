// Example: Using the issuer service as a client

const crypto = require('crypto');
const fetch = require('node-fetch');

const CLIENT_ID = 'your-client-id';
const API_KEY = 'your-api-key';
const HMAC_SECRET = Buffer.from('your-hmac-secret-base64', 'base64');

// Start session with API key
async function startSession() {
    const response = await fetch('https://issuer.provii.app/v1/issuance/start', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-API-Key': API_KEY
        },
        body: JSON.stringify({
            actor: 'app',
            schema: 'provii.age/0',
            validity_days: 365
        })
    });
    return response.json();
}

// Complete with HMAC
async function completeIssuance(sessionId, issuanceRequest) {
    const timestamp = Math.floor(Date.now() / 1000);
    const message = `${sessionId}:${JSON.stringify(issuanceRequest)}`;
    const canonicalMessage = `${timestamp}:${message}`;
    
    const hmac = crypto
        .createHmac('sha256', HMAC_SECRET)
        .update(canonicalMessage)
        .digest('hex');
    
    const response = await fetch('https://issuer.provii.app/v1/issuance/complete', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            session_id: sessionId,
            issuance_request: issuanceRequest,
            authorizer: {
                format: 'client',
                keyId: CLIENT_ID,
                timestamp: timestamp,
                hmac: hmac
            }
        })
    });
    return response.json();
}