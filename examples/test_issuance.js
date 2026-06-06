const crypto = require('crypto');
const https = require('https');

// Replace with your saved credentials
const CLIENT_ID = 'YOUR_CLIENT_ID';
const API_KEY = 'YOUR_API_KEY';
const HMAC_SECRET = Buffer.from('YOUR_HMAC_SECRET_BASE64', 'base64');

function request(options, data) {
    return new Promise((resolve, reject) => {
        const req = https.request(options, res => {
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', () => {
                try {
                    resolve(JSON.parse(body));
                } catch(e) {
                    reject(body);
                }
            });
        });
        req.on('error', reject);
        if (data) req.write(JSON.stringify(data));
        req.end();
    });
}

async function test() {
    // 1. Start session
    console.log('Starting session...');
    const startRes = await request({
        hostname: 'issuer.provii.app',
        path: '/v1/issuance/start',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-API-Key': API_KEY
        }
    }, {
        actor: 'app',
        schema: 'provii.age/0',
        validity_days: 365
    });
    
    console.log('Session:', startRes);
    
    // 2. Create issuance request
    const issuanceRequest = {
        v: 2,
        kid: startRes.kid,
        c_bytes: crypto.randomBytes(32).toString('base64url'),
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + (365 * 86400),
        schema: 'provii.age/0'
    };
    
    // 3. Create HMAC
    const timestamp = Math.floor(Date.now() / 1000);
    const message = `${startRes.session_id}:${JSON.stringify(issuanceRequest)}`;
    const canonicalMessage = `${timestamp}:${message}`;
    const hmac = crypto.createHmac('sha256', HMAC_SECRET)
        .update(canonicalMessage)
        .digest('hex');
    
    // 4. Complete issuance
    console.log('\nCompleting issuance...');
    const completeRes = await request({
        hostname: 'issuer.provii.app',
        path: '/v1/issuance/complete',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    }, {
        session_id: startRes.session_id,
        issuance_request: issuanceRequest,
        authorizer: {
            format: 'client',
            keyId: CLIENT_ID,
            timestamp: timestamp,
            hmac: hmac
        }
    });
    
    console.log('Credential issued:', completeRes);
}

test().catch(console.error);