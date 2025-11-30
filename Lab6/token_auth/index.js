const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const axios = require('axios');
const { auth } = require('express-oauth2-jwt-bearer');
const jose = require('jose');
const port = 3000;

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const AUTH0_CONFIG = {
    DOMAIN: 'vladriabyi.us.auth0.com',
    CLIENT_ID: '2Lugn7UQlBadqukI5tfpvPFiC6DceDuE',
    CLIENT_SECRET: 'Ad7pnBCjGlGnOFfnm4hjYp2_WBCfErPwoOM6kReGHu1wVxjoy9OiDfpCT6CwS5gC',
    AUDIENCE: 'https://vladriabyi.us.auth0.com/api/v2/',
    AUTHORIZE_URL: `https://vladriabyi.us.auth0.com/authorize`,
    TOKEN_URL: `https://vladriabyi.us.auth0.com/oauth/token`,
    REDIRECT_URI: 'http://localhost:3000/callback'
};

const checkJwt = auth({
    audience: AUTH0_CONFIG.AUDIENCE,
    issuerBaseURL: `https://${AUTH0_CONFIG.DOMAIN}/`,
    tokenSigningAlg: 'RS256'
});

async function getPublicKeyFromJWKS() {
    try {
        const jwksResponse = await axios.get(`https://${AUTH0_CONFIG.DOMAIN}/.well-known/jwks.json`);
        const jwks = jwksResponse.data;
        
        if (jwks.keys && jwks.keys.length > 0) {
            const key = jwks.keys[0];
            const publicKey = await jose.importJWK({
                kty: key.kty,
                n: key.n,
                e: key.e
            }, 'RSA-OAEP-256');
            return publicKey;
        }
        throw new Error('No keys found in JWKS');
    } catch (error) {
        console.error('Error getting public key from JWKS:', error);
        throw error;
    }
}

async function encryptPayload(payload, publicKey) {
    try {
        const encrypted = await new jose.CompactEncrypt(
            new TextEncoder().encode(JSON.stringify(payload))
        )
        .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' })
        .encrypt(publicKey);
        return encrypted;
    } catch (error) {
        console.error('Encryption error:', error);
        throw error;
    }
}

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '/index.html'));
});

app.get('/login', (req, res) => {
    const params = new URLSearchParams({
        response_type: 'code',
        response_mode: 'query',
        client_id: AUTH0_CONFIG.CLIENT_ID,
        redirect_uri: AUTH0_CONFIG.REDIRECT_URI,
        scope: 'openid profile email offline_access',
        audience: AUTH0_CONFIG.AUDIENCE
    });
    const authorizeUrl = `${AUTH0_CONFIG.AUTHORIZE_URL}?${params.toString()}`;
    res.redirect(authorizeUrl);
});

app.get('/callback', async (req, res) => {
    const { code } = req.query;

    if (!code) {
        return res.status(400).send('Authorization code required');
    }

    try {
        const tokenPayload = new URLSearchParams({
            grant_type: 'authorization_code',
            client_id: AUTH0_CONFIG.CLIENT_ID,
            client_secret: AUTH0_CONFIG.CLIENT_SECRET,
            code,
            redirect_uri: AUTH0_CONFIG.REDIRECT_URI
        });

        const tokenResponse = await axios.post(
            AUTH0_CONFIG.TOKEN_URL,
            tokenPayload.toString(),
            { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
        );

        const { access_token, refresh_token, id_token } = tokenResponse.data;

        return res.send(`
            <!DOCTYPE html>
            <html lang="en">
                <head>
                    <meta charset="UTF-8" />
                    <title>Auth0 Callback</title>
                </head>
                <body>
                    <script>
                        const payload = {
                            token: ${JSON.stringify(access_token)},
                            refreshToken: ${JSON.stringify(refresh_token || '')},
                            idToken: ${JSON.stringify(id_token || '')}
                        };
                        sessionStorage.setItem('session', JSON.stringify(payload));
                        window.location.href = '/';
                    </script>
                </body>
            </html>
        `);
    } catch (error) {
        console.error('Code exchange error:', error.response?.data || error.message);
        res.status(500).send('Failed to exchange authorization code');
    }
});

app.get('/resource', checkJwt, (req, res) => {
    res.json({
        message: 'Access Granted via Authorization Code Flow!',
        user: req.auth.payload.sub,
        tokenValidated: true
    });
});

app.post('/api/encrypt-payload', checkJwt, async (req, res) => {
    try {
        const publicKey = await getPublicKeyFromJWKS();
        const payload = {
            ...req.auth.payload,
            timestamp: Date.now()
        };
        await encryptPayload(payload, publicKey);
        res.json({
            message: 'Payload encrypted successfully',
            originalPayload: payload,
            encrypted: true
        });
    } catch (error) {
        console.error('Encryption error:', error);
        res.status(500).json({ error: 'Failed to encrypt payload' });
    }
});

app.post('/api/token/refresh', async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).send({ error: 'Refresh token required' });

    try {
        const refreshPayload = new URLSearchParams({
            grant_type: 'refresh_token',
            client_id: AUTH0_CONFIG.CLIENT_ID,
            client_secret: AUTH0_CONFIG.CLIENT_SECRET,
            refresh_token: refreshToken
        });

        const response = await axios.post(
            AUTH0_CONFIG.TOKEN_URL,
            refreshPayload.toString(),
            { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
        );

        res.json({
            token: response.data.access_token,
            refreshToken: response.data.refresh_token || refreshToken
        });
    } catch (error) {
        res.status(401).send({ error: 'Refresh failed' });
    }
});

app.get('/logout', (req, res) => {
    const logoutUrl = `https://${AUTH0_CONFIG.DOMAIN}/v2/logout?client_id=${AUTH0_CONFIG.CLIENT_ID}&returnTo=${encodeURIComponent('http://localhost:3000')}`;
    res.redirect(logoutUrl);
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});