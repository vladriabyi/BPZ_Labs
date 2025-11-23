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
    API_URL: `https://vladriabyi.us.auth0.com/oauth/token`,
    REALM: 'Username-Password-Authentication',
    SESSION_KEY: 'Authorization'
};

const checkJwt = auth({
    audience: AUTH0_CONFIG.AUDIENCE,
    issuerBaseURL: `https://${AUTH0_CONFIG.DOMAIN}/`
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

app.get('/resource', checkJwt, (req, res) => {
    res.json({
        message: 'Access Granted. User ID: ' + req.auth.payload.sub,
        tokenValidated: true,
        user: req.auth.payload
    });
});

app.post('/api/login', async (req, res) => {
    const { login, password } = req.body;

    const data = {
        grant_type: 'http://auth0.com/oauth/grant-type/password-realm',
        username: login,
        password: password,
        audience: AUTH0_CONFIG.AUDIENCE,
        client_id: AUTH0_CONFIG.CLIENT_ID,
        client_secret: AUTH0_CONFIG.CLIENT_SECRET,
        realm: AUTH0_CONFIG.REALM,
        scope: 'openid profile offline_access'
    };

    try {
        const auth0Response = await axios.post(AUTH0_CONFIG.API_URL, data, {
            headers: {
                'Content-Type': 'application/json'
            }
        });

        const { access_token, refresh_token, expires_in, id_token } = auth0Response.data;

        if (access_token) {
            return res.json({ 
                token: access_token, 
                refreshToken: refresh_token 
            });
        }
        
        res.status(401).send();
        
    } catch (error) {
        console.error("Auth0 Login Error:", error.response?.data || error.message);
        res.status(401).send({ error: 'Authentication failed' });
    }
});

app.post('/api/token/refresh', async (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(400).send({ error: 'Refresh token required' });
    }

    const data = {
        grant_type: 'refresh_token',
        client_id: AUTH0_CONFIG.CLIENT_ID,
        client_secret: AUTH0_CONFIG.CLIENT_SECRET,
        refresh_token: refreshToken
    };

    try {
        const auth0Response = await axios.post(AUTH0_CONFIG.API_URL, data, {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });

        const { access_token, expires_in, refresh_token: newRefreshToken } = auth0Response.data;

        res.json({
            token: access_token,
            refreshToken: newRefreshToken || refreshToken
        });

    } catch (error) {
        console.error("Token Refresh Error:", error.response?.data || error.message);
        res.status(401).send({ error: 'Refresh token expired or invalid' });
    }
});

app.get('/logout', (req, res) => {
    res.redirect('/'); 
});

app.post('/api/encrypt-payload', checkJwt, async (req, res) => {
    try {
        const publicKey = await getPublicKeyFromJWKS();

        const payload = {
            ...req.auth.payload,
            timestamp: Date.now()
        };

        const encrypted = await encryptPayload(payload, publicKey);
        
        res.json({
            message: 'Payload encrypted successfully',
            originalPayload: payload,
            encrypted: true
        });
    } catch (error) {
        console.error('Encryption error:', error);
        res.status(500).json({ error: 'Failed to encrypt payload: ' + error.message });
    }
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
});
