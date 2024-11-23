const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const axios = require('axios');
const jwt = require('jsonwebtoken');
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

const getExpiresIn = (token) => {
    try {
        const decoded = jwt.decode(token);
        if (decoded && decoded.exp) {
            const now = Math.floor(Date.now() / 1000);
            return decoded.exp - now;
        }
        return 0;
    } catch (e) {
        return 0; 
    }
};

app.use((req, res, next) => {
    const authHeader = req.get(AUTH0_CONFIG.SESSION_KEY);
    
    if (authHeader) {
        const [scheme, token] = authHeader.split(' ');
        
        if (scheme === 'Bearer' && token) {
            req.session = { accessToken: token };
            req.isAuthenticated = true;

            try {
                const decoded = jwt.decode(token); 
                req.session.username = decoded.name || decoded.sub; 
                req.session.email = decoded.email;
            } catch (e) {
                console.error("Token decode error:", e);
                req.isAuthenticated = false;
            }

            const expiresIn = getExpiresIn(token);
            if (expiresIn > 0 && expiresIn < 300 && req.session.refreshToken) {
                console.log("Token about to expire. Attempting refresh...");
                req.needsRefresh = true; 
            }

            return next();
        }
    }
    
    req.isAuthenticated = false;
    next();
});

app.get('/', (req, res) => {
    if (req.isAuthenticated && req.session.username) {
        return res.json({
            username: req.session.username,
            email: req.session.email,
            needsRefresh: req.needsRefresh || false,
            logout: 'http://localhost:3000/logout'
        });
    }
    res.sendFile(path.join(__dirname, '/index.html'));
});

app.get('/resource', (req, res) => {
    if (req.isAuthenticated) {
        return res.json({
            message: 'Access Granted. User ID: ' + req.session.username
        });
    }
    res.status(401).send('Unauthorized');
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

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
});
