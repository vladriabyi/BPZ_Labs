const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const jwt = require('jsonwebtoken');

const port = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '10s';

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const users = [
    {
        login: 'Login',
        password: 'Password',
        username: 'Username',
    },
    {
        login: 'Login1',
        password: 'Password1',
        username: 'Username1',
    }
];

const extractToken = (headerValue = '') => {
    if (!headerValue) {
        return null;
    }
    const parts = headerValue.split(' ');
    if (parts.length === 2) {
        const [schema, token] = parts;
        if (/^Bearer$/i.test(schema)) {
            return token;
        }
    }
    return parts[0];
};

const attachUserFromToken = (req, res, next) => {
    const authorizationHeader = req.get('Authorization');
    const rawToken = extractToken(authorizationHeader);

    if (!rawToken) {
        return next();
    }

    try {
        const payload = jwt.verify(rawToken, JWT_SECRET);
        req.user = payload;
    } catch (error) {
        console.warn('Invalid JWT provided:', error.message);
        return res.status(401).json({ error: 'Invalid or expired token' });
    }

    next();
};

const requireAuth = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({ error: 'Authorization token missing' });
    }
    next();
};

app.use(attachUserFromToken);

app.get('/', (req, res) => {
    if (req.user) {
        return res.json({
            username: req.user.username,
            login: req.user.login,
            logout: 'Client should discard JWT'
        });
    }
    res.sendFile(path.join(__dirname + '/index.html'));
});

app.get('/logout', (req, res) => {
    res.json({ message: 'Remove the JWT on the client to logout' });
});

app.get('/profile', requireAuth, (req, res) => {
    res.json({
        username: req.user.username,
        login: req.user.login
    });
});

app.post('/api/login', (req, res) => {
    const { login, password } = req.body;

    const user = users.find((user) => user.login === login && user.password === password);

    if (!user) {
        return res.status(401).json({ error: 'Invalid login or password' });
    }

    const token = jwt.sign(
        {
            username: user.username,
            login: user.login
        },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
    );

    res.json({
        token,
        tokenType: 'Bearer',
        expiresIn: JWT_EXPIRES_IN,
        username: user.username
    });
});

app.listen(port, () => {
    console.log(`JWT auth app listening on port ${port}`);
});
