# oauth
k
https://github.com/copilot/c/a74be8df-53de-4a0a-8462-1953de1db423
const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const axios = require('axios');

const app = express();
const port = 3001;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());

const sessions = {}; // 用于存储会话信息

// 生成随机字符串函数
function generateRandomString(length) {
    return crypto.randomBytes(length).toString('hex');
}

// 登录页面
app.get('/', (req, res) => {
    res.send(`
        <html>
        <body>
            <h1>Welcome to Our Website</h1>
            <a href="/login/oauth">Login with OAuth</a>
        </body>
        </html>
    `);
});

// OAuth登录端点
app.get('/login/oauth', (req, res) => {
    const sessionId = generateRandomString(16);
    const state = generateRandomString(16);
    sessions[sessionId] = { state };

    res.cookie('session_id', sessionId, { httpOnly: true });

    const clientId = 'client_id_123456';
    const redirectUri = 'http://localhost:3001/callback';
    const oauthUrl = `http://localhost:3000/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&state=${state}`;

    res.redirect(oauthUrl);
});

// OAuth回调端点
app.get('/callback', (req, res) => {
    const { code, state } = req.query;
    const sessionId = req.cookies.session_id;

    if (!code || !state || !sessionId || !sessions[sessionId]) {
        return res.status(400).send('Invalid request');
    }

    // 验证状态参数
    if (state !== sessions[sessionId].state) {
        return res.status(400).send('Invalid state parameter');
    }
//
    // 请求OAuth提供商的令牌端点
    const tokenUrl = 'http://localhost:3000/token';
    const clientId = 'client_id_123456';
    const clientSecret = 'client_secret_123456';
    const redirectUri = 'http://localhost:3000/callback';

    axios.post(tokenUrl, {
        client_id: clientId,
        client_secret: clientSecret,
        code,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code'
    })
    .then(response => {
        sessions[sessionId].accessToken = response.data.access_token;
        res.redirect('/secure');
    })
    .catch(error => {
        console.error(error);
        res.status(500).send('Failed to obtain access token');
    });
});

// 受保护资源端点
app.get('/secure', (req, res) => {
    const sessionId = req.cookies.session_id;

    if (!sessionId || !sessions[sessionId] || !sessions[sessionId].accessToken) {
        return res.status(401).send('Unauthorized');
    }

    res.send(`
        <html>
        <body>
            <h1>Secure Page</h1>
            <p>You are logged in with access token: ${sessions[sessionId].accessToken}</p>
        </body>
        </html>
    `);
});

app.listen(port, () => {
    console.log(`Website server is listening on port ${port}`);
});

```
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const clients = [
    {
        clientId: 'client_id_123456',
        clientSecret: 'client_secret_123456',
        redirectUris: ['http://localhost:3000/callback']
    }
];

const users = [
    {
        id: '123456',
        username: '123456',
        password: '123456'
    }
];

const authorizationCodes = [];
const accessTokens = [];

// 生成随机字符串函数
function generateRandomString(length) {
    return crypto.randomBytes(length).toString('hex');
}

// 授权端点
app.get('/authorize', (req, res) => {
    const clientId = req.query.client_id;
    const redirectUri = req.query.redirect_uri;
    const username = req.query.username;
    const password = req.query.password;
    const state = req.query.state;

    const client = clients.find(c => c.clientId === clientId && c.redirectUris.includes(redirectUri));
    console.log(client);
//{
//  clientId: 'client_id_123456',
//  clientSecret: 'client_secret_123456',
//  redirectUris: [ 'http://localhost:3000/callback' ]
//}
    
    const user = users.find(u => u.username === username && u.password === password);
//怎么匹配多个用户，/authorize端点的同用户code怎么和/token的匹配，同clientid之间
    if (!client || !user) {
        return res.status(400).send('Invalid client or user credentials');
    }

    const code = generateRandomString(16);
    authorizationCodes.push({ code, clientId, redirectUri, userId: user.id });

    res.redirect(`${redirectUri}?code=${code}&state=${state}`);
});

// 令牌端点
app.post('/token', (req, res) => {
    const { client_id, client_secret, code, redirect_uri } = req.body;

    const client = clients.find(c => c.clientId === client_id && c.clientSecret === client_secret);
    const authCode = authorizationCodes.find(c => c.code === code && c.redirectUri === redirect_uri);

    if (!client || !authCode) {
        return res.status(400).send('Invalid client or authorization code');
    }

    const accessToken = generateRandomString(32);
    accessTokens.push({ token: accessToken, userId: authCode.userId });

    // 删除已使用的授权码
    const index = authorizationCodes.indexOf(authCode);
    authorizationCodes.splice(index, 1);

    res.json({ access_token: accessToken });
});

// 受保护资源端点
app.get('/secure', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).send('Unauthorized');
    }

    const token = authHeader.split(' ')[1];
    const accessToken = accessTokens.find(t => t.token === token);

    if (!accessToken) {
        return res.status(401).send('Invalid access token');
    }

    res.json({ message: 'Secure data' });
});

app.listen(3000, () => {
    console.log('OAuth server is listening on port 3000');
});

```


const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const axios = require('axios');

const app = express();
const port = 3001;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());

const sessions = {}; // 用于存储会话信息

// 生成随机字符串函数
function generateRandomString(length) {
    return crypto.randomBytes(length).toString('hex');
}

// 登录页面
app.get('/', (req, res) => {
    res.send(`
        <html>
        <body>
            <h1>Welcome to Our Website</h1>
            <a href="/login/oauth">Login with OAuth</a>
        </body>
        </html>
    `);
});

// OAuth登录端点
app.get('/login/oauth', (req, res) => {
    const sessionId = generateRandomString(16);
    const state = generateRandomString(16);
    sessions[sessionId] = { state };

    res.cookie('session_id', sessionId, { httpOnly: true });

    const clientId = 'client_id_123456';
    const redirectUri = 'http://localhost:3001/callback';
    const oauthUrl = `http://localhost:3000/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&state=${state}`;

    res.redirect(oauthUrl);
});

// OAuth回调端点
app.get('/callback', (req, res) => {
    const { code, state } = req.query;
    const sessionId = req.cookies.session_id;

    if (!code || !state || !sessionId || !sessions[sessionId]) {
        return res.status(400).send('Invalid request');
    }

    // 验证状态参数
    if (state !== sessions[sessionId].state) {
        return res.status(400).send('Invalid state parameter');
    }
//
    // 请求OAuth提供商的令牌端点
    const tokenUrl = 'http://localhost:3000/token';
    const clientId = 'client_id_123456';
    const clientSecret = 'client_secret_123456';
    const redirectUri = 'http://localhost:3000/callback';

    axios.post(tokenUrl, {
        client_id: clientId,
        client_secret: clientSecret,
        code,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code'
    })
    .then(response => {
        sessions[sessionId].accessToken = response.data.access_token;
        res.redirect('/secure');
    })
    .catch(error => {
        console.error(error);
        res.status(500).send('Failed to obtain access token');
    });
});

// 受保护资源端点
app.get('/secure', (req, res) => {
    const sessionId = req.cookies.session_id;

    if (!sessionId || !sessions[sessionId] || !sessions[sessionId].accessToken) {
        return res.status(401).send('Unauthorized');
    }

    res.send(`
        <html>
        <body>
            <h1>Secure Page</h1>
            <p>You are logged in with access token: ${sessions[sessionId].accessToken}</p>
        </body>
        </html>
    `);
});

app.listen(port, () => {
    console.log(`Website server is listening on port ${port}`);
});
