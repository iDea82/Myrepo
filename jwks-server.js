const express = require('express');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const basicAuth = require('express-basic-auth');
const { generateKeyPair } = require('./keygen');
const cors = require('cors');
require('dotenv').config();
const port = process.env.PORT;
const jwt_key = process.env.JWT_KEY;
const app = express();
//const port = 8080;

app.use(cors());
app.use(express.static('public'));
//Middleware to parse JSON requests
app.use(express.json());

//Load existing keys from keys.json
const keys = JSON.parse(fs.readFileSync('keys.json', 'utf8'));

//JWKS endpoint
app.get('/jwks', (req, res) => {
    const currentTime = Date.now();
    const validKeys = keys.filter((key) => key.expiry > currentTime);
    const jwks = {
        keys: validKeys.map((key) => ({
            kid: key.kid,
            kty: 'RSA',
            nbf: key.expiry - 24 * 60 * 60 * 1000, //Not Before (1 day before expiry)
            use: 'sig',
            alg: 'RS256',
            e: 'AQAB',
            n: key.publicKey,
        })),
    };
    res.json(jwks);
        
});

//
app.get('/', (req, res) => {
  //health check route
  res.status(200).send({ code: 0, message: 'ok' });
});

app.get('/token', (req, res) =>{
  //route to get a token
  let id = Math.random().toString(36).substring(2, 8);
  let limit = 60 * 3; //180 secs
  let expires = Math.floor(Date.now() / 1000) + limit;
  let payload = {
    _id: id,
    exp: expires,
  };
  let token = jwt.sign(payload, jwt_key);
  res.status(201).send({ code:0, message: 'ok', data: token });
});


app.get('/test', (req, res) => {
  //simulate route that needs a valid token to access
  const header = req.header('Authorization');
  const [type, token] = header.split(' ');
  if (type === 'Bearer' && typeof token !== 'undefined') {
    try {
      let payload = jwt.verify(token, jwt_key);
      let current = Math.floor(Date.now() / 1000);
      let diff = current - payload.exp;
      res.status(200).send({ code: 0, message: `all good. ${diff} remaining` });
    } catch (err) {
      res.status(401).send({ code: 123, message: 'Invalid or expired token.' });
    }
  } else {
    res.status(401).send({ code: 456, message: 'Invalid token' });
  }
});
//



// Authentication endpoint
app.post('/auth', basicAuth({ users: { 'userABC': 'password123' } }), (req, res) => {
  const expired  = req.query;
  const keyToUse = expired ? keys[1] : keys[0]; // Use the second key if 'expired' is present

  const payload = {
    sub: 'userABC',
    // Add other claims as needed
  };

  const token = jwt.sign(payload, keyToUse.rsaPrivateKey, { algorithm: 'RS256', keyid: keyToUse.kid });

  res.json({ token });
});


app.listen(port, () => {
  console.log(`JWKS server is running on port ${port}`);
});
