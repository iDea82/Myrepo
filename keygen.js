const fs = require('fs');
const crypto = require('crypto');

function generateKeyPair() {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem',
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem',
        },
    });

    const kid = crypto.randomBytes(16).toString('hex');
    const expiry = Date.now() + 24 * 60 * 60 * 1000; //Expiry timestamp (1 day from now)

    return { kid, privateKey, publicKey, expiry };

}

const keys = [generateKeyPair()];

//Write the keys to a JSON file
fs.writeFileSync('keys.json', JSON.stringify(keys, null, 2));

module.exports = { generateKeyPair };