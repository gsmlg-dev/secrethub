// Synthetic local client-encrypted fixture, using the pinned official PBKDF2/HKDF-expand contract.
const crypto = require('node:crypto');
const fs = require('node:fs');
const email = `official-${crypto.randomUUID()}@example.test`;
const password = crypto.randomBytes(24).toString('base64url');
const master = crypto.pbkdf2Sync(password, email, 600000, 32, 'sha256');
const verifier = crypto.pbkdf2Sync(master, password, 1, 32, 'sha256').toString('base64');
const expand = info => crypto.createHmac('sha256', master).update(Buffer.concat([Buffer.from(info), Buffer.from([1])])).digest();
const stretched = Buffer.concat([expand('enc'), expand('mac')]);
function encrypt(data, key) {
 const iv = crypto.randomBytes(16), cipher = crypto.createCipheriv('aes-256-cbc', key.subarray(0, 32), iv);
 const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
 const mac = crypto.createHmac('sha256', key.subarray(32)).update(Buffer.concat([iv, encrypted])).digest();
 return `2.${iv.toString('base64')}|${encrypted.toString('base64')}|${mac.toString('base64')}`;
}
const userKey = crypto.randomBytes(64);
const pair = crypto.generateKeyPairSync('rsa', {modulusLength: 2048});
const fixture = {email, password, password_hash: verifier, encrypted_key: encrypt(userKey, stretched), public_key: pair.publicKey.export({type: 'spki', format: 'der'}).toString('base64'), encrypted_private_key: encrypt(pair.privateKey.export({type: 'pkcs8', format: 'der'}), userKey)};
fs.writeFileSync(process.argv[2], JSON.stringify(fixture), {mode: 0o600});
