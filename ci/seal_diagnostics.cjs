'use strict';
// Generic diagnostic envelope. The runner receives only the recipient PUBLIC key.
const fs = require('node:fs');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const path = require('node:path');
const AAD = Buffer.from('private-build-diagnostics/v1');
const MAX_LOG = 8 * 1024 * 1024;

function tail(file) {
  if (!fs.existsSync(file)) return '';
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink()) throw Error('Invalid diagnostic input');
  const fd = fs.openSync(file, 'r');
  try {
    const data = Buffer.alloc(Math.min(stat.size, MAX_LOG));
    const n = fs.readSync(fd, data, 0, data.length, Math.max(0, stat.size - MAX_LOG));
    return (stat.size > MAX_LOG ? '[Earlier output truncated]\n' : '') + data.subarray(0, n).toString('utf8');
  } finally { fs.closeSync(fd); }
}

function seal(payload, pem) {
  const recipient = crypto.createPublicKey(pem);
  if (recipient.asymmetricKeyType !== 'rsa' || recipient.asymmetricKeyDetails.modulusLength < 3072) {
    throw Error('RSA key of at least 3072 bits required');
  }
  const key = crypto.randomBytes(32);
  try {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(AAD);
    const plaintext = zlib.gzipSync(Buffer.from(JSON.stringify(payload)));
    const data = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return JSON.stringify({version: 1,
      key: crypto.publicEncrypt({key: recipient, oaepHash: 'sha256', padding: crypto.constants.RSA_PKCS1_OAEP_PADDING}, key).toString('base64'),
      iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64')});
  } finally { key.fill(0); }
}

function main() {
  const [root, output] = process.argv.slice(2);
  if (!root || !output || process.argv.length !== 4) throw Error('Invalid arguments');
  const payload = {bootstrap: tail(path.join(root, 'bootstrap.log')), task: tail(path.join(root, 'task.log'))};
  const encrypted = seal(payload, process.env.DIAGNOSTICS_PUBLIC_KEY || '');
  // Do not create an uploadable file until encryption has fully succeeded.
  fs.mkdirSync(path.dirname(output), {recursive: true, mode: 0o700});
  fs.writeFileSync(output, encrypted, {flag: 'wx', mode: 0o600});
}
if (require.main === module) {
  try { main(); } catch (_) { process.stderr.write('Diagnostic encryption failed.\n'); process.exitCode = 1; }
}
module.exports = {seal, tail};
