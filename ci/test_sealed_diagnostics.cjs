'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');
const {seal, tail} = require('./seal_diagnostics.cjs');
const keys = crypto.generateKeyPairSync('rsa', {modulusLength: 3072});
function open(envelope, privateKey = keys.privateKey) {
  const v = JSON.parse(envelope);
  const key = crypto.privateDecrypt({key: privateKey, oaepHash: 'sha256', padding: crypto.constants.RSA_PKCS1_OAEP_PADDING}, Buffer.from(v.key, 'base64'));
  const c = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(v.iv, 'base64'));
  c.setAAD(Buffer.from('private-build-diagnostics/v1'));
  c.setAuthTag(Buffer.from(v.tag, 'base64'));
  return JSON.parse(zlib.gunzipSync(Buffer.concat([c.update(Buffer.from(v.data, 'base64')), c.final()])));
}
const pem = keys.publicKey.export({type: 'spki', format: 'pem'});
test('only recipient can decrypt and plaintext never enters envelope', () => {
  const payload = {task: 'private fixture source and credential'};
  const envelope = seal(payload, pem);
  assert(!envelope.includes(payload.task));
  assert.deepEqual(open(envelope), payload);
  const wrong = crypto.generateKeyPairSync('rsa', {modulusLength: 3072});
  assert.throws(() => open(envelope, wrong.privateKey));
});
test('tampering is detected', () => {
  const v = JSON.parse(seal({task: 'private fixture'}, pem));
  const data = Buffer.from(v.data, 'base64'); data[0] ^= 1; v.data = data.toString('base64');
  assert.throws(() => open(JSON.stringify(v)));
});
test('reject absent and weak recipient keys', () => {
  assert.throws(() => seal({}, ''));
  const weak = crypto.generateKeyPairSync('rsa', {modulusLength: 2048}).publicKey.export({type: 'spki', format: 'pem'});
  assert.throws(() => seal({}, weak));
});
test('only regular bounded log inputs are read', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sealed-test-'));
  try { const file = path.join(root, 'log'); fs.writeFileSync(file, 'fixture'); assert.equal(tail(file), 'fixture'); assert.throws(() => tail(root)); }
  finally { fs.rmSync(root, {recursive: true, force: true}); }
});
