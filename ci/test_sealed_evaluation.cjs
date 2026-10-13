'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const {MAGIC, sealEvaluation} = require('./seal_evaluation.cjs');
const keys = crypto.generateKeyPairSync('rsa', {modulusLength: 3072});
const pem = keys.publicKey.export({type: 'spki', format: 'pem'});
const identity = {source_repository: 'omnisolo-llc/omniterm', source_sha: 'a'.repeat(40),
  builder_repository: 'omnisolo-llc/omniterm-release', builder_sha: 'b'.repeat(40), run_id: '42', attempt: '2'};
function fixture(t) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'evaluation-contract-')));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const input = path.join(root, 'preview'); fs.mkdirSync(input);
  const bytes = Buffer.concat([Buffer.from('PK\x03\x04fixture-evaluation-'), crypto.randomBytes(2 * 1024 * 1024)]);
  fs.writeFileSync(path.join(input, 'fixture.zip'), bytes);
  const hash = crypto.createHash('sha256').update(bytes).digest('hex');
  fs.writeFileSync(path.join(input, 'fixture.zip.sha256'), `${hash}  fixture.zip\n`);
  return {root, input, bytes, output: path.join(root, 'evaluation.sealed')};
}
function open(bytes, privateKey = keys.privateKey) {
  assert.deepEqual(bytes.subarray(0, MAGIC.length), MAGIC);
  const start = MAGIC.length + 4;
  const end = start + bytes.readUInt32BE(MAGIC.length);
  const header = JSON.parse(bytes.subarray(start, end));
  const key = crypto.privateDecrypt({key: privateKey, oaepHash: 'sha256', padding: crypto.constants.RSA_PKCS1_OAEP_PADDING}, Buffer.from(header.key, 'base64'));
  const cipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(header.iv, 'base64'));
  cipher.setAAD(bytes.subarray(0, end)); cipher.setAuthTag(bytes.subarray(-16));
  return {header, plaintext: Buffer.concat([cipher.update(bytes.subarray(end, -16)), cipher.final()])};
}
test('evaluation bytes stream under recipient encryption and bind pipeline metadata', t => {
  const f = fixture(t); sealEvaluation(f.input, f.output, identity, 'verify-windows', pem);
  const encrypted = fs.readFileSync(f.output); const result = open(encrypted);
  assert.deepEqual(result.plaintext, f.bytes);
  assert.deepEqual(result.header.identity, identity);
  assert.equal(result.header.scope, 'verify-windows');
  assert.equal(result.header.plaintext_size, f.bytes.length);
  assert(!encrypted.includes(f.bytes.subarray(0, 1024)));
  assert.equal(fs.statSync(f.output).nlink, 1);
});
test('ciphertext and pipeline header tampering are rejected by authentication', t => {
  const f = fixture(t); sealEvaluation(f.input, f.output, identity, 'verify-windows', pem);
  const encrypted = fs.readFileSync(f.output);
  const changed = Buffer.from(encrypted); changed[changed.length - 20] ^= 1;
  assert.throws(() => open(changed));
  const text = encrypted.toString('latin1').replace('"run_id":"42"', '"run_id":"43"');
  assert.throws(() => open(Buffer.from(text, 'latin1')));
});
test('rejects extra files, links and mismatching checksum before publishing encrypted output', t => {
  const f = fixture(t);
  fs.writeFileSync(path.join(f.input, 'private.key'), 'fixture-only-secret');
  assert.throws(() => sealEvaluation(f.input, f.output, identity, 'verify-windows', pem));
  assert(!fs.existsSync(f.output)); fs.unlinkSync(path.join(f.input, 'private.key'));
  fs.writeFileSync(path.join(f.input, 'fixture.zip.sha256'), `${'0'.repeat(64)}  fixture.zip\n`);
  assert.throws(() => sealEvaluation(f.input, f.output, identity, 'verify-windows', pem));
  assert(!fs.existsSync(f.output));
});
test('rejects absent recipient, foreign identity and existing output', t => {
  const f = fixture(t);
  assert.throws(() => sealEvaluation(f.input, f.output, identity, 'verify-windows', ''));
  assert.throws(() => sealEvaluation(f.input, f.output, {...identity, source_repository: 'other/repo'}, 'verify-windows', pem));
  fs.writeFileSync(f.output, 'existing fixture receipt');
  assert.throws(() => sealEvaluation(f.input, f.output, identity, 'verify-windows', pem));
  assert.equal(fs.readFileSync(f.output, 'utf8'), 'existing fixture receipt');
});
