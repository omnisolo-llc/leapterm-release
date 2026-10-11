'use strict';
// Streaming recipient encryption for the explicitly requested evaluation ZIP.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const MAGIC = Buffer.from('OMNI-EVALUATION-SEALED-1\n');
const MAX_ZIP = 512 * 1024 * 1024;
const KEYS = ['source_repository', 'source_sha', 'builder_repository', 'builder_sha', 'run_id', 'attempt'];

function validateIdentity(identity) {
  const sha = value => typeof value === 'string' && /^[a-f0-9]{40}$/.test(value) && !/^0+$/.test(value);
  const number = (value, max) => typeof value === 'string' && value.length <= max && /^[1-9][0-9]*$/.test(value);
  if (!identity || typeof identity !== 'object' || Array.isArray(identity) ||
      Object.keys(identity).length !== KEYS.length || KEYS.some(key => !Object.hasOwn(identity, key)) ||
      identity.source_repository !== 'omnisolo-llc/omniterm' || identity.builder_repository !== 'omnisolo-llc/omniterm-release' ||
      !sha(identity.source_sha) || !sha(identity.builder_sha) || !number(identity.run_id, 32) || !number(identity.attempt, 16)) {
    throw Error('Invalid evaluation identity');
  }
}
function regular(file, maximum) {
  const info = fs.lstatSync(file, {bigint: true});
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1n || info.size <= 0n || info.size > BigInt(maximum) ||
      fs.realpathSync(file) !== path.resolve(file)) throw Error('Invalid evaluation input');
  return info;
}
function same(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size &&
    left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs && right.nlink === 1n && right.isFile();
}
function inventory(directory) {
  if (!path.isAbsolute(directory) || fs.realpathSync(directory) !== directory || !fs.lstatSync(directory).isDirectory()) {
    throw Error('Invalid evaluation directory');
  }
  const names = fs.readdirSync(directory).sort();
  const zip = names.find(name => /^[A-Za-z0-9][A-Za-z0-9_.+-]{0,150}\.zip$/.test(name));
  if (!zip || names.length !== 2 || !names.includes(`${zip}.sha256`)) throw Error('Invalid evaluation inventory');
  const file = path.join(directory, zip);
  const metadata = regular(file, MAX_ZIP);
  const checksumFile = path.join(directory, `${zip}.sha256`);
  regular(checksumFile, 256);
  const checksum = fs.readFileSync(checksumFile, 'utf8');
  const suffix = `  ${zip}`;
  const line = checksum.replace(/\r?\n$/, '');
  if (line.length !== 64 + suffix.length || !/^[a-f0-9]{64}$/.test(line.slice(0, 64)) || line.slice(64) !== suffix) {
    throw Error('Invalid evaluation checksum');
  }
  return {file, metadata, checksum: line.slice(0, 64), filename: zip};
}
function sealEvaluation(directory, output, identity, scope, pem) {
  validateIdentity(identity);
  if (typeof scope !== 'string' || !/^[a-z][a-z0-9-]{0,63}$/.test(scope) || !path.isAbsolute(output)) {
    throw Error('Invalid evaluation scope');
  }
  const source = inventory(directory);
  return sealBoundFile(source, output, {schema: 1, kind: 'evaluation', identity, scope,
    filename: source.filename, plaintext_sha256: source.checksum, plaintext_size: Number(source.metadata.size)},
    pem, MAGIC, MAX_ZIP);
}
// Encryption only. Native callers own classification, inventory and receipts.
// Preserve the evaluation protocol while allowing other approved native
// producers to use the same bounded, authenticated streaming primitive.
function sealBoundFile(source, output, attributes, pem, magic, maximum) {
  if (!path.isAbsolute(output) || fs.realpathSync(path.dirname(output)) !== path.dirname(output) ||
      !fs.lstatSync(path.dirname(output)).isDirectory() || !Buffer.isBuffer(magic) ||
      !Number.isSafeInteger(maximum) || maximum <= 0 || !attributes || typeof attributes !== 'object' ||
      ['algorithm', 'key', 'iv'].some(key => Object.hasOwn(attributes, key))) throw Error('Invalid sealed file input');
  const recipient = crypto.createPublicKey(pem);
  if (recipient.asymmetricKeyType !== 'rsa' || recipient.asymmetricKeyDetails.modulusLength < 3072) {
    throw Error('RSA key of at least 3072 bits required');
  }
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const temporary = path.join(path.dirname(output), `.evaluation-${crypto.randomBytes(16).toString('hex')}`);
  let input, destination;
  try {
    input = fs.openSync(source.file, 'r');
    if (!same(source.metadata, fs.fstatSync(input, {bigint: true}))) throw Error('Evaluation input changed');
    const header = Buffer.from(JSON.stringify({...attributes,
      algorithm: 'RSA-OAEP-SHA256+A256GCM',
      key: crypto.publicEncrypt({key: recipient, oaepHash: 'sha256', padding: crypto.constants.RSA_PKCS1_OAEP_PADDING}, key).toString('base64'),
      iv: iv.toString('base64')}));
    if (header.length > 16384) throw Error('Evaluation header exceeds its bound');
    const length = Buffer.alloc(4); length.writeUInt32BE(header.length);
    const aad = Buffer.concat([magic, length, header]);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv); cipher.setAAD(aad);
    const digest = crypto.createHash('sha256');
    destination = fs.openSync(temporary, 'wx', 0o600);
    fs.writeFileSync(destination, aad);
    const buffer = Buffer.alloc(1024 * 1024);
    let read, bytes = 0;
    while ((read = fs.readSync(input, buffer)) > 0) {
      bytes += read;
      if (bytes > maximum) throw Error('Sealed input exceeds its bound');
      const chunk = buffer.subarray(0, read);
      digest.update(chunk);
      fs.writeFileSync(destination, cipher.update(chunk));
    }
    fs.writeFileSync(destination, cipher.final());
    fs.writeFileSync(destination, cipher.getAuthTag());
    if (bytes !== Number(source.metadata.size) || digest.digest('hex') !== source.checksum ||
        !same(source.metadata, fs.fstatSync(input, {bigint: true})) || !same(source.metadata, regular(source.file, maximum))) {
      throw Error('Evaluation revision changed');
    }
    fs.fsyncSync(destination); fs.closeSync(destination); destination = undefined;
    // Linking the completed private file rejects an existing destination.
    fs.linkSync(temporary, output); fs.unlinkSync(temporary);
  } finally {
    key.fill(0);
    if (input !== undefined) fs.closeSync(input);
    if (destination !== undefined) fs.closeSync(destination);
    if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
  }
}
if (require.main === module) {
  try {
    const [directory, output, identityFile, scope] = process.argv.slice(2);
    if (!directory || !output || !identityFile || !scope || process.argv.length !== 6) throw Error('Invalid arguments');
    regular(identityFile, 16384);
    sealEvaluation(directory, output, JSON.parse(fs.readFileSync(identityFile, 'utf8')), scope,
      process.env.DIAGNOSTICS_PUBLIC_KEY || '');
  } catch (_) { process.stderr.write('Evaluation encryption failed.\n'); process.exitCode = 1; }
}
module.exports = {MAGIC, MAX_ZIP, validateIdentity, inventory, sealEvaluation, sealBoundFile, regular};
