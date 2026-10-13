import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createRelayOwner } from '../relay/native/src/owner.js';

const nativeRoot = new URL('../relay/native/', import.meta.url);
const credentials = {
  RELAY_AUTH_TOKEN: 'Native-Relay-Workload-2026!Credential',
  RELAY_MANAGEMENT_TOKEN: 'Native-Relay-Operator-2026!Credential',
  RELAY_PUBLIC_ORIGIN: 'https://relay.example.test',
};

test('native relay package runtime dependencies match its pinned lockfile', async () => {
  const manifest = JSON.parse(await readFile(new URL('package.json', nativeRoot), 'utf8'));
  const lock = JSON.parse(await readFile(new URL('package-lock.json', nativeRoot), 'utf8'));
  assert.equal(manifest.name, 'omniterm-self-hosted-origin');
  assert.equal(manifest.version, '1.0.0');
  assert.equal(manifest.engines.node, '>=24.21.0');
  assert.equal(manifest.scripts.start, 'node src/cli.js');
  assert.deepEqual(lock.packages[''].dependencies, manifest.dependencies);
  assert.deepEqual(lock.packages[''].engines, manifest.engines);
  assert.equal(lock.packages['node_modules/ws'].version, manifest.dependencies.ws);
});

test('native owner enforces loopback and independent credentials and persists revocation', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'omniterm-native-relay-contract-'));
  const statePath = join(directory, 'relay.sqlite');
  let owner;
  t.after(async () => {
    if (owner) await owner.close();
    await rm(directory, {recursive: true, force: true});
  });

  await assert.rejects(
    createRelayOwner({env: credentials, statePath, host: '0.0.0.0'}),
    /loopback_relay_listener_required/,
  );
  await assert.rejects(
    createRelayOwner({
      env: {...credentials, RELAY_MANAGEMENT_TOKEN: credentials.RELAY_AUTH_TOKEN},
      statePath,
    }),
    /independent_relay_credentials_required/,
  );

  owner = await createRelayOwner({env: credentials, statePath, port: 0});
  assert.match(owner.origin, /^http:\/\/127\.0\.0\.1:/);

  const health = await fetch(`${owner.origin}/healthz`);
  assert.equal(health.status, 200);
  assert.equal(await health.text(), 'OK');
  const init = await (await fetch(`${owner.origin}/relay/api/v1/init`)).json();
  assert.deepEqual(init.transports, ['websocket']);
  assert.equal(init.native_rtc, false);

  const queryCredential = await fetch(
    `${owner.origin}/v1/connectors/stream?connector_id=relay-contract&token=${encodeURIComponent(credentials.RELAY_AUTH_TOKEN)}`,
  );
  assert.equal(queryCredential.status, 401);
  assert.equal((await queryCredential.json()).error, 'header_authentication_required');

  const connector = 'relay-contract';
  const managementPath = `/internal/v1/connectors/${connector}/revoke`;
  const workloadCannotRevoke = await fetch(`${owner.origin}${managementPath}`, {
    method: 'POST',
    headers: {'x-relay-management-token': credentials.RELAY_AUTH_TOKEN},
  });
  assert.equal(workloadCannotRevoke.status, 401);

  const revoke = await fetch(`${owner.origin}${managementPath}`, {
    method: 'POST',
    headers: {'x-relay-management-token': credentials.RELAY_MANAGEMENT_TOKEN},
  });
  assert.equal(revoke.status, 204);
  await owner.close();
  owner = undefined;

  owner = await createRelayOwner({env: credentials, statePath, port: 0});
  const deniedAfterRestart = await fetch(
    `${owner.origin}/v1/connectors/stream?connector_id=${connector}`,
    {headers: {'x-workload-token': credentials.RELAY_AUTH_TOKEN}},
  );
  assert.equal(deniedAfterRestart.status, 403);
  assert.equal((await deniedAfterRestart.json()).error, 'connector_revoked');

  const restore = await fetch(`${owner.origin}/internal/v1/connectors/${connector}/restore`, {
    method: 'POST',
    headers: {'x-relay-management-token': credentials.RELAY_MANAGEMENT_TOKEN},
  });
  assert.equal(restore.status, 204);

  if (process.platform !== 'win32') {
    for (const path of [directory, statePath, statePath + '.owner']) {
      const mode = (await stat(path)).mode & 0o777;
      assert.equal(mode & 0o077, 0, `${path} must not be accessible to group or other users`);
    }
  }
});
