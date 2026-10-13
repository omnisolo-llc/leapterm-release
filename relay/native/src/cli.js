// SPDX-License-Identifier: GPL-3.0-only
import {createRelayOwner} from './owner.js';

try {
  for (const name of ['RELAY_AUTH_TOKEN', 'RELAY_MANAGEMENT_TOKEN', 'RELAY_PUBLIC_ORIGIN', 'RELAY_STATE_PATH']) {
    if (!process.env[name]) throw Error('relay_configuration_required');
  }
  const owner = await createRelayOwner({
    env: process.env,
    statePath: process.env.RELAY_STATE_PATH,
    host: process.env.RELAY_LISTEN_HOST || '127.0.0.1',
    port: Number(process.env.RELAY_PORT || '7777'),
  });
  process.stdout.write(JSON.stringify({ready: true, listen: owner.origin}) + '\n');
  let stopping = false;
  const stop = async () => {
    if (stopping) return;
    stopping = true;
    try { await owner.close(); }
    catch { process.stderr.write('relay_shutdown_failed\n'); process.exitCode = 1; }
  };
  process.once('SIGTERM', stop);
  process.once('SIGINT', stop);
} catch {
  // Never echo environment values, headers, configuration text, or exception URLs.
  process.stderr.write('relay_startup_failed: verify runtime, private state permissions, and independent credentials\n');
  process.exitCode = 1;
}
