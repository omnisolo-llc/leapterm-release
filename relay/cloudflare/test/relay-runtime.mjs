// Real local Workerd fixture for public-kit development checks.
// The source repository additionally asserts extracted-package behavior in Rust.
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';

const entry = fileURLToPath(new URL('../src/index.js', import.meta.url));
let source;
export async function actualRelay(test, bindings, {outboundService} = {}) {
  source ??= build({entryPoints: [entry], bundle: true, write: false,
    platform: 'neutral', format: 'esm', external: ['cloudflare:*', 'node:*']})
    .then(result => result.outputFiles[0].text);
  // A separate fixture Worker reaches the actual public Durable Object for
  // defense-in-depth tests. It supplies routing only, never an auth/storage result.
  const probe = `export default { async fetch(request, env) {
    const connector = request.headers.get('x-fixture-direct-connector');
    if (!connector) return env.PUBLIC.fetch(request);
    const headers = new Headers(request.headers);
    headers.delete('x-fixture-direct-connector');
    const id = env.PROBE.idFromName(JSON.stringify(['free-v1', connector]));
    return env.PROBE.get(id).fetch(new Request(request, {headers}));
  }};`;
  const runtime = new Miniflare(convertV4MiniflareOptions({workers: [
    {name: 'fixture-router', script: probe, modules: true, compatibilityDate: '2026-09-18',
      serviceBindings: {PUBLIC: 'public-relay'},
      durableObjects: {PROBE: {className: 'NativeConnectorRelay', scriptName: 'public-relay', useSQLite: true}}},
    {name: 'public-relay', script: await source, modules: true,
      compatibilityDate: '2026-09-18', bindings,
      durableObjects: {NATIVE_CONNECTORS: {className: 'NativeConnectorRelay', useSQLite: true}},
      ...(outboundService ? {outboundService} : {})},
  ]}));
  await runtime.ready;
  const sockets = new Set();
  test.after(async () => {
    for (const socket of sockets) try { socket.close(); } catch {}
    await runtime.dispose();
  });
  return {
    runtime,
    async fetch(path, options = {}) {
      const response = await runtime.dispatchFetch(new URL(path, 'https://relay.example'), options);
      if (response.webSocket) {
        response.webSocket.accept(); sockets.add(response.webSocket);
      }
      return response;
    },
    async direct(connectorId, request) {
      const headers = new Headers(request.headers);
      headers.set('x-fixture-direct-connector', connectorId);
      return runtime.dispatchFetch(request.url, {method: request.method, headers,
        body: request.body, duplex: request.body ? 'half' : undefined});
    },
  };
}
