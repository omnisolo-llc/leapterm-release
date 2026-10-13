import test from 'node:test';
import assert from 'node:assert/strict';
import { rtcConfiguration, rtcCorsPreflight, rtcRoute } from '../src/rtc.js';

const service = '00000000-0000-4000-8000-000000000003';

test('RTC requires explicit enablement, an HTTPS origin and independent service identity', () => {
  const base = {
    NATIVE_PUBLIC_RTC_ENABLED: 'true',
    NATIVE_RTC_INGRESS: 'https://rtc.example.test',
    NATIVE_RTC_SERVICE_TOKEN: service,
    RELAY_AUTH_TOKEN: 'Public-Relay-Workload-Token-2026!',
    RELAY_MANAGEMENT_TOKEN: 'Public-Relay-Management-Token-2026!',
  };
  assert.equal(rtcConfiguration({...base, NATIVE_PUBLIC_RTC_ENABLED: 'false'}), null);
  assert.ok(rtcConfiguration(base, 'https://relay.example.test'));
  assert.equal(rtcConfiguration({...base, NATIVE_RTC_INGRESS: 'http://rtc.example.test'}), null);
  assert.equal(rtcConfiguration({...base, NATIVE_RTC_INGRESS: 'https://relay.example.test'},
    'https://relay.example.test'), null);
  assert.equal(rtcConfiguration({...base, NATIVE_RTC_SERVICE_TOKEN: base.RELAY_AUTH_TOKEN}), null);
  assert.equal(rtcConfiguration({...base, NATIVE_RTC_SERVICE_TOKEN: base.RELAY_MANAGEMENT_TOKEN}), null);
  assert.equal(rtcConfiguration({...base, NATIVE_RTC_SERVICE_TOKEN: service,
    NATIVE_RELAY_AUTHORITY_TOKEN: service}), null);
  assert.equal(rtcConfiguration({...base, NATIVE_RTC_INGRESS: 'https://rtc.localhost'}), null);
  assert.equal(rtcConfiguration({...base, NATIVE_RTC_INGRESS: 'https://relay.internal'}), null);
  assert.equal(rtcRoute('/internal/v1/connectors/device-1/rtc-offer')?.[1], 'device-1');
  assert.equal(rtcRoute('/internal/v1/connectors/device-1/dial-stream'), null);
});

test('RTC CORS preflight reflects only allowed HTTPS origins and requested headers', async () => {
  const env = {NATIVE_RELAY_BROWSER_ORIGINS: 'https://app.example.test'};
  const allowed = rtcCorsPreflight(new Request('https://relay.example.test/internal/v1/connectors/device-1/rtc-offer', {
    method: 'OPTIONS', headers: {
      origin: 'https://app.example.test',
      'access-control-request-method': 'POST',
      'access-control-request-headers': 'content-type,x-workload-token',
    },
  }), env);
  assert.equal(allowed.status, 204);
  assert.equal(allowed.headers.get('access-control-allow-origin'), 'https://app.example.test');
  assert.equal(allowed.headers.get('access-control-allow-credentials'), null);

  const denied = rtcCorsPreflight(new Request('https://relay.example.test/internal/v1/connectors/device-1/rtc-offer', {
    method: 'OPTIONS', headers: {
      origin: 'https://attacker.example.test',
      'access-control-request-method': 'POST',
      'access-control-request-headers': 'content-type,x-workload-token',
    },
  }), env);
  assert.equal(denied.status, 403);
  assert.equal(denied.headers.get('access-control-allow-origin'), null);
});
