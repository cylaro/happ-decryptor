import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import test from 'node:test';

import { bridgePlugin, createBridgeHandler, requestUpstream } from '../server/bridge.js';

const publicDns = async () => [{ address: '93.184.216.34', family: 4 }];
const forbiddenDns = async () => { throw new Error('Unexpected DNS lookup in offline test'); };

function request({ method = 'POST', path, body = '', remoteAddress = '127.0.0.1', headers = {} }) {
  const req = new EventEmitter();
  req.method = method;
  req.url = path;
  req.headers = {
    host: '127.0.0.1:5173',
    origin: 'http://127.0.0.1:5173',
    'sec-fetch-site': 'same-origin',
    'content-type': 'application/json',
    ...headers,
  };
  req.socket = { remoteAddress };
  const response = {
    statusCode: 200,
    headers: {},
    chunks: [],
    setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
    writeHead(status, headersToSet) { this.statusCode = status; Object.assign(this.headers, headersToSet); },
    end(chunk = '') { this.chunks.push(String(chunk)); this.ended = true; },
  };
  queueMicrotask(() => {
    if (body) req.emit('data', Buffer.from(body));
    req.emit('end');
  });
  return { req, response };
}

async function call(handler, options) {
  const { req, response } = request(options);
  await handler(req, response);
  return { response, body: JSON.parse(response.chunks.join('')) };
}

const validSubscription = JSON.stringify({
  url: 'https://panel.example/sub',
  identity: { hwid: 'abcdefghij', deviceOs: 'iOS', verOs: '18', deviceModel: 'Phone', userAgent: 'Happ/1' },
});

test('capabilities is local-only and loopback protected', async () => {
  const handler = createBridgeHandler({ resolve: forbiddenDns });
  const ok = await call(handler, { method: 'GET', path: '/api/capabilities' });
  assert.deepEqual(ok.body, { local: true });
  const remote = await call(handler, { method: 'GET', path: '/api/capabilities', remoteAddress: '192.168.1.5' });
  assert.equal(remote.response.statusCode, 403);
  assert.match(remote.body.error, /loopback/i);
});

test('preserves exact subscription headers and returns upstream non-2xx responses', async () => {
  const seen = [];
  const handler = createBridgeHandler({ outbound: async (target, options) => {
    seen.push({ target, options });
    return { status: 429, headers: { 'content-type': 'text/plain', 'retry-after': '9' }, text: 'slow down' };
  }, resolve: async () => [{ address: '93.184.216.34', family: 4 }] });
  const result = await call(handler, { path: '/api/subscription', body: validSubscription });
  assert.equal(result.response.statusCode, 200);
  assert.equal(result.body.status, 429);
  assert.equal(result.body.text, 'slow down');
  assert.equal(seen[0].options.headers['x-hwid'], 'abcdefghij');
  assert.equal(seen[0].options.headers['User-Agent'], 'Happ/1');
  assert.equal(seen[0].options.headers['x-device-os'], 'iOS');
});

test('rejects private destinations, cross-site metadata, and redirects', async () => {
  const handler = createBridgeHandler({ outbound: async () => ({ status: 200, headers: {}, text: '' }), resolve: forbiddenDns });
  for (const url of ['http://127.0.0.1/x', 'http://[::1]/x', 'http://169.254.169.254/latest', 'http://[::ffff:127.0.0.1]/x']) {
    const result = await call(handler, { path: '/api/subscription', body: JSON.stringify({ url, identity: {} }) });
    assert.equal(result.response.statusCode, 400, url);
    assert.match(result.body.error, /public|private|loopback|metadata/i, url);
  }
  const cross = await call(handler, { path: '/api/subscription', body: validSubscription, headers: { origin: 'https://evil.example', 'sec-fetch-site': 'cross-site' } });
  assert.equal(cross.response.statusCode, 403);
  const redirect = createBridgeHandler({ outbound: async () => ({ status: 302, headers: { location: 'https://secret.example' }, text: '' }), resolve: async () => [{ address: '93.184.216.34', family: 4 }] });
  const redirected = await call(redirect, { path: '/api/subscription', body: validSubscription });
  assert.equal(redirected.response.statusCode, 400);
  assert.match(redirected.body.error, /redirect/i);
});

test('encrypt uses only the official endpoint and parses conservative links', async () => {
  const seen = [];
  const handler = createBridgeHandler({ outbound: async (target, options) => {
    seen.push({ target, options });
    return { status: 200, headers: { 'content-type': 'application/json' }, text: JSON.stringify({ encrypted_link: 'happ://crypt5/abc' }) };
  }, resolve: async () => [{ address: '93.184.216.34', family: 4 }] });
  const result = await call(handler, { path: '/api/encrypt', body: JSON.stringify({ url: 'https://panel.example/sub' }) });
  assert.deepEqual(result.body, { link: 'happ://crypt5/abc' });
  assert.equal(seen[0].target, 'https://crypto.happ.su/api-v2.php');
  assert.equal(JSON.parse(seen[0].options.body).url, 'https://panel.example/sub');
});

test('limits request bodies and reports outbound failures clearly', async () => {
  const handler = createBridgeHandler({ outbound: async () => { throw new Error('upstream timed out'); }, resolve: async () => [{ address: '93.184.216.34', family: 4 }] });
  const error = await call(handler, { path: '/api/subscription', body: validSubscription });
  assert.equal(error.response.statusCode, 502);
  assert.match(error.body.error, /upstream request failed/i);
  const tooLarge = await call(handler, { path: '/api/subscription', body: 'x'.repeat(16 * 1024 + 1) });
  assert.equal(tooLarge.response.statusCode, 413);
});

test('rejects all non-public IPv4 and IPv6 ranges including alternate encodings', async () => {
  const handler = createBridgeHandler({ resolve: forbiddenDns, outbound: () => assert.fail('must not send') });
  for (const host of ['0.0.0.0', '10.2.3.4', '127.255.255.254', '2130706433', '0x7f000001',
    '100.64.1.1', '172.16.2.3', '192.168.1.1', '192.0.0.1', '198.18.0.1', '224.0.0.1',
    '255.255.255.255', '168.63.129.16', '[::]', '[::1]', '[::ffff:192.168.1.1]',
    '[::ffff:a00:1]', '[fc00::1]', '[fd00:ec2::254]', '[fe80::1]', '[fec0::1]',
    '[ff02::1]', '[2001:db8::1]', '[2002:7f00:1::]', '[64:ff9b::7f00:1]', '[3fff::1]']) {
    const result = await call(handler, { path: '/api/subscription', body: JSON.stringify({ url: `http://${host}/secret` }) });
    assert.equal(result.response.statusCode, 400, host);
    assert.match(result.body.error, /public|private|unsafe/i, host);
  }
});

test('rejects mixed DNS records, credentials and unsupported protocols before outbound', async () => {
  const handler = createBridgeHandler({ resolve: async () => [...await publicDns(), { address: '::1', family: 6 }], outbound: () => assert.fail('must not send') });
  for (const url of ['https://panel.example/private', 'https://name:password@panel.example/sub', 'file:///secret', 'ftp://panel.example/sub']) {
    const result = await call(handler, { path: '/api/subscription', body: JSON.stringify({ url }) });
    assert.equal(result.response.statusCode, 400);
    assert.ok(!result.body.error.includes('password'));
  }
});

test('requires matching loopback Host and Origin and rejects browser cross-site metadata', async () => {
  const handler = createBridgeHandler({ resolve: forbiddenDns, outbound: () => assert.fail('must not send') });
  for (const headers of [
    { host: 'evil.example:5173' }, { host: '127.0.0.1:5173/anything' },
    { origin: 'http://127.0.0.1:9000' }, { origin: 'http://localhost:5173' },
    { origin: undefined }, { origin: 'null' }, { origin: 'http://127.0.0.1:5173/path' },
    { 'sec-fetch-site': 'cross-site' }, { 'sec-fetch-site': 'same-site' },
  ]) {
    const result = await call(handler, { path: '/api/subscription', body: validSubscription, headers });
    assert.equal(result.response.statusCode, 403, JSON.stringify(headers));
    assert.equal(result.response.headers['access-control-allow-origin'], undefined);
  }
  const get = await call(handler, { method: 'GET', path: '/api/capabilities', headers: { origin: undefined } });
  assert.deepEqual(get.body, { local: true });
  const ipv6 = await call(handler, { method: 'GET', path: '/api/capabilities', remoteAddress: '::1', headers: { host: '[::1]:5173', origin: 'http://[::1]:5173' } });
  assert.deepEqual(ipv6.body, { local: true });
});

test('body, DNS and upstream body deadlines are bounded without exposing secret URLs', async () => {
  const handler = createBridgeHandler({ timeoutMs: 10, resolve: () => new Promise(() => {}), outbound: () => assert.fail('must not send') });
  const result = await call(handler, { path: '/api/subscription', body: validSubscription });
  assert.equal(result.response.statusCode, 504);
  assert.match(result.body.error, /timed out/i);
  const upstream = createBridgeHandler({ timeoutMs: 10, resolve: publicDns, outbound: () => new Promise(() => {}) });
  const timed = await call(upstream, { path: '/api/subscription', body: validSubscription });
  assert.equal(timed.response.statusCode, 504);
  const fail = createBridgeHandler({ resolve: publicDns, outbound: async () => { throw new Error('https://secret.example/token?secret'); } });
  const failed = await call(fail, { path: '/api/subscription', body: validSubscription });
  assert.equal(failed.response.statusCode, 502);
  assert.ok(!failed.body.error.includes('secret'));
});

test('rejects malformed JSON and invalid identity before outbound and bounds responses', async () => {
  const handler = createBridgeHandler({ resolve: publicDns, outbound: () => assert.fail('must not send') });
  for (const body of ['bad JSON', 'null', '[]', JSON.stringify({ url: 'https://panel.example/sub', identity: { userAgent: 'Happ\r\nX-Bad: yes' } }), JSON.stringify({ url: 'https://panel.example/sub', identity: { hwid: 'short' } })]) {
    const result = await call(handler, { path: '/api/subscription', body });
    assert.equal(result.response.statusCode, 400);
  }
  const large = createBridgeHandler({ resolve: publicDns, outbound: async () => ({ status: 200, headers: {}, text: 'x'.repeat(2 * 1024 * 1024 + 1) }) });
  const result = await call(large, { path: '/api/subscription', body: validSubscription });
  assert.equal(result.response.statusCode, 502);
  assert.match(result.body.error, /too large/i);
});

test('official encryption rejects unrelated JSON, redirects and non-2xx; accepts plain crypt5', async () => {
  for (const text of ['{"link":"happ://crypt5/abc"}', '{"encrypted_link":"https://evil.example"}', '<p>happ://crypt5/abc</p>']) {
    const handler = createBridgeHandler({ resolve: publicDns, outbound: async () => ({ status: 200, headers: {}, text }) });
    const result = await call(handler, { path: '/api/encrypt', body: validSubscription });
    assert.equal(result.response.statusCode, 502);
  }
  for (const status of [302, 500]) {
    const handler = createBridgeHandler({ resolve: publicDns, outbound: async () => ({ status, headers: {}, text: '{"encrypted_link":"happ://crypt5/abc"}' }) });
    const result = await call(handler, { path: '/api/encrypt', body: validSubscription });
    assert.equal(result.response.statusCode, 502);
  }
  const handler = createBridgeHandler({ resolve: publicDns, outbound: async () => ({ status: 200, headers: {}, text: 'happ://crypt5/abc\n' }) });
  const result = await call(handler, { path: '/api/encrypt', body: validSubscription });
  assert.deepEqual(result.body, { link: 'happ://crypt5/abc' });
});

test('Vite hooks mount bridge without intercepting ordinary assets', async () => {
  const plugin = bridgePlugin();
  for (const hook of ['configureServer', 'configurePreviewServer']) {
    let middleware;
    plugin[hook]({ middlewares: { use(value) { middleware = value; } } });
    let passed = false;
    await middleware({ url: '/src/main.js' }, {}, () => { passed = true; });
    assert.equal(passed, true);
  }
});

test('HTTP transport pins validated DNS addresses and preserves exact headers', async () => {
  let options;
  const fakeRequest = (url, opts, onResponse) => {
    options = opts;
    assert.equal(url.hostname, 'panel.example');
    const request = new EventEmitter();
    request.end = () => {
      const response = new EventEmitter();
      response.statusCode = 401;
      response.headers = { 'content-type': 'text/plain' };
      onResponse(response);
      queueMicrotask(() => { response.emit('data', Buffer.from('denied')); response.emit('end'); });
    };
    request.destroy = (error) => request.emit('error', error);
    return request;
  };
  const result = await requestUpstream('https://panel.example/sub', {
    records: await publicDns(), headers: { 'User-Agent': 'Happ/EXACT', 'x-hwid': 'abcdefghij' },
  }, { httpsRequest: fakeRequest });
  assert.equal(options.headers['User-Agent'], 'Happ/EXACT');
  assert.equal(result.status, 401);
  assert.equal(result.text, 'denied');
  assert.equal(options.agent, false);
  options.lookup('panel.example', {}, (error, address, family) => {
    assert.equal(error, null);
    assert.equal(address, '93.184.216.34');
    assert.equal(family, 4);
  });
  options.lookup('panel.example', { all: true }, (error, records) => {
    assert.equal(error, null);
    assert.deepEqual(records, [{ address: '93.184.216.34', family: 4 }]);
  });
});
