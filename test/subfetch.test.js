import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildHeaders,
  encryptOfficial,
  fetchSubscription,
  getCapabilities,
} from '../src/lib/subfetch.js';

test('buildHeaders preserves the supplied Happ identity exactly', () => {
  assert.deepEqual(buildHeaders({
    hwid: 'UE42LJXu4DbiCaBv',
    deviceOs: 'iOS',
    verOs: '18.3',
    deviceModel: 'iPhone 14 Pro Max',
    userAgent: 'Happ/1.0',
  }), {
    'x-hwid': 'UE42LJXu4DbiCaBv',
    'x-device-os': 'iOS',
    'x-ver-os': '18.3',
    'x-device-model': 'iPhone 14 Pro Max',
    'User-Agent': 'Happ/1.0',
  });
});

test('buildHeaders does not invent defaults and rejects invalid header values', () => {
  assert.deepEqual(buildHeaders(), {});
  assert.deepEqual(buildHeaders({ hwid: '' }), {});
  assert.throws(() => buildHeaders({ hwid: 'too-short' }), /x-hwid/);
  assert.throws(() => buildHeaders({ hwid: 'abcdefghij\r\nX-Leak: yes' }), /x-hwid/);
  assert.throws(() => buildHeaders({ deviceOs: 'iOS\nspoof' }), /header/i);
});

test('client respects pre-aborted signals, bridge errors and unavailable capabilities', async () => {
  const oldFetch = globalThis.fetch;
  globalThis.fetch = async (_url, { signal }) => {
    signal.throwIfAborted();
    return new Response(JSON.stringify({ error: 'redirect rejected' }), { status: 400 });
  };
  try {
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(fetchSubscription('https://panel.example/sub', { signal: controller.signal }), { name: 'AbortError' });
    await assert.rejects(fetchSubscription('https://panel.example/sub'), /redirect rejected/);
    assert.deepEqual(await getCapabilities(), { local: false });
    globalThis.fetch = async () => new Response('<html>static site</html>', { status: 200 });
    assert.deepEqual(await getCapabilities(), { local: false });
  } finally {
    globalThis.fetch = oldFetch;
  }
});

test('fetchSubscription posts the identity to the same-origin bridge', async () => {
  const calls = [];
  const oldFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    return new Response(JSON.stringify({ status: 206, contentType: 'text/plain', headers: {}, text: 'partial' }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
  try {
    const result = await fetchSubscription('https://panel.example/sub', {
      identity: { hwid: 'abcdefghij', deviceOs: 'Android', userAgent: 'Happ/2' },
    });
    assert.equal(result.status, 206);
    assert.equal(calls[0].url, '/api/subscription');
    assert.equal(calls[0].init.method, 'POST');
    assert.deepEqual(JSON.parse(calls[0].init.body), {
      url: 'https://panel.example/sub',
      identity: { hwid: 'abcdefghij', deviceOs: 'Android', userAgent: 'Happ/2' },
    });
  } finally {
    globalThis.fetch = oldFetch;
  }
});

test('client exports capabilities and official encryption calls', async () => {
  const calls = [];
  const oldFetch = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ url, init });
    const body = url === '/api/capabilities' ? { local: true } : { link: 'happ://crypt5/test' };
    return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  try {
    assert.deepEqual(await getCapabilities(), { local: true });
    assert.deepEqual(await encryptOfficial('https://panel.example/sub'), { link: 'happ://crypt5/test' });
    assert.equal(calls[0].url, '/api/capabilities');
    assert.equal(calls[1].url, '/api/encrypt');
    assert.equal(JSON.parse(calls[1].init.body).url, 'https://panel.example/sub');
  } finally {
    globalThis.fetch = oldFetch;
  }
});

test('client deadline aborts a hanging bridge request', async () => {
  const oldFetch = globalThis.fetch;
  globalThis.fetch = (_url, { signal }) => new Promise((resolve, reject) => {
    signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })));
  });
  try {
    await assert.rejects(fetchSubscription('https://panel.example/sub', { timeoutMs: 10 }), /aborted|timeout/i);
  } finally {
    globalThis.fetch = oldFetch;
  }
});

test('public routes build targets and forward identity headers', async () => {
  const calls = [];
  const original = globalThis.fetch;
  globalThis.fetch = async (url, init) => { calls.push([String(url), init]); return new Response('ok', { headers: { 'content-type': 'text/plain' } }); };
  try {
    await fetchSubscription('https://panel.example/sub', { identity: { hwid: 'abcdefghij' }, route: 'corsfix' });
    assert.equal(calls[0][0], 'https://proxy.corsfix.com/?https://panel.example/sub');
    assert.equal(calls[0][1].headers['x-hwid'], 'abcdefghij');
    await fetchSubscription('https://panel.example/sub', { identity: {}, route: 'custom', customProxy: 'https://p.example/?url={url}' });
    assert.equal(calls[1][0], 'https://p.example/?url=' + encodeURIComponent('https://panel.example/sub'));
    await assert.rejects(fetchSubscription('https://panel.example/sub', { route: 'custom', customProxy: '' }), /proxy address/i);
  } finally { globalThis.fetch = original; }
});
