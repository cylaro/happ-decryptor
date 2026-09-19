import assert from 'node:assert/strict';
import test from 'node:test';

import {
  toBase64,
  fromBase64,
  generateImportLink,
  SUPPORTED_CLIENTS,
  toBase64Subscription,
  fromBase64Subscription,
  uriListToJson,
  jsonToUriList,
  detectSubscriptionContent,
  convertContent,
} from '../src/lib/converters.js';

test('base64 roundtrips unicode text', () => {
  const text = 'https://example.com/?q=привет ✔';
  assert.equal(fromBase64(toBase64(text)), text);
});

test('supported client list contains only evidenced clients', () => {
  assert.deepEqual(SUPPORTED_CLIENTS.map(({ id }) => id), ['v2raytun']);
  assert.ok(SUPPORTED_CLIENTS.every(({ id, label }) => id && label));
});

test('v2raytun import uses the documented raw subscription URL', () => {
  assert.equal(
    generateImportLink('v2raytun', 'https://a.b/c?x=1#literal'),
    'v2raytun://import/https://a.b/c?x=1#literal',
  );
});

test('unverified client wrappers are rejected', () => {
  assert.throws(() => generateImportLink('happ', 'https://a.b/c'));
  assert.throws(() => generateImportLink('mihomo', 'https://a.b/c'));
});

test('base64 subscription encodes and decodes URI lists', () => {
  const list = ['vless://a-uuid@host:443?x=1#Node1', 'ss://b#Node2'];
  const encoded = toBase64Subscription(list);
  assert.equal(encoded, Buffer.from(list.join('\n'), 'utf8').toString('base64'));
  assert.deepEqual(fromBase64Subscription(encoded), list);
});

test('URI list converts to JSON and back', () => {
  const list = ['vless://a#One', 'trojan://b#Two'];
  const json = uriListToJson(list);
  assert.deepEqual(JSON.parse(json), list);
  assert.deepEqual(jsonToUriList(json), list);
});

test('JSON conversion preserves supplied JSON and does not invent configs', () => {
  const supplied = '{"outbounds":[{"protocol":"freedom"}]}';
  assert.equal(convertContent(supplied, 'json'), JSON.stringify(JSON.parse(supplied), null, 2));
  assert.throws(() => convertContent('vless://a#One', 'json'));
});

test('detects base64-encoded subscription content', () => {
  const encoded = Buffer.from('vless://a#One\nvless://b#Two', 'utf8').toString('base64');
  const detected = detectSubscriptionContent(encoded);
  assert.equal(detected.format, 'base64-list');
  assert.deepEqual(detected.uris, ['vless://a#One', 'vless://b#Two']);
});

test('detects a plain URI list', () => {
  const detected = detectSubscriptionContent('vless://a#One\nss://b#Two\n');
  assert.equal(detected.format, 'uri-list');
  assert.deepEqual(detected.uris, ['vless://a#One', 'ss://b#Two']);
});

test('flags non-subscription content as unknown', () => {
  assert.equal(detectSubscriptionContent('<!DOCTYPE html><html></html>').format, 'unknown');
  assert.equal(detectSubscriptionContent('<html><body>login</body></html>').format, 'unknown');
  assert.equal(detectSubscriptionContent('{"broken":').format, 'unknown');
});

test('content conversion has explicit text and base64 contracts', () => {
  const text = 'vless://a#One\nss://b#Two\n';
  assert.equal(convertContent(text, 'text'), text);
  const encoded = convertContent(text, 'base64');
  assert.deepEqual(fromBase64(encoded).split('\n'), ['vless://a#One', 'ss://b#Two']);
  assert.throws(() => convertContent('<html>not data</html>', 'base64'));
});
