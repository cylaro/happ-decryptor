import assert from 'node:assert/strict';
import test from 'node:test';

import {
  parseInput,
  withParam,
  withoutParam,
  generateHwid,
  isValidHwid,
  generateSeed,
} from '../src/lib/linkedit.js';

test('parses crypt links by kind and payload', () => {
  assert.deepEqual(parseInput('happ://crypt5/AbC'), { kind: 'crypt5', payload: 'AbC' });
  assert.deepEqual(parseInput('happ://crypt/AbC'), { kind: 'crypt', payload: 'AbC' });
  assert.deepEqual(parseInput('crypt2/AbC'), { kind: 'crypt2', payload: 'AbC' });
});

test('parses plain http(s) URLs', () => {
  assert.deepEqual(parseInput('https://sub.example.com/x?y=1'), {
    kind: 'url',
    url: 'https://sub.example.com/x?y=1',
  });
});

test('rejects junk input', () => {
  assert.throws(() => parseInput('hello world, this is not a link'));
  assert.throws(() => parseInput('https://user:password@example.com/sub'));
  assert.throws(() => parseInput('https://example.com/sub\nX-Injected: yes'));
});

test('adds a query param to a URL without a query', () => {
  assert.equal(withParam('https://a.example/sub', 'hwid', 'abc'), 'https://a.example/sub?hwid=abc');
});

test('adds a query param preserving existing ones', () => {
  assert.equal(
    withParam('https://a.example/sub?x=1', 'hwid', 'abc'),
    'https://a.example/sub?x=1&hwid=abc',
  );
});

test('replaces an existing param value', () => {
  assert.equal(
    withParam('https://a.example/sub?hwid=old&x=1', 'hwid', 'new'),
    'https://a.example/sub?hwid=new&x=1',
  );
});

test('encodes special characters in values', () => {
  const out = withParam('https://a.example/sub', 'ua', 'Happ/1.0 (iOS; a&b)');
  assert.equal(new URL(out).searchParams.get('ua'), 'Happ/1.0 (iOS; a&b)');
});

test('removes a param and keeps the rest', () => {
  assert.equal(
    withoutParam('https://a.example/sub?hwid=abc&x=1', 'hwid'),
    'https://a.example/sub?x=1',
  );
});

test('removing an absent param preserves literal URL bytes', () => {
  const url = 'https://a.example/sub?x=%2F&y=1';
  assert.equal(withoutParam(url, 'missing'), url);
});

test('generated HWIDs satisfy the Remnawave rule', () => {
  const seen = new Set();
  for (let i = 0; i < 200; i++) {
    const hwid = generateHwid();
    assert.ok(isValidHwid(hwid), hwid);
    seen.add(hwid);
  }
  assert.ok(seen.size > 190);
});

test('HWID generation validates length and uses only alphanumeric characters', () => {
  assert.match(generateHwid(10), /^[A-Za-z0-9]{10}$/);
  assert.throws(() => generateHwid(9));
  assert.throws(() => generateHwid(65));
  assert.ok(isValidHwid('abcdefghij='));
});

test('HWID validation follows the 10-64 char rule', () => {
  assert.ok(isValidHwid('abcdefghij'));
  assert.ok(!isValidHwid('short'));
  assert.ok(!isValidHwid('has space!!'));
});

test('generated seeds are 16 hex chars', () => {
  assert.match(generateSeed(), /^[0-9a-f]{16}$/);
});
