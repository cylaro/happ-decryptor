import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { decryptCrypt5Direct } from '../src/crypt5.js';
import { encryptCrypt5 } from '../src/lib/crypt5encrypt.js';
import { encryptCryptLegacy, decryptCryptLegacy } from '../src/lib/legacy.js';

const keytable = JSON.parse(
  await readFile(new URL('../public/data/crypt5-keys.json', import.meta.url), 'utf8'),
);
const MARKER = Object.keys(keytable)[0];
const TARGET = 'https://example.com/sub?hwid=abc123#test';
const PREFIX = 'happ://crypt5/';
const nonce = new TextEncoder().encode('abcdefghijkl');
const salt = Uint8Array.from({ length: 8 }, (_, i) => 0x41 + i);
const key = Uint8Array.from({ length: 32 }, (_, i) => 0x11 + i);

test('crypt5 legacy layout roundtrip', () => {
  const link = encryptCrypt5(TARGET, keytable, { marker: MARKER, nonce, salt: null, key });
  assert.ok(link.startsWith(PREFIX));
  assert.equal(decryptCrypt5Direct(link.slice(PREFIX.length), keytable), TARGET);
});

test('crypt5 salted layout roundtrip with seed', () => {
  const link = encryptCrypt5(TARGET, keytable, { marker: MARKER, nonce, salt, key });
  assert.ok(link.startsWith(PREFIX));
  assert.equal(decryptCrypt5Direct(link.slice(PREFIX.length), keytable), TARGET);
});

test('crypt5 encrypted with random options decrypts back', () => {
  const link = encryptCrypt5(TARGET, keytable, {});
  assert.ok(link.startsWith(PREFIX));
  assert.equal(decryptCrypt5Direct(link.slice(PREFIX.length), keytable), TARGET);
});

test('crypt5 defaults use URI-safe printable nonce and salt bytes', () => {
  const link = encryptCrypt5(TARGET, keytable, {});
  const payload = link.slice(PREFIX.length);
  assert.match(payload, /^[\x21-\x7e]+$/);
  assert.equal(decryptCrypt5Direct(payload, keytable), TARGET);
});

test('crypt5 rejects explicit non-printable nonce and salt', () => {
  assert.throws(() => encryptCrypt5(TARGET, keytable, {
    marker: MARKER,
    nonce: Uint8Array.from({ length: 12 }, () => 0),
    salt,
    key,
  }));
  assert.throws(() => encryptCrypt5(TARGET, keytable, {
    marker: MARKER,
    nonce,
    salt: Uint8Array.from({ length: 8 }, () => 0),
    key,
  }));
});

test('crypt5 rejects markers missing from the keytable', () => {
  assert.throws(() => encryptCrypt5(TARGET, keytable, { marker: 'zzzzzzzz' }));
});

test('crypt5 ciphertext is non-deterministic for fresh keys', () => {
  const a = encryptCrypt5(TARGET, keytable, {});
  const b = encryptCrypt5(TARGET, keytable, {});
  assert.notEqual(a, b);
});

test('tampered crypt5 link fails authentication', () => {
  const link = encryptCrypt5(TARGET, keytable, {});
  const payload = link.slice(PREFIX.length);
  const tampered = payload.slice(0, 300) + (payload[300] === 'A' ? 'B' : 'A') + payload.slice(301);
  assert.throws(() => decryptCrypt5Direct(tampered, keytable));
});

const LEGACY = [
  ['crypt', 0],
  ['crypt2', 1],
  ['crypt3', 2],
  ['crypt4', 3],
];

for (const [scheme, ordinal] of LEGACY) {
  test(`${scheme} encryption roundtrip`, async () => {
    const link = encryptCryptLegacy(ordinal, TARGET);
    assert.ok(link.startsWith(`happ://${scheme}/`));
    assert.equal(await decryptCryptLegacy(ordinal, link.slice(8 + scheme.length)), TARGET);
  });
}
