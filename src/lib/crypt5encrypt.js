/**
 * Experimental local inverse of src/crypt5.js, NOT verified in the Happ app.
 *
 * The outer container is a raw byte string (not base64): marker(4) + body +
 * marker(4), passed through the ABCD->CDAB swap. The 12-byte nonce and the
 * 8-byte salt live inside that string, so both use URI-unreserved characters to
 * keep the emitted link round-trippable through the browser text pipeline.
 */

import forge from 'node-forge';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';

const textEncoder = new TextEncoder();

function asciiRandom(length) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  return globalThis.crypto.getRandomValues(new Uint8Array(length)).map((byte) => alphabet.charCodeAt(byte & 63));
}

function assertAsciiSafe(bytes, name) {
  if (!(bytes instanceof Uint8Array)) throw new Error(`crypt5 ${name} must be a Uint8Array`);
  for (const byte of bytes) {
    if (!/[A-Za-z0-9._~-]/.test(String.fromCharCode(byte))) throw new Error(`crypt5 ${name} must contain only URI-safe printable bytes (A-Z, a-z, 0-9, . _ ~ -)`);
  }
}

function bytesToB64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function latinToBytes(str) {
  const out = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) out[i] = str.charCodeAt(i) & 0xff;
  return out;
}

function bytesToLatin(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
  return out;
}

/** ABCD -> BADC for every complete two-byte pair (self-inverse). */
function swapAdjacent(bytes) {
  const result = bytes.slice();
  for (let i = 0; i + 1 < result.length; i += 2) {
    [result[i], result[i + 1]] = [result[i + 1], result[i]];
  }
  return result;
}

/** ABCD -> CDAB for every complete four-byte block (self-inverse). */
function swapBlockHalves(bytes) {
  const result = bytes.slice();
  const fullLength = result.length - (result.length % 4);
  for (let i = 0; i < fullLength; i += 4) {
    [result[i], result[i + 2]] = [result[i + 2], result[i]];
    [result[i + 1], result[i + 3]] = [result[i + 3], result[i + 1]];
  }
  return result;
}

const _keyCache = new Map();

function loadPrivateKey(keytable, marker) {
  const keyBase64 = keytable[marker];
  if (!Object.hasOwn(keytable, marker) || typeof keyBase64 !== 'string' || !keyBase64) throw new Error(`unknown crypt5 marker: ${marker}`);
  let privateKey = _keyCache.get(keyBase64);
  if (privateKey) return privateKey;
  const lines = keyBase64.match(/.{1,64}/g);
  const pem = `-----BEGIN PRIVATE KEY-----\n${lines.join('\n')}\n-----END PRIVATE KEY-----`;
  privateKey = forge.pki.privateKeyFromPem(pem);
  _keyCache.set(keyBase64, privateKey);
  return privateKey;
}

function rsaEncryptLatin(privateKey, latinMessage) {
  const publicKey = forge.pki.setRsaPublicKey(privateKey.n, privateKey.e);
  return publicKey.encrypt(latinMessage, 'RSAES-PKCS1-V1_5');
}

/**
 * Build a happ://crypt5/ link for a target URL.
 * opts: { marker, nonce (12 bytes), salt (8 bytes or null), key (32 bytes) }
 * Defaults: CSPRNG marker, URI-safe nonce/salt and a full-entropy 32-byte key.
 * Local round-trip tests do not establish external client compatibility.
 */
export function encryptCrypt5(target, keytable, opts = {}) {
  const markers = Object.keys(keytable);
  if (markers.length === 0) throw new Error('crypt5 keytable is empty');

  let marker = opts.marker;
  if (marker === undefined) {
    const limit = 2 ** 32 - (2 ** 32 % markers.length);
    let random;
    do { random = globalThis.crypto.getRandomValues(new Uint32Array(1))[0]; } while (random >= limit);
    marker = markers[random % markers.length];
  }
  if (!/^[A-Za-z0-9._~-]{8}$/.test(marker)) throw new Error('crypt5 marker must contain eight URI-safe characters');
  const privateKey = loadPrivateKey(keytable, marker);

  const nonce = opts.nonce ?? asciiRandom(12);
  if (nonce.length !== 12) throw new Error('crypt5 nonce must be 12 bytes');
  assertAsciiSafe(nonce, 'nonce');

  const salt = opts.salt === undefined ? asciiRandom(8) : opts.salt;
  if (salt !== null && salt.length !== 8) throw new Error('crypt5 salt must be 8 bytes');
  if (salt) assertAsciiSafe(salt, 'salt');

  const rawKey = opts.key ?? globalThis.crypto.getRandomValues(new Uint8Array(32));
  if (!(rawKey instanceof Uint8Array) || rawKey.length !== 32) throw new Error('crypt5 key must be 32 bytes');

  const chachaKey = salt ? rawKey.map((byte, i) => byte ^ salt[i % salt.length]) : rawKey;
  const chacha = chacha20poly1305(chachaKey, nonce);

  const payloadText = bytesToB64(textEncoder.encode(target));
  const ciphertextText = bytesToB64(chacha.encrypt(swapAdjacent(textEncoder.encode(payloadText))));

  const keyLatin = bytesToLatin(swapAdjacent(textEncoder.encode(bytesToB64(rawKey))));
  const rsaText = bytesToB64(latinToBytes(rsaEncryptLatin(privateKey, keyLatin)));

  const digits = textEncoder.encode(String(ciphertextText.length));
  const head = salt ? [0x53, 0x45, ...salt] : [];
  const bodyLength = 12 + head.length + digits.length + 1 + ciphertextText.length + rsaText.length;
  const body = new Uint8Array(bodyLength);
  body.set(nonce, 0);
  body.set(head, 12);
  body.set(digits, 12 + head.length);
  body[12 + head.length + digits.length] = 0x21;
  body.set(textEncoder.encode(ciphertextText), 12 + head.length + digits.length + 1);
  body.set(textEncoder.encode(rsaText), 12 + head.length + digits.length + 1 + ciphertextText.length);

  const shuffled = new Uint8Array(4 + bodyLength + 4);
  shuffled.set(textEncoder.encode(marker.slice(0, 4)), 0);
  shuffled.set(body, 4);
  shuffled.set(textEncoder.encode(marker.slice(4)), 4 + bodyLength);

  return `happ://crypt5/${bytesToLatin(swapBlockHalves(shuffled))}`;
}
