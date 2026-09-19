/** Validate without URL serialization, which could invalidate signed query bytes. */
export function validateUrl(url) {
  if (typeof url !== 'string' || !/^https?:\/\//i.test(url) || /[\s\x00-\x1f\x7f-\x9f\\]/.test(url)) {
    throw new Error('expected an http(s) URL without whitespace or control characters');
  }
  const parsed = new URL(url);
  if (!parsed.hostname || parsed.username || parsed.password || /^https?:\/\/[^/?#]*@/i.test(url)) {
    throw new Error('URL must have a host and must not contain credentials');
  }
  return url;
}

/** Return the literal URL or an untouched encrypted payload for the decryptor. */
export function parseInput(raw) {
  const input = String(raw ?? '');
  if (!input) throw new Error('empty input');
  const crypt = /^(?:happ:\/\/)?(crypt[2-5]?)\/(.+)$/s.exec(input);
  if (crypt) return { kind: crypt[1], payload: crypt[2] };
  const prefix = 'v2raytun://import/';
  const url = input.startsWith(prefix) ? input.slice(prefix.length) : input;
  return { kind: 'url', url: validateUrl(url) };
}

function editParam(url, key, value) {
  validateUrl(url);
  key = String(key);
  const hashAt = url.indexOf('#');
  const hash = hashAt < 0 ? '' : url.slice(hashAt);
  const beforeHash = hashAt < 0 ? url : url.slice(0, hashAt);
  const queryAt = beforeHash.indexOf('?');
  const base = queryAt < 0 ? beforeHash : beforeHash.slice(0, queryAt);
  const parts = queryAt < 0 ? [] : beforeHash.slice(queryAt + 1).split('&');
  const matches = (part) => [...new URLSearchParams(part).keys()][0] === key;
  const matching = parts.filter(matches);
  if (value === undefined && !matching.length) return url;
  if (value !== undefined && matching.length === 1 && new URLSearchParams(matching[0]).get(key) === String(value)) return url;
  const replacement = value === undefined ? null : new URLSearchParams([[key, String(value)]]).toString();
  let inserted = false;
  const edited = parts.flatMap((part) => {
    if (!matches(part)) return [part];
    if (replacement === null || inserted) return [];
    inserted = true;
    return [replacement];
  });
  if (replacement !== null && !inserted) edited.push(replacement);
  return base + (edited.length ? `?${edited.join('&')}` : '') + hash;
}

export function withParam(url, key, value) {
  return editParam(url, key, String(value));
}

export function withoutParam(url, key) {
  return editParam(url, key, undefined);
}

const HWID_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

/** Random test identifier only: not a hardware identity or device attestation. */
export function generateHwid(length = 16) {
  if (!Number.isInteger(length) || length < 10 || length > 64) throw new Error('test ID length must be an integer from 10 to 64');
  let out = '';
  const bytes = new Uint8Array(length);
  const limit = 256 - 256 % HWID_ALPHABET.length;
  while (out.length < length) {
    globalThis.crypto.getRandomValues(bytes);
    for (const byte of bytes) {
      if (byte < limit) out += HWID_ALPHABET[byte % HWID_ALPHABET.length];
      if (out.length === length) break;
    }
  }
  return out;
}

export function isValidHwid(value) {
  return typeof value === 'string' && /^[A-Za-z0-9=-]{10,64}$/.test(value);
}

/** Arbitrary random test seed, not an app-issued seed or crypt5 salt. */
export function generateSeed() {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(8));
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}
