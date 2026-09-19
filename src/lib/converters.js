/** Data encodings, not translators between proxy client configurations. */
import { validateUrl } from './linkedit.js';

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true });

export function toBase64(text) {
  const bytes = textEncoder.encode(text);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function fromBase64(text) {
  const input = String(text).trim();
  if (!/^[A-Za-z0-9+/_-]*={0,2}$/.test(input)) throw new Error('invalid base64');
  const clean = input.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  const padded = clean + '='.repeat((4 - clean.length % 4) % 4);
  if (input.includes('=') && input.length !== padded.length) throw new Error('invalid base64 padding');
  const binary = atob(padded);
  if (btoa(binary).replace(/=+$/, '') !== clean) throw new Error('invalid base64 encoding');
  return textDecoder.decode(Uint8Array.from(binary, (char) => char.charCodeAt(0)));
}

// https://docs.v2raytun.com/deep-link: v2raytun://import/{subscription_link}
// Unverified Happ add, Clash, Mihomo and Sing-box wrappers are intentionally omitted.
export const SUPPORTED_CLIENTS = Object.freeze([
  Object.freeze({ id: 'v2raytun', label: 'v2RayTun', source: 'https://docs.v2raytun.com/deep-link' }),
]);

export function generateImportLink(client, url, name = '') {
  validateUrl(url);
  if (client !== 'v2raytun') throw new Error(`unsupported import client: ${client}`);
  if (name) throw new Error('v2RayTun import links do not have a documented name parameter');
  return `v2raytun://import/${url}`;
}

// Syntactic URI-list data only; no claim that a client accepts each node's options.
const URI_RE = /^(?:vless|vmess|ss|socks|trojan|hysteria2|hy2):\/\/[^\s<>\x00-\x1f\x7f]+$/i;

function validateUriList(uris) {
  if (!Array.isArray(uris) || !uris.length || uris.some((uri) => typeof uri !== 'string' || !URI_RE.test(uri))) {
    throw new Error('expected a non-empty array of proxy URI strings (data, not client configs)');
  }
  return uris;
}

export function toBase64Subscription(uriList) {
  return toBase64(validateUriList(uriList).join('\n'));
}

export function fromBase64Subscription(encoded) {
  return validateUriList(fromBase64(encoded).split(/\r?\n/).map((line) => line.trim()).filter(Boolean));
}

/** A JSON array of URI strings is data, NOT an Xray JSON configuration. */
export function uriListToJson(uriList) {
  return JSON.stringify(validateUriList(uriList), null, 2);
}

export function jsonToUriList(json) {
  return validateUriList(JSON.parse(json));
}

/** Formats: uri-list, base64-list, json-uri-array (data), json, unknown. */
export function detectSubscriptionContent(raw) {
  const text = String(raw ?? '');
  const trimmed = text.trim();
  if (!trimmed || trimmed.startsWith('<')) return { format: 'unknown', text };
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const json = JSON.parse(trimmed);
      if (Array.isArray(json) && json.length && json.every((entry) => typeof entry === 'string' && URI_RE.test(entry))) {
        return { format: 'json-uri-array', uris: json, text };
      }
      return { format: 'json', text };
    } catch {
      return { format: 'unknown', text };
    }
  }
  const lines = trimmed.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (lines.every((line) => URI_RE.test(line))) return { format: 'uri-list', uris: lines, text };
  try {
    const uris = fromBase64Subscription(trimmed);
    return { format: 'base64-list', uris, text: fromBase64(trimmed) };
  } catch {
    return { format: 'unknown', text };
  }
}

/** JSON means pretty-print supplied JSON, never manufacture an Xray config. */
export function convertContent(raw, format) {
  const detected = detectSubscriptionContent(raw);
  if (!['text', 'base64', 'json'].includes(format)) throw new Error(`unsupported output format: ${format}`);
  if (detected.format === 'unknown') throw new Error('unrecognized subscription data or malformed JSON');
  if (format === 'text') {
    return detected.format === 'json-uri-array' ? detected.uris.join('\n') : detected.text;
  }
  if (format === 'base64') {
    if (!detected.uris) throw new Error('base64 conversion requires URI-list data, not a JSON config');
    return toBase64Subscription(detected.uris);
  }
  if (detected.format !== 'json' && detected.format !== 'json-uri-array') {
    throw new Error('URI-to-JSON config translation is not supported; supply JSON to pretty-print');
  }
  return JSON.stringify(JSON.parse(String(raw)), null, 2);
}
