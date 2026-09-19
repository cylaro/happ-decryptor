import dns from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';

const MAX_REQUEST_BYTES = 16 * 1024;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 15_000;
const OFFICIAL_ENCRYPT_URL = 'https://crypto.happ.su/api-v2.php';

function jsonResponse(res, status, value) {
  const body = JSON.stringify(value);
  res.statusCode = status;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  res.end(body);
}

function isLoopbackAddress(address) {
  if (!address) return false;
  address = address.replace(/^\[|\]$/g, '');
  const normalized = address.startsWith('::ffff:') ? address.slice(7) : address;
  if (net.isIP(normalized) === 4) return normalized === '127.0.0.1';
  return normalized === '::1';
}

function requestHostIsLoopback(req) {
  const host = String(req.headers?.host ?? '').trim();
  if (!host || /[\s/@?#]/.test(host)) return false;
  let hostname;
  try {
    hostname = new URL(`http://${host}`).hostname;
  } catch {
    return false;
  }
  return isLoopbackAddress(hostname);
}

function originMatchesLoopback(req) {
  const origin = req.headers?.origin;
  if (!origin) return req.method === 'GET';
  let parsed;
  try {
    parsed = new URL(origin);
  } catch {
    return false;
  }
  if (origin !== parsed.origin || !['http:', 'https:'].includes(parsed.protocol) || !isLoopbackAddress(parsed.hostname)) {
    return false;
  }
  const host = String(req.headers?.host ?? '').toLowerCase();
  const originHost = parsed.port ? `${parsed.hostname}:${parsed.port}` : parsed.hostname;
  return host === originHost.toLowerCase();
}

function requestIsLocal(req) {
  const metadata = String(req.headers?.['sec-fetch-site'] ?? '').toLowerCase();
  return isLoopbackAddress(req.socket?.remoteAddress) && requestHostIsLoopback(req) &&
    originMatchesLoopback(req) && !['cross-site', 'same-site'].includes(metadata);
}

function parseIPv4(value) {
  if (net.isIP(value) !== 4) return null;
  const parts = value.split('.').map(Number);
  return (((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3]) >>> 0;
}

function parseIPv6(value) {
  if (net.isIP(value) !== 6) return null;
  const mapped = value.toLowerCase().match(/^(.*):ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return { mapped: parseIPv4(mapped[2]) };
  const halves = value.toLowerCase().split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if (halves.length === 1 && missing !== 0 || halves.length === 2 && missing < 1) return null;
  const words = [...left, ...Array.from({ length: missing }, () => '0'), ...right];
  if (words.length !== 8 || words.some((part) => !/^[0-9a-f]{1,4}$/.test(part))) return null;
  let number = 0n;
  for (const word of words) number = (number << 16n) | BigInt(`0x${word}`);
  return { number };
}

function isPublicAddress(address) {
  const ipv4 = parseIPv4(address);
  if (ipv4 !== null) {
    const first = ipv4 >>> 24;
    const second = (ipv4 >>> 16) & 255;
    const third = (ipv4 >>> 8) & 255;
    const blocked = address === '168.63.129.16' || first === 0 || first === 10 || first === 127 || first >= 224 ||
      first === 100 && second >= 64 && second <= 127 ||
      first === 169 && second === 254 ||
      first === 172 && second >= 16 && second <= 31 ||
      first === 192 && second === 0 && third === 0 ||
      first === 192 && second === 0 && third === 2 ||
      first === 192 && second === 88 && third === 99 ||
      first === 192 && second === 168 ||
      first === 198 && second === 18 || first === 198 && second === 19 ||
      first === 198 && second === 51 && third === 100 ||
      first === 203 && second === 0 && third === 113;
    return !blocked;
  }
  const ipv6 = parseIPv6(address);
  if (!ipv6) return false;
  if ('mapped' in ipv6) return isPublicAddress(
    `${ipv6.mapped >>> 24}.${ipv6.mapped >>> 16 & 255}.${ipv6.mapped >>> 8 & 255}.${ipv6.mapped & 255}`,
  );
  const n = ipv6.number;
  const first = Number(n >> 120n);
  const second = Number((n >> 112n) & 255n);
  return (first & 0xe0) === 0x20 &&
    !(first === 0x20 && [0x01, 0x02].includes(second)) &&
    !(first === 0x3f && second === 0xff);
}

function assertSafeHeaderValue(name, value) {
  if (value === undefined || value === null || value === '') return;
  if (typeof value !== 'string' || value.length > 1024 || /[\r\n]/.test(value)) {
    throw new Error(`invalid ${name} header`);
  }
}

export function buildIdentityHeaders(identity = {}) {
  if (!identity || typeof identity !== 'object' || Array.isArray(identity)) throw new Error('identity must be an object');
  const { hwid, deviceOs, verOs, deviceModel, userAgent } = identity;
  if (hwid !== undefined && hwid !== '' && (typeof hwid !== 'string' || !/^[A-Za-z0-9=-]{10,64}$/.test(hwid))) {
    throw new Error('invalid x-hwid header');
  }
  assertSafeHeaderValue('x-device-os', deviceOs);
  assertSafeHeaderValue('x-ver-os', verOs);
  assertSafeHeaderValue('x-device-model', deviceModel);
  assertSafeHeaderValue('User-Agent', userAgent);
  const headers = {};
  if (hwid) headers['x-hwid'] = hwid;
  if (deviceOs) headers['x-device-os'] = deviceOs;
  if (verOs) headers['x-ver-os'] = verOs;
  if (deviceModel) headers['x-device-model'] = deviceModel;
  if (userAgent) headers['User-Agent'] = userAgent;
  return headers;
}

function raceSignal(promise, signal) {
  if (!signal) return promise;
  if (signal.aborted) return Promise.reject(new Error('request timed out'));
  return new Promise((resolve, reject) => {
    const abort = () => reject(new Error('request timed out'));
    signal.addEventListener('abort', abort, { once: true });
    promise.then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
  });
}

async function readBody(req, signal) {
  const length = Number(req.headers?.['content-length']);
  if (Number.isFinite(length) && length > MAX_REQUEST_BYTES) throw Object.assign(new Error('request body too large'), { status: 413 });
  return raceSignal(new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let settled = false;
    req.on('data', (chunk) => {
      if (settled) return;
      size += chunk.length;
      if (size > MAX_REQUEST_BYTES) {
        settled = true;
        reject(Object.assign(new Error('request body too large'), { status: 413 }));
      }
      else chunks.push(chunk);
    });
    req.on('end', () => { if (!settled) { settled = true; resolve(Buffer.concat(chunks).toString('utf8')); } });
    req.on('error', reject);
  }), signal);
}

async function resolvePublicUrl(value, resolve) {
  if (typeof value !== 'string' || value.length > 8192) throw new Error('invalid destination URL');
  let parsed;
  try { parsed = new URL(value); } catch { throw new Error('invalid destination URL'); }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || !parsed.hostname) {
    throw new Error('destination must be a public http(s) URL without credentials');
  }
  const hostname = parsed.hostname.replace(/^\[|\]$/g, '');
  const literal = net.isIP(hostname);
  const records = literal ? [{ address: hostname, family: literal }] : await resolve(hostname);
  if (!Array.isArray(records) || records.length === 0 || records.some((record) => !isPublicAddress(record.address))) {
    throw new Error('destination resolves to a private or unsafe address');
  }
  return { parsed, records };
}

export function requestUpstream(target, options = {}, transports = {}) {
  const parsed = new URL(target);
  const transport = transports[parsed.protocol === 'https:' ? 'httpsRequest' : 'httpRequest'] ?? (parsed.protocol === 'https:' ? https.request : http.request);
  return new Promise((resolve, reject) => {
    const request = transport(parsed, {
      method: options.method ?? 'GET',
      headers: options.headers,
      agent: false,
      lookup(_hostname, lookupOptions, callback) {
        if (lookupOptions.all) return callback(null, options.records);
        const record = options.records.find((entry) => !lookupOptions.family || entry.family === lookupOptions.family) ?? options.records[0];
        callback(null, record.address, record.family);
      },
    }, (response) => {
      const chunks = [];
      let size = 0;
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_RESPONSE_BYTES) {
          request.destroy(new Error('upstream response too large'));
          return;
        }
        chunks.push(chunk);
      });
      response.on('end', () => resolve({ status: response.statusCode ?? 502, headers: Object.fromEntries(Object.entries(response.headers).map(([key, value]) => [key, Array.isArray(value) ? value.join(', ') : String(value ?? '')])), text: Buffer.concat(chunks).toString('utf8') }));
    });
    request.on('error', reject);
    if (options.signal) options.signal.addEventListener('abort', () => request.destroy(new Error('request timed out')), { once: true });
    if (options.body) request.write(options.body);
    request.end();
  });
}

const defaultOutbound = (target, options) => requestUpstream(target, options);

function parseOfficialLink(text) {
  let value;
  try { value = JSON.parse(text)?.encrypted_link; } catch { value = text.trim(); }
  if (typeof value !== 'string' || !/^happ:\/\/crypt5\/\S+$/.test(value)) throw new Error('official service returned no encrypted link');
  return value;
}

export function createBridgeHandler({ outbound = defaultOutbound, resolve = (hostname) => dns.lookup(hostname, { all: true, verbatim: true }), timeoutMs = REQUEST_TIMEOUT_MS } = {}) {
  return async function bridgeHandler(req, res, next = () => {}) {
    if (!req.url?.startsWith('/api/')) return next();
    if (!requestIsLocal(req)) return jsonResponse(res, 403, { error: 'loopback request required' });
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      if (req.method === 'GET' && req.url === '/api/capabilities') return jsonResponse(res, 200, { local: true });
      if (req.method !== 'POST' || !['/api/subscription', '/api/encrypt'].includes(req.url)) return jsonResponse(res, 404, { error: 'not found' });
      if (!String(req.headers?.['content-type'] ?? '').toLowerCase().startsWith('application/json')) return jsonResponse(res, 415, { error: 'application/json required' });
      const payload = JSON.parse(await readBody(req, controller.signal));
      if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('invalid request object');
      const resolved = await raceSignal(resolvePublicUrl(payload.url, resolve), controller.signal);
      async function send(target, options) {
        let result;
        try { result = await raceSignal(outbound(target, options), controller.signal); }
        catch { throw Object.assign(new Error(controller.signal.aborted ? 'request timed out' : 'upstream request failed'), { status: controller.signal.aborted ? 504 : 502 }); }
        if (Buffer.byteLength(result.text) > MAX_RESPONSE_BYTES) throw Object.assign(new Error('upstream response too large'), { status: 502 });
        return result;
      }
      let upstream;
      if (req.url === '/api/subscription') {
        upstream = await send(resolved.parsed.href, {
          method: 'GET', headers: buildIdentityHeaders(payload.identity), records: resolved.records, signal: controller.signal,
        });
        if (upstream.status >= 300 && upstream.status < 400) throw Object.assign(new Error('upstream redirects are rejected'), { status: 400 });
        return jsonResponse(res, 200, { status: upstream.status, contentType: upstream.headers['content-type'] ?? '', headers: upstream.headers, text: upstream.text });
      }
      const official = await raceSignal(resolvePublicUrl(OFFICIAL_ENCRYPT_URL, resolve), controller.signal);
      upstream = await send(official.parsed.href, {
        method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify({ url: resolved.parsed.href }), records: official.records, signal: controller.signal,
      });
      if (upstream.status >= 300 && upstream.status < 400) throw Object.assign(new Error('official service redirect rejected'), { status: 502 });
      if (upstream.status < 200 || upstream.status >= 300) throw Object.assign(new Error(`official service HTTP ${upstream.status}`), { status: 502 });
      try { return jsonResponse(res, 200, { link: parseOfficialLink(upstream.text) }); }
      catch { throw Object.assign(new Error('official service returned no encrypted link'), { status: 502 }); }
    } catch (error) {
      const status = error?.status ?? (controller.signal.aborted ? 504 : error?.message?.includes('upstream') ? 502 : 400);
      return jsonResponse(res, status, { error: error?.message || 'bridge request failed' });
    } finally {
      clearTimeout(timer);
    }
  };
}

export function bridgePlugin() {
  return {
    name: 'happ-local-request-bridge',
    configureServer(server) { server.middlewares.use(createBridgeHandler()); },
    configurePreviewServer(server) { server.middlewares.use(createBridgeHandler()); },
  };
}
