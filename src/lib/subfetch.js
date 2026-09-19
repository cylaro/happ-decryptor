function assertHeaderValue(name, value) {
  if (value === undefined || value === null || value === '') return;
  if (typeof value !== 'string' || value.length > 1024 || /[\r\n]/.test(value)) throw new Error(`invalid ${name} header`);
}

/** Happ identity headers are preserved exactly; no device defaults are invented. */
export function buildHeaders({ hwid, deviceOs, verOs, deviceModel, userAgent } = {}) {
  if (hwid !== undefined && hwid !== '' && (typeof hwid !== 'string' || !/^[A-Za-z0-9=-]{10,64}$/.test(hwid))) throw new Error('invalid x-hwid header');
  assertHeaderValue('x-device-os', deviceOs);
  assertHeaderValue('x-ver-os', verOs);
  assertHeaderValue('x-device-model', deviceModel);
  assertHeaderValue('User-Agent', userAgent);
  const headers = {};
  if (hwid) headers['x-hwid'] = hwid;
  if (deviceOs) headers['x-device-os'] = deviceOs;
  if (verOs) headers['x-ver-os'] = verOs;
  if (deviceModel) headers['x-device-model'] = deviceModel;
  if (userAgent) headers['User-Agent'] = userAgent;
  return headers;
}

function withDeadline(signal, timeoutMs) {
  const controller = new AbortController();
  if (signal?.aborted) controller.abort();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const abort = () => controller.abort();
  signal?.addEventListener('abort', abort, { once: true });
  return { signal: controller.signal, cleanup: () => { clearTimeout(timer); signal?.removeEventListener('abort', abort); } };
}

async function postJson(path, body, { signal, timeoutMs = 15_000 } = {}) {
  const deadline = withDeadline(signal, timeoutMs);
  try {
    const response = await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), signal: deadline.signal });
    const result = await response.json();
    if (!response.ok) throw new Error(result?.error || `bridge request failed (${response.status})`);
    return result;
  } finally { deadline.cleanup(); }
}

/**
 * Request routes. Verified 2026-09: corsfix.com forwards x-hwid, x-device-os,
 * x-ver-os, x-device-model and answers CORS preflight; free dev tier ~60 rpm,
 * development origins only. Custom route accepts any CORS proxy template with
 * an optional {url} placeholder. Third-party routes see the subscription URL.
 */
export const REQUEST_ROUTES = Object.freeze([
  Object.freeze({ id: 'bridge', label: 'Мост (локальный сервер)' }),
  Object.freeze({ id: 'corsfix', label: 'corsfix.com (публичный, ~60/мин)', build: (url) => `https://proxy.corsfix.com/?${url}` }),
  Object.freeze({ id: 'custom', label: 'Свой прокси' }),
]);

function buildProxyTarget(route, customProxy, url) {
  if (route === 'corsfix') return `https://proxy.corsfix.com/?${url}`;
  const template = String(customProxy ?? '').trim();
    if (!template) throw new Error('specify your proxy address (optionally with {url})');
  return template.includes('{url}') ? template.replace('{url}', encodeURIComponent(url)) : template + url;
}

export async function fetchSubscription(url, { identity = {}, route = 'bridge', customProxy = '', signal, timeoutMs } = {}) {
  const headers = buildHeaders(identity);
  if (route === 'bridge') return postJson('/api/subscription', { url, identity }, { signal, timeoutMs });
  const target = buildProxyTarget(route, customProxy, url);
  const deadline = withDeadline(signal, timeoutMs ?? 15_000);
  try {
    const response = await fetch(target, { headers, signal: deadline.signal });
    return {
      status: response.status,
      contentType: response.headers.get('content-type') ?? '',
      headers: Object.fromEntries(response.headers.entries()),
      text: await response.text(),
    };
  } catch (error) {
    if (deadline.signal.aborted) throw new Error('request timed out');
    throw new Error(error?.name === 'AbortError' && signal?.aborted ? 'request cancelled' : 'прокси недоступен или заблокировал запрос (CORS/лимит)');
  } finally { deadline.cleanup(); }
}

export async function encryptOfficial(url, { signal, timeoutMs } = {}) {
  return postJson('/api/encrypt', { url }, { signal, timeoutMs });
}

export async function getCapabilities({ signal, timeoutMs } = {}) {
  const deadline = withDeadline(signal, timeoutMs ?? 5000);
  try {
    const response = await fetch('/api/capabilities', { signal: deadline.signal });
    if (!response.ok) return { local: false };
    try { return await response.json(); } catch { return { local: false }; }
  } catch (error) {
    if (error?.name === 'AbortError' && signal?.aborted) throw error;
    return { local: false };
  } finally { deadline.cleanup(); }
}
