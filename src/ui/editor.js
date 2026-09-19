import QRCode from 'qrcode';
import { parseInput, withParam, generateHwid, isValidHwid } from '../lib/linkedit.js';
import { toBase64, generateImportLink, detectSubscriptionContent } from '../lib/converters.js';
import { fetchSubscription, encryptOfficial, getCapabilities } from '../lib/subfetch.js';
import { copyText, showToast, t } from './util.js';

const $ = (id) => document.getElementById(id);

const IDENTITY_KEY = 'happ-identity';
const ROUTE_KEY = 'happ-request-route';
const CUSTOM_PROXY_KEY = 'happ-custom-proxy';
const IDENTITY_PAIRS = [
  ['request-hwid', 'id-hwid'], ['request-ua', 'id-ua'], ['request-os', 'id-os'],
  ['request-version', 'id-ver'], ['request-model', 'id-model'],
];
const identityFields = () => IDENTITY_PAIRS.flat().map($);
function saveIdentity() {
  try { localStorage.setItem(IDENTITY_KEY, JSON.stringify(Object.fromEntries(identityFields().map((f) => [f.id, f.value])))); } catch { /* storage is optional */ }
}
function restoreIdentity() {
  let saved;
  try { saved = JSON.parse(localStorage.getItem(IDENTITY_KEY) || 'null'); } catch { return; }
  if (!saved || typeof saved !== 'object') return;
  for (const [requestId, editorId] of IDENTITY_PAIRS) {
    const value = saved[requestId];
    if (typeof value === 'string') { $(requestId).value = value; $(editorId).value = value; }
  }
}

export function initEditor() {
  let validUrl = '';
  let local = false;
  let busy = false;
  let revision = 0;
  let qrRevision = 0;
  let requestController;
  let lastResponse = '';
  let responseAvailable = false;

  function status(id, message, kind = 'ok') {
    $(id).textContent = message;
    $(id).dataset.kind = kind;
  }

  function syncButtons() {
    $('encrypt').disabled = !local || !validUrl || !$('encrypt-consent').checked || busy;
    $('request-send').disabled = !!requestController || ($('request-route').value === 'bridge' && !local);
    $('copy-output').disabled = !$('output').value;
    $('qr-open').disabled = !$('output').value;
  }

  function validate(raw) {
    const parsed = parseInput(raw);
    if (parsed.kind !== 'url') throw new Error(t('Prepare the encrypted link first.', 'Сначала расшифруйте ссылку.'));
    return parsed.url;
  }

  function clearOutput() {
    $('output').value = '';
    $('qr').hidden = true;
    qrRevision++;
    syncButtons();
  }

  async function drawQr(value) {
    const version = ++qrRevision;
    try {
      const canvas = document.createElement('canvas');
      await QRCode.toCanvas(canvas, value, { width: 240, margin: 4, errorCorrectionLevel: 'M' });
      if (version !== qrRevision) return;
      const visible = $('qr-canvas');
      visible.width = canvas.width; visible.height = canvas.height;
      visible.getContext('2d').drawImage(canvas, 0, 0);
      $('qr').hidden = false;
    } catch {
      if (version === qrRevision) {
        $('qr').hidden = true;
        status('format-help', t('Too long for a QR code. Use Copy.', 'Слишком длинно для QR-кода. Используйте копирование.'), 'error');
      }
    }
  }

  function setOutput(value) {
    $('output').value = value;
    syncButtons();
    if (value) drawQr(value); else clearOutput();
  }

  function renderOutput() {
    clearOutput();
    if (!validUrl) return;
    const format = $('format').value;
    $('format-note').textContent = format.toUpperCase();
    const descriptions = {
      raw: t('Add the URL as a subscription in your client.', 'Добавьте URL как подписку в клиенте.'),
      v2raytun: t('Documented v2RayTun format: the subscription URL follows /import/.', 'Документированный формат v2RayTun: URL подписки после /import/.'),
      base64: t('Base64-encoded URL text.', 'URL в кодировке Base64.'),
      json: t('The URL as a JSON object.', 'URL в виде JSON-объекта.'),
      'happ-official': t('Use the consent checkbox and the official encryption button below.', 'Подтвердите передачу URL и нажмите кнопку официального шифрования ниже.'),
    };
    status('format-help', descriptions[format]);
    if (format === 'happ-official') return;
    const output = format === 'raw' ? validUrl : format === 'v2raytun'
      ? generateImportLink('v2raytun', validUrl) : format === 'base64'
        ? toBase64(validUrl) : JSON.stringify({ url: validUrl }, null, 2);
    setOutput(output);
  }

  function renderParams() {
    const container = $('params');
    container.replaceChildren();
    if (!validUrl) return;
    const entries = [...new URL(validUrl).searchParams];
    entries.forEach(([key, value], index) => {
      const row = document.createElement('div');
      row.className = 'param-row';
      const label = document.createElement('span'); label.textContent = key;
      const input = document.createElement('input');
      input.className = 'text-input'; input.value = value;
      input.setAttribute('aria-label', key);
      const remove = document.createElement('button');
      remove.className = 'secondary compact'; remove.type = 'button'; remove.textContent = '×';
      remove.setAttribute('aria-label', `${t('Remove', 'Удалить')} ${key}`);
      function change(deleting) {
        const url = new URL(validUrl);
        const current = [...url.searchParams];
        if (deleting) current.splice(index, 1); else current[index][1] = input.value;
        url.search = new URLSearchParams(current).toString();
        acceptUrl(url.href, false);
      }
      input.addEventListener('change', () => change(false));
      remove.addEventListener('click', () => change(true));
      row.append(label, input, remove); container.append(row);
    });
  }

  function acceptUrl(url, prepared) {
    validUrl = validate(url);
    revision++;
    $('destination').value = validUrl;
    $('request-url').value = validUrl;
    if (prepared) $('encrypt-consent').checked = false;
    renderParams(); renderOutput(); syncButtons();
  }

  function decrypt(raw) {
    return new Promise((resolve, reject) => {
      const worker = new Worker(new URL('./decrypt-worker.js', import.meta.url), { type: 'module' });
      const timer = setTimeout(() => finish(new Error(t('Decryption timed out (20s).', 'Время расшифровки истекло (20 с).'))), 20000);
      function finish(error, url) {
        clearTimeout(timer); worker.terminate();
        if (error) reject(error); else resolve(url);
      }
      worker.onmessage = ({ data }) => finish(data.error ? new Error(data.error) : null, data.url);
      worker.onerror = (event) => finish(new Error(event.message));
      worker.postMessage(raw);
    });
  }

  async function prepare() {
    if (busy) return;
    busy = true; validUrl = ''; revision++;
    $('prepare').disabled = true;
    $('destination').value = ''; $('params').replaceChildren();
    clearOutput();
    try {
      const raw = $('source').value.trim();
      const parsed = parseInput(raw);
      status('source-status', t('Preparing…', 'Обработка…'));
      const url = parsed.kind === 'url' ? parsed.url : await decrypt(raw);
      acceptUrl(url, true);
      $('source-kind').textContent = parsed.kind.toUpperCase();
      status('source-status', t('Link ready.', 'Ссылка готова.'));
    } catch (error) {
      validUrl = ''; clearOutput();
      status('source-status', error.message, 'error');
    } finally {
      busy = false; $('prepare').disabled = false; syncButtons();
    }
  }

  $('prepare').addEventListener('click', prepare);
  $('source').addEventListener('input', () => { $('prepare').disabled = !$('source').value.trim() || busy; });
  $('source').addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) prepare();
  });
  $('source-clear').addEventListener('click', () => {
    if (busy) return;
    validUrl = ''; revision++; $('source').value = ''; $('destination').value = '';
    $('params').replaceChildren(); clearOutput(); status('source-status', '');
  });
  $('destination').addEventListener('input', () => {
    try { acceptUrl($('destination').value, false); status('source-status', ''); }
    catch (error) { validUrl = ''; revision++; clearOutput(); $('params').replaceChildren(); status('source-status', error.message, 'error'); }
  });
  $('param-add').addEventListener('click', () => {
    if (!validUrl || !$('param-key').value.trim()) return;
    try {
      acceptUrl(withParam(validUrl, $('param-key').value.trim(), $('param-value').value), false);
      $('param-key').value = ''; $('param-value').value = '';
    } catch (error) { showToast(error.message, 'error'); }
  });
  $('format').addEventListener('change', renderOutput);
  $('copy-output').addEventListener('click', () => copyText($('output').value));
  $('encrypt-consent').addEventListener('change', syncButtons);
  $('encrypt').addEventListener('click', async () => {
    if (!local || !validUrl || busy || !$('encrypt-consent').checked) return;
    const version = revision;
    busy = true; clearOutput();
    status('source-status', t('Requesting the official Happ API…', 'Запрос к официальному Happ API…'));
    try {
      const { link } = await encryptOfficial(validUrl);
      if (version !== revision) return;
      $('format').value = 'happ-official';
      setOutput(link);
      status('source-status', t('Returned by the official API. Hardware binding is unchanged.', 'Получено от официального API. Привязка устройства не изменена.'));
    } catch (error) { status('source-status', error.message, 'error'); }
    finally { busy = false; syncButtons(); }
  });

  $('qr-open').addEventListener('click', async () => {
    if (!$('output').value) return;
    try {
      await QRCode.toCanvas($('dialog-canvas'), $('output').value, { width: 360, margin: 4 });
      $('qr-dialog').showModal();
    } catch { showToast(t('Too long for QR.', 'Слишком длинно для QR.'), 'error'); }
  });
  $('qr-close').addEventListener('click', () => $('qr-dialog').close());

  function clearResponse() {
    lastResponse = ''; responseAvailable = false; $('response').value = ''; $('response-meta').textContent = '';
    $('copy-response').disabled = true; $('download-response').disabled = true;
  }
  $('request-send').addEventListener('click', async () => {
    const route = $('request-route').value;
    if (route === 'bridge' && !local) { showToast(t('The bridge needs the desktop build — pick a public route.', 'Мост работает в локальной версии — выберите публичный маршрут.'), 'error'); return; }
    if (requestController) return;
    clearResponse();
    requestController = new AbortController(); syncButtons();
    status('request-status', t('REQUESTING', 'ЗАПРОС'));
    try {
      const url = validate($('request-url').value);
      const identity = {
        hwid: $('request-hwid').value.trim(), userAgent: $('request-ua').value.trim(),
        deviceOs: $('request-os').value.trim(), verOs: $('request-version').value.trim(), deviceModel: $('request-model').value.trim(),
      };
      const result = await fetchSubscription(url, { identity, route, customProxy: $('request-custom-proxy').value, signal: requestController.signal });
      lastResponse = result.text;
      $('response').value = lastResponse;
      const denied = result.status < 200 || result.status >= 300 || result.headers['x-hwid-not-supported'] === 'true' || result.headers['x-hwid-max-devices-reached'] === 'true';
      status('request-status', `HTTP ${result.status}${denied ? t(' · REJECTED', ' · ОТКАЗ') : ''}`, denied ? 'error' : 'ok');
      const detected = detectSubscriptionContent(lastResponse);
      $('response-meta').textContent = `${result.contentType}\n${t('Format', 'Формат')}: ${detected.format}\n` + Object.entries(result.headers).filter(([key]) => /^(x-hwid|subscription-|profile-)/i.test(key)).map(([key, value]) => `${key}: ${value}`).join('\n');
      responseAvailable = !!lastResponse && !denied;
      $('copy-response').disabled = !responseAvailable;
      $('download-response').disabled = !responseAvailable;
    } catch (error) { clearResponse(); status('request-status', error.message, 'error'); }
    finally { requestController = undefined; syncButtons(); }
  });
  $('copy-response').addEventListener('click', () => { if (responseAvailable) copyText(lastResponse); });
  $('download-response').addEventListener('click', () => {
    if (!responseAvailable) return;
    const link = document.createElement('a');
    const url = URL.createObjectURL(new Blob([lastResponse], { type: 'text/plain;charset=utf-8' }));
    link.href = url; link.download = 'subscription.txt'; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });

  restoreIdentity();
  try {
    const savedRoute = localStorage.getItem(ROUTE_KEY);
    $('request-route').value = ['bridge', 'corsfix', 'custom'].includes(savedRoute) ? savedRoute : 'bridge';
    $('request-custom-proxy').value = localStorage.getItem(CUSTOM_PROXY_KEY) || '';
  } catch { /* optional */ }
  $('request-route').addEventListener('change', applyRoute);
  $('request-custom-proxy').addEventListener('input', () => {
    try { localStorage.setItem(CUSTOM_PROXY_KEY, $('request-custom-proxy').value); } catch { /* optional */ }
  });
  applyRoute();
  for (const field of identityFields()) field.addEventListener('input', () => {
    saveIdentity();
    const [requestId, editorId] = IDENTITY_PAIRS.find(([a, b]) => [a, b].includes(field.id));
    const mirror = field.id === requestId ? $(editorId) : $(requestId);
    if (mirror.value !== field.value) mirror.value = field.value;
  });
  $('id-hwid-roll').addEventListener('click', () => {
    const hwid = generateHwid();
    $('id-hwid').value = hwid; $('request-hwid').value = hwid;
    saveIdentity();
    showToast(t('New random HWID generated', 'Сгенерирован новый случайный HWID'));
  });
  $('id-to-url').addEventListener('click', () => {
    if (!validUrl) { showToast(t('Prepare a link first.', 'Сначала подготовьте ссылку.'), 'error'); return; }
    const hwid = $('id-hwid').value.trim();
    if (!isValidHwid(hwid)) { showToast(t('Set a valid x-hwid (10–64 characters).', 'Задайте корректный x-hwid (10–64 символа).'), 'error'); return; }
    try {
      const url = withParam(validUrl, 'hwid', hwid);
      validUrl = url; $('destination').value = url; revision++;
      renderOutput();
      showToast(t('HWID bound into the link', 'HWID вшит в ссылку'));
    } catch (error) { showToast(error.message, 'error'); }
  });

  function applyRoute() {
    const route = $('request-route').value;
    $('custom-proxy-row').hidden = route !== 'custom';
    try { localStorage.setItem(ROUTE_KEY, route); } catch { /* optional */ }
    syncButtons();
  }

  function bridgeLabel() {
    $('bridge-state').textContent = local ? t('REQUESTS READY', 'ЗАПРОСЫ ДОСТУПНЫ') : t('REQUESTS UNAVAILABLE', 'ЗАПРОСЫ НЕДОСТУПНЫ');
    syncButtons();
  }
  document.addEventListener('langchange', () => { bridgeLabel(); if ($('format').value !== 'happ-official') renderOutput(); });
  getCapabilities().then((capabilities) => { local = capabilities.local === true; bridgeLabel(); }).catch(() => { local = false; bridgeLabel(); });
  $('prepare').disabled = false;
  syncButtons();
}
