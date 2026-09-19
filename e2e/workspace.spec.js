import { test, expect } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.goto('/');
});

test('plain URL is preserved, query edits are explicit, imports use the URL not base64', async ({ page }) => {
  const original = 'https://example.com/sub?token=a%2Fb&tag=one&tag=two#profile';
  await page.locator('#source').fill(original);
  await expect(page.locator('#prepare')).toBeEnabled();
  await page.locator('#prepare').click();
  await expect(page.locator('#destination')).toHaveValue(original);
  await expect(page.locator('#output')).toHaveValue(original);
  await page.locator('#format').selectOption('v2raytun');
  await expect(page.locator('#output')).toHaveValue(`v2raytun://import/${original}`);
  await page.locator('#param-key').fill('test');
  await page.locator('#param-value').fill('a & b');
  await page.locator('#param-add').click();
  const result = new URL(await page.locator('#destination').inputValue());
  expect(result.searchParams.get('test')).toBe('a & b');
  expect(result.searchParams.getAll('tag')).toEqual(['one', 'two']);
});

test('invalid replacement cannot leave a copyable stale result', async ({ page }) => {
  await page.locator('#source').fill('https://example.com/sub');
  await page.locator('#prepare').click();
  await expect(page.locator('#copy-output')).toBeEnabled();
  await page.locator('#source').fill('javascript:alert(1)');
  await page.locator('#prepare').click();
  await expect(page.locator('#copy-output')).toBeDisabled();
  await expect(page.locator('#output')).toHaveValue('');
});

test('local request sends user-entered identity and clears old response on failure', async ({ page }) => {
  await page.locator('#source').fill('https://example.com/sub');
  await page.locator('#prepare').click();
  await page.locator('.nav-link[href="#/request"]').click();
  await page.locator('#request-ua').fill('ActualClient/2.0');
  await page.locator('#request-hwid').fill('actual-device-123');
  let payload;
  await page.route('**/api/subscription', async (route) => {
    payload = route.request().postDataJSON();
    await route.fulfill({ json: { status: 200, contentType: 'text/plain', headers: {}, text: 'vless://id@example.com:443#Node' } });
  });
  await page.locator('#request-send').click();
  await expect(page.locator('#response')).toContainText('');
  await expect(page.locator('#response')).toHaveValue('vless://id@example.com:443#Node');
  expect(payload.identity.userAgent).toBe('ActualClient/2.0');
  expect(payload.identity.hwid).toBe('actual-device-123');
  await page.unroute('**/api/subscription');
  await page.route('**/api/subscription', (route) => route.fulfill({ status: 502, json: { error: 'Upstream refused connection' } }));
  await page.locator('#request-send').click();
  await expect(page.locator('#request-status')).toContainText('Upstream refused');
  await expect(page.locator('#response')).toHaveValue('');
  await expect(page.locator('#download-response')).toBeDisabled();
});

test('encryption requires consent and never auto-uploads a URL', async ({ page }) => {
  await page.locator('#source').fill('https://example.com/private');
  await page.locator('#prepare').click();
  await page.locator('#format').selectOption('happ-official');
  await expect(page.locator('#encrypt')).toBeDisabled();
  await page.locator('#encrypt-consent').check();
  let payload;
  await page.route('**/api/encrypt', (route) => {
    payload = route.request().postDataJSON();
    return route.fulfill({ json: { link: 'happ://crypt5/fixture-from-official-api' } });
  });
  await page.locator('#encrypt').click();
  await expect(page.locator('#output')).toHaveValue('happ://crypt5/fixture-from-official-api');
  expect(payload.url).toBe('https://example.com/private');
});

test('clipboard failure is not reported as success', async ({ page }) => {
  await page.evaluate(() => Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: () => Promise.reject(new Error('denied')) } }));
  await page.locator('#source').fill('https://example.com/sub');
  await page.locator('#prepare').click();
  await page.locator('#copy-output').click();
  await expect(page.locator('#notice')).toHaveAttribute('data-kind', 'error');
});

test('language switches, guide explains device identities, mobile does not overflow', async ({ page }) => {
  await page.locator('#language').click();
  await expect(page.locator('html')).toHaveAttribute('lang', 'ru');
  await page.locator('a[href="#/guide"]').click();
  await expect(page.locator('#view-guide')).toBeVisible();
  await expect(page.locator('#view-guide')).toContainText('one device');
  await page.setViewportSize({ width: 375, height: 812 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: 'test-results/mobile-guide.png', fullPage: true });
  await page.locator('.nav-link[href="#/workspace"]').click();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test('device identity persists across reloads', async ({ page }) => {
  await page.locator('.nav-link[href="#/request"]').click();
  await page.locator('#request-hwid').fill('ue42ljxu4dbicabv');
  await page.locator('#request-ua').fill('Happ/1.16.0 (iOS 18.3; iPhone 14 Pro)');
  await page.reload();
  await expect(page.locator('#request-hwid')).toHaveValue('ue42ljxu4dbicabv');
  await expect(page.locator('#request-ua')).toHaveValue('Happ/1.16.0 (iOS 18.3; iPhone 14 Pro)');
});

test('editor identity syncs with request and hwid binds into the link', async ({ page }) => {
  await page.locator('#source').fill('https://example.com/sub');
  await expect(page.locator('#prepare')).toBeEnabled();
  await page.locator('#prepare').click();
  await page.locator('#id-hwid').fill('ue42ljxu4dbicabv');
  await expect(page.locator('#request-hwid')).toHaveValue('ue42ljxu4dbicabv');
  await page.locator('#id-hwid-roll').click();
  const rolled = await page.locator('#request-hwid').inputValue();
  expect(rolled).toMatch(/^[A-Za-z0-9]{16}$/);
  await page.locator('#id-to-url').click();
  const destination = await page.locator('#destination').inputValue();
  expect(destination).toContain(`hwid=${rolled}`);
});

test('public proxy route works without the local bridge', async ({ page }) => {
  await page.route('**/api/capabilities*', (route) => route.fulfill({ json: { local: false } }));
  await page.goto('/#/request');
  await page.reload();
  await expect(page.locator('#bridge-state')).toContainText('UNAVAILABLE');
  await page.locator('#request-route').selectOption('corsfix');
  await page.locator('#request-url').fill('https://example.com/sub');
  await page.locator('#request-hwid').fill('ue42ljxu4dbicabv');
  let payload;
  await page.route('**/proxy.corsfix.com/**', (route) => {
    payload = { url: route.request().url(), headers: route.request().headers() };
    return route.fulfill({ contentType: 'text/plain', body: 'vless://id@example.com:443#Node' });
  });
  await page.locator('#request-send').click();
  await expect(page.locator('#response')).toHaveValue('vless://id@example.com:443#Node');
  expect(payload.url).toContain('https://proxy.corsfix.com/?https://example.com/sub');
  expect(payload.headers['x-hwid']).toBe('ue42ljxu4dbicabv');
});

test('desktop UI boots without runtime errors', async ({ page }) => {
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.reload();
  await page.locator('#source').fill('https://example.com/sub');
  await page.locator('#prepare').click();
  await expect(page.locator('#output')).toHaveValue('https://example.com/sub');
  await expect(page.locator('#qr')).toBeVisible();
  await page.screenshot({ path: 'test-results/desktop-workspace.png', fullPage: true });
  expect(errors).toEqual([]);
});
