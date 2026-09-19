import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  timeout: 20000,
  workers: 1,
  globalTimeout: 90000,
  webServer: {
    command: 'npm run dev -- --host 127.0.0.1 --port 5173 --strictPort',
    url: 'http://127.0.0.1:5173',
    timeout: 20000,
    reuseExistingServer: true,
  },
  use: { baseURL: 'http://127.0.0.1:5173', headless: true },
  reporter: 'list',
});
