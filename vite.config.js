import { defineConfig } from 'vite';
import { bridgePlugin } from './server/bridge.js';

export default defineConfig({
  // When deploying to GitHub Pages the base must be /<repo-name>/.
  // Pass it via the BASE_URL environment variable in CI; falls back to '/' locally.
  base: process.env.BASE_URL ?? '/',
  plugins: [bridgePlugin()],
  server: { host: '127.0.0.1' },
  preview: { host: '127.0.0.1' },
});
