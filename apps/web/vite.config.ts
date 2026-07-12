import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// The read-API (FastAPI) runs on :8000 in dev; proxy /v1 to it so the app can
// call relative paths and avoid CORS. Production serves the app behind the API gateway.
// Target explicit IPv4 (not `localhost`, which Node resolves to IPv6 ::1 first —
// uvicorn binds 127.0.0.1, so `localhost` would 500 on connection refused).
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/v1': { target: 'http://127.0.0.1:8000', changeOrigin: true },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-setup.ts'],
  },
});
