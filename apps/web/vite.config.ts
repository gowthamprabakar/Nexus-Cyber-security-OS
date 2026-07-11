import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// The read-API (FastAPI) runs on :8000 in dev; proxy /v1 to it so the app can
// call relative paths and avoid CORS. Production serves the app behind the API gateway.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/v1': { target: 'http://localhost:8000', changeOrigin: true },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-setup.ts'],
  },
});
