import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'

// https://vite.dev/config/
export default defineConfig({
  // The engine serves this app at /dashboard (see ncsa/api/app.py), so every
  // asset URL has to carry that prefix. The build writes straight into the
  // package the engine ships, which is what keeps a demo to one command with
  // no build step on the night.
  base: '/dashboard/',
  build: {
    outDir: '../ncsa/api/static/dashboard',
    emptyOutDir: true,
  },
  plugins: [
    react(),
    tailwindcss()
  ],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "./src"),
    },
  },
  server: {
    // The UI calls /api/*, which is proxied to the FastAPI engine. Going
    // through one origin keeps CORS out of the picture entirely and means the
    // same client code works unchanged when the built assets are served by
    // FastAPI itself in production.
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api/, ""),
      },
    },
  },
})
