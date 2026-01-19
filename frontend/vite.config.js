import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import wasm from 'vite-plugin-wasm'
import topLevelAwait from 'vite-plugin-top-level-await'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    wasm(),
    topLevelAwait(),
    react()
  ],
  server: {
    host: 'localhost',
    port: 5173,
    strictPort: true
  },
  optimizeDeps: {
    exclude: ['argon2-browser'],
    include: ['@noble/curves', '@noble/hashes'],
    esbuildOptions: {
      target: 'esnext'
    }
  }
})
