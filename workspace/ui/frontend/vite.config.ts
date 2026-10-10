import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  // Wails dev server: the Go backend proxies API calls from port 34115
  // automatically; no explicit proxy config needed here.
})
