/// <reference types="vitest" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// 后端 API 端口由 APP_PORT 配置决定（默认 3000），dev 代理目标必须跟随它；
// 后端跑在非默认端口时若仍写死 3000，/api、/health、/oauth 全部落空。
// 前端 dev 端口固定 5175，不在此处变更。
const proxyTarget = `http://localhost:${process.env.APP_PORT || '3000'}`

export default defineConfig({
  plugins: [react(), tailwindcss()],
  test: {
    environment: 'jsdom',
    globals: true,
    include: ['src/**/*.test.{ts,tsx}'],
    setupFiles: ['./src/test/setup.ts'],
  },
  server: {
    port: 5175,
    strictPort: true,
    proxy: {
      '/api': proxyTarget,
      '/health': proxyTarget,
      '/oauth': proxyTarget,
    },
  },
})
