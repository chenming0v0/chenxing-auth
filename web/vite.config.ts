/// <reference types="vitest" />
import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { isSpaDocumentNavigation } from './src/bootstrap-navigation.ts'

// 后端 API 端口由 APP_PORT 配置决定（默认 3000），dev 代理目标必须跟随它；
// 后端跑在非默认端口时若仍写死 3000，/api、/health、/oauth、/auth 全部落空。
// /auth/external/{slug} 是整页导航（下发 state Cookie 并 302），必须代理而非走 SPA fallback。
// 前端 dev 端口固定 5175，不在此处变更。
const proxyTarget = `http://localhost:${process.env.APP_PORT || '3000'}`

function bootstrapNavigationPlugin(): Plugin {
  return {
    name: 'chenxing-bootstrap-navigation',
    configureServer(server) {
      server.middlewares.use(async (request, response, next) => {
        const requestUrl = new URL(request.url ?? '/', 'http://chenxing-vite.local')
        if (!isSpaDocumentNavigation({
          method: request.method,
          path: requestUrl.pathname,
          accept: request.headers.accept,
          fetchDestination: request.headers['sec-fetch-dest'],
        })) {
          next()
          return
        }

        try {
          const upstream = await fetch(new URL(`${requestUrl.pathname}${requestUrl.search}`, proxyTarget), {
            method: 'HEAD',
            headers: {
              accept: 'text/html,application/xhtml+xml',
              'sec-fetch-dest': 'document',
            },
            redirect: 'manual',
          })
          const location = upstream.headers.get('location')
          if (location && [301, 302, 303, 307, 308].includes(upstream.status)) {
            response.statusCode = upstream.status
            response.setHeader('location', location)
            response.end()
            return
          }
        } catch {
          // Backend availability is reported by the proxied API calls; Vite still serves the shell.
        }
        next()
      })
    },
  }
}

export default defineConfig({
  plugins: [bootstrapNavigationPlugin(), react(), tailwindcss()],
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
      '/auth': proxyTarget,
    },
  },
})
