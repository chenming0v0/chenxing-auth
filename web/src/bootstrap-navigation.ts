export type NavigationRequest = {
  method?: string
  path: string
  accept?: string | string[]
  fetchDestination?: string | string[]
}

function headerText(value: string | string[] | undefined): string {
  return Array.isArray(value) ? value.join(',') : value ?? ''
}

export function isSpaDocumentNavigation(request: NavigationRequest): boolean {
  const method = (request.method ?? 'GET').toUpperCase()
  if (method !== 'GET' && method !== 'HEAD') return false
  if (!isSpaNavigationPath(request.path)) return false
  if (!headerText(request.accept).split(',').some((item) => item.trim().startsWith('text/html'))) return false
  const destination = headerText(request.fetchDestination).trim()
  return destination === '' || destination === 'document'
}

function isSpaNavigationPath(path: string): boolean {
  if (
    path.includes('%')
    || path.startsWith('/assets/')
    || path === '/api'
    || path.startsWith('/api/')
    || path === '/auth/external'
    || path.startsWith('/auth/external/')
    || path === '/health'
    || path.startsWith('/health/')
    || path === '/.well-known'
    || path.startsWith('/.well-known/')
    || path.split('/').some((segment) => segment.startsWith('.'))
    || hasFileExtension(path)
  ) {
    return false
  }
  if (path === '/oauth' || path.startsWith('/oauth/')) {
    return ['/oauth/account', '/oauth/consent', '/oauth/redirect'].includes(path)
  }
  return true
}

function hasFileExtension(path: string): boolean {
  const segment = path.split('/').at(-1) ?? ''
  const dot = segment.lastIndexOf('.')
  return dot > 0 && dot < segment.length - 1
}
