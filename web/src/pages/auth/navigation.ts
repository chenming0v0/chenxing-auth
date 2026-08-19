const DEFAULT_RETURN_TO = '/console'

export function safeReturnTo(value: string | null): string {
  if (!value) return DEFAULT_RETURN_TO
  try {
    decodeURIComponent(value)
    const target = new URL(value.replace(/\\/g, '/'), window.location.origin)
    if (target.origin !== window.location.origin || target.username || target.password) return DEFAULT_RETURN_TO
    return `${target.pathname}${target.search}${target.hash}`
  } catch {
    return DEFAULT_RETURN_TO
  }
}

export function dropDeadRequestId(requestId: string): void {
  const params = new URLSearchParams(window.location.search)
  const returnTo = params.get('returnTo')
  if (returnTo) {
    try {
      const target = new URL(returnTo.replace(/\\/g, '/'), window.location.origin)
      if (target.searchParams.get('request_id') === requestId) {
        target.searchParams.delete('request_id')
        params.set('returnTo', `${target.pathname}${target.search}${target.hash}`)
      }
    } catch {
      // Invalid returnTo remains harmless because safeReturnTo rejects it on navigation.
    }
  }
  if (params.get('request_id') === requestId) params.delete('request_id')
  const hash = window.location.hash
  const search = params.toString()
  const next = `${window.location.pathname}${search ? `?${search}` : ''}${hash}`
  if (next === window.location.pathname + window.location.search + hash) return
  window.history.replaceState({}, '', next)
  window.dispatchEvent(new PopStateEvent('popstate'))
}
