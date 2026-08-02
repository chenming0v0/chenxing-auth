export type ApiError = { message: string; status: number }

function csrfToken() {
  return document.cookie
    .split('; ')
    .find((cookie) => cookie.startsWith('csrf_token='))
    ?.split('=')[1]
}

export async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = init.method?.toUpperCase() ?? 'GET'
  const headers = new Headers(init.headers)
  headers.set('Accept', 'application/json')
  if (method !== 'GET' && method !== 'HEAD') {
    headers.set('Content-Type', 'application/json')
    const token = csrfToken()
    if (token) headers.set('X-CSRF-Token', decodeURIComponent(token))
  }

  const response = await fetch(path, { ...init, headers, credentials: 'include' })
  if (!response.ok) {
    const detail = await response.json().catch(() => ({})) as { message?: string }
    const error: ApiError = { message: detail.message ?? '请求未完成，请稍后重试。', status: response.status }
    throw error
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}
