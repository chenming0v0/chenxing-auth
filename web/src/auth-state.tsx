import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import { apiFetch, clearApiCache, type AuthStatusResponse, type UserMe } from './api'

export type BootstrapState = 'loading' | 'required' | 'ready'

type AuthContextValue = {
  user: UserMe | null
  status: 'loading' | 'authenticated' | 'unauthenticated'
  bootstrap: BootstrapState
  refresh: () => Promise<UserMe | null>
  refreshBootstrap: () => Promise<BootstrapState>
  clear: () => void
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserMe | null>(null)
  const [status, setStatus] = useState<AuthContextValue['status']>('loading')
  const [bootstrap, setBootstrap] = useState<BootstrapState>('loading')
  const loaded = useRef(false)

  const clear = useCallback(() => {
    setUser(null)
    setStatus('unauthenticated')
    clearApiCache()
  }, [])

  const refreshBootstrap = useCallback(async () => {
    try {
      const result = await apiFetch<{ initialized: boolean }>('/api/v1/admin/bootstrap/status', {
        redirectOn401: false,
      })
      const next: BootstrapState = result.initialized ? 'ready' : 'required'
      setBootstrap(next)
      return next
    } catch {
      // If bootstrap status is unavailable, keep the app usable instead of locking the UI.
      setBootstrap('ready')
      return 'ready'
    }
  }, [])

  const refresh = useCallback(async () => {
    try {
      const auth = await apiFetch<AuthStatusResponse>('/api/v1/auth/status', { redirectOn401: false })
      if (!auth.authenticated) {
        clear()
        return null
      }
      const profile = await apiFetch<UserMe>('/api/v1/auth/me', { redirectOn401: false })
      setUser(profile)
      setStatus('authenticated')
      return profile
    } catch {
      clear()
      return null
    }
  }, [clear])

  useEffect(() => {
    if (loaded.current) return
    loaded.current = true
    void Promise.all([refreshBootstrap(), refresh()])
  }, [refresh, refreshBootstrap])

  const logout = useCallback(async () => {
    try {
      await apiFetch<void>('/api/v1/auth/session', { method: 'DELETE', redirectOn401: false })
    } finally {
      clear()
    }
  }, [clear])

  return (
    <AuthContext.Provider value={{ user, status, bootstrap, refresh, refreshBootstrap, clear, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext)
  if (!value) throw new Error('useAuth must be used inside AuthProvider')
  return value
}
