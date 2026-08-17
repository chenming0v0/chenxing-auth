import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import { ApiError, apiFetch, clearApiCache, type UserMe } from './api'

export type BootstrapState = 'loading' | 'required' | 'ready' | 'error'

/** logout 的撤销结果。revoked=false 表示服务端会话可能仍然有效（#325）。 */
export type LogoutResult = {
  revoked: boolean
}

type AuthContextValue = {
  user: UserMe | null
  status: 'loading' | 'authenticated' | 'unauthenticated' | 'error'
  bootstrap: BootstrapState
  refresh: () => Promise<UserMe | null>
  refreshBootstrap: () => Promise<BootstrapState>
  clear: () => void
  logout: () => Promise<LogoutResult>
}

const AuthContext = createContext<AuthContextValue | null>(null)

const AUTH_SYNC_CHANNEL = 'chenxing-auth-sync'
const AUTH_SYNC_STORAGE_KEY = 'chenxing-auth-sync-event'
const REVALIDATE_THROTTLE_MS = 5_000

type AuthSyncEvent = { type: 'logout'; nonce: string }

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserMe | null>(null)
  const [status, setStatus] = useState<AuthContextValue['status']>('loading')
  const [bootstrap, setBootstrap] = useState<BootstrapState>('loading')
  const loaded = useRef(false)
  const channelRef = useRef<BroadcastChannel | null>(null)
  const sessionExpiryTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const lastRevalidationRef = useRef(0)
  // generation：clear/logout 时递增，丢弃登出后才落地的 refresh 写入（#99）。
  // refreshSeq：同一代内每次 refresh 递增。代数分辨不了同代并发请求，
  // 启动时的 /auth/me 与登录后的 refresh 会重叠，只有最新序号可以写回（#473）。
  // 使用 useRef 而非 useState：不触发重渲染，且读到的始终是最新值而非快照。
  const generationRef = useRef<number>(0)
  const refreshSeqRef = useRef<number>(0)
  const userIdRef = useRef<UserMe['id'] | null>(null)

  const clearLocal = useCallback(() => {
    // 递增代数——所有正在进行的 refresh() await 返回后会发现代数不匹配，自动丢弃结果
    generationRef.current += 1
    setUser(null)
    setStatus('unauthenticated')
    userIdRef.current = null
    clearApiCache()
  }, [])

  const broadcastLogout = useCallback(() => {
    const event: AuthSyncEvent = { type: 'logout', nonce: `${Date.now()}-${Math.random()}` }
    try {
      channelRef.current?.postMessage(event)
    } catch {
      // BroadcastChannel may be unavailable or closed; localStorage remains the fallback.
    }
    try {
      window.localStorage.setItem(AUTH_SYNC_STORAGE_KEY, JSON.stringify(event))
    } catch {
      // Storage can be disabled in privacy-restricted browser contexts.
    }
  }, [])

  const clear = useCallback(() => {
    clearLocal()
    if (typeof window !== 'undefined') broadcastLogout()
  }, [broadcastLogout, clearLocal])

  const refreshBootstrap = useCallback(async () => {
    // 重试（错误面板的按钮）时回到 loading，界面显示检查中而不是旧错误。
    setBootstrap('loading')
    try {
      const result = await apiFetch<{ initialized: boolean }>('/api/v1/admin/bootstrap/status', {
        redirectOn401: false,
      })
      const next: BootstrapState = result.initialized ? 'ready' : 'required'
      setBootstrap(next)
      return next
    } catch (error) {
      // bootstrap_status 协议：未初始化返回 200 {initialized:false}；已初始化实例
      // 刻意返回与未注册路由一致的 404（bootstrap_guard::hidden_bootstrap_status），
      // 401 同理只可能来自已就绪实例。只有这两种是「已初始化」的确定信号。
      // 网络错误（status === 0）和 5xx 是瞬态故障：若误判为 ready，未初始化系统
      // 会被踢到 /login，而登录接口同样拒绝未初始化实例——用户被锁死（#324）。
      // 瞬态故障进入 error 状态，由界面提供 refreshBootstrap() 重试入口。
      if (error instanceof ApiError && (error.status === 404 || error.status === 401)) {
        setBootstrap('ready')
        return 'ready'
      }
      setBootstrap('error')
      return 'error'
    }
  }, [])

  const refresh = useCallback(async () => {
    // 记下本轮代数和序号。logout 改代数；后续 refresh 改序号。
    // 任一不匹配都说明自己过期，不得覆盖当前 user/status。
    const generation = generationRef.current
    const requestId = ++refreshSeqRef.current
    const isCurrentRequest = () =>
      generation === generationRef.current && requestId === refreshSeqRef.current
    // 已认证页面刷新资料时保持现有内容；初次加载、登录完成和错误重试则进入 loading。
    setStatus((current) => current === 'authenticated' ? current : 'loading')
    try {
      // Issue #102：直接请求 /auth/me，移除冗余的 /auth/status 前置请求。
      // 未认证时 /auth/me 返回 401，由 catch 块处理；无需额外往返。
      const profile = await apiFetch<UserMe>('/api/v1/auth/me', { redirectOn401: false })

      // await 返回后核对代数和序号：logout 改代数，更新的 refresh 改序号。
      // 过期结果直接丢弃，避免把已登出或已被更新请求覆盖的状态写回去。
      if (!isCurrentRequest()) return null

      if (userIdRef.current !== null && String(userIdRef.current) !== String(profile.id)) {
        // Entitlements are account-scoped. Invalidate both the completed value and any
        // in-flight request before exposing the new identity to the rest of the SPA.
        clearApiCache()
      }
      userIdRef.current = profile.id
      setUser(profile)
      setStatus('authenticated')
      return profile
    } catch (error) {
      // 过期请求不得写状态。尤其是旧 401：再调 clear() 会把登录后的新状态清掉（#473）。
      if (!isCurrentRequest()) return null

      // 只有明确的 401 才代表未认证，应清空本地状态。
      // 网络错误（ApiError.status === 0）和服务端错误（5xx）不等于已登出：
      // 在网络抖动时误调 clear() 会把仍有效的会话踢出，属于错误行为。
      if (error instanceof ApiError && error.status === 401) {
        clear()
      } else {
        // 非 401 故障不代表会话失效。已认证页面继续保留当前用户；初次加载则
        // 进入显式可恢复状态，由受保护路由提供重试动作，避免永久停在 loading。
        setStatus((current) => current === 'authenticated' ? current : 'error')
      }
      return null
    }
  }, [clear])

  useEffect(() => {
    if (typeof window === 'undefined') return

    const onRemoteLogout = (event: AuthSyncEvent | null) => {
      if (event?.type === 'logout') clearLocal()
    }
    const onStorage = (event: StorageEvent) => {
      if (event.key !== AUTH_SYNC_STORAGE_KEY || !event.newValue) return
      try {
        onRemoteLogout(JSON.parse(event.newValue) as AuthSyncEvent)
      } catch {
        // Ignore malformed values from other applications using localStorage.
      }
    }

    window.addEventListener('storage', onStorage)
    if ('BroadcastChannel' in window) {
      try {
        const channel = new BroadcastChannel(AUTH_SYNC_CHANNEL)
        channelRef.current = channel
        channel.addEventListener('message', (event: MessageEvent<AuthSyncEvent>) => onRemoteLogout(event.data))
      } catch {
        channelRef.current = null
      }
    }

    return () => {
      window.removeEventListener('storage', onStorage)
      channelRef.current?.close()
      channelRef.current = null
    }
  }, [clearLocal])

  useEffect(() => {
    if (sessionExpiryTimerRef.current) clearTimeout(sessionExpiryTimerRef.current)
    sessionExpiryTimerRef.current = null
    if (!user?.current_session_expires_at) return

    const expiresAt = new Date(user.current_session_expires_at).getTime()
    if (!Number.isFinite(expiresAt)) return
    // setTimeout 的 delay 超过 2^31-1 ms 时宿主会按溢出立即触发（HTML 标准行为），
    // 远期到期时间（如 2099）会被当成“已到期”在下个 tick 直接登出。这里把单次
    // 延迟钳制到上限，并在每次触发时复核剩余时间：未到期就重新续订，只有真正
    // 过期才清除认证状态（#504 的到期定时器边界）。
    const MAX_TIMEOUT_MS = 2_147_483_647
    const arm = () => {
      const remaining = expiresAt - Date.now()
      if (remaining <= 0) {
        clear()
        return
      }
      sessionExpiryTimerRef.current = setTimeout(arm, Math.min(remaining, MAX_TIMEOUT_MS))
    }
    arm()
    return () => {
      if (sessionExpiryTimerRef.current) clearTimeout(sessionExpiryTimerRef.current)
      sessionExpiryTimerRef.current = null
    }
  }, [clear, user?.current_session_expires_at])

  useEffect(() => {
    if (typeof window === 'undefined') return
    const revalidate = () => {
      if (document.visibilityState !== 'visible' || status !== 'authenticated') return
      const now = Date.now()
      if (now - lastRevalidationRef.current < REVALIDATE_THROTTLE_MS) return
      lastRevalidationRef.current = now
      void refresh()
    }
    window.addEventListener('focus', revalidate)
    document.addEventListener('visibilitychange', revalidate)
    return () => {
      window.removeEventListener('focus', revalidate)
      document.removeEventListener('visibilitychange', revalidate)
    }
  }, [refresh, status])

  useEffect(() => {
    if (loaded.current) return
    loaded.current = true
    void Promise.all([refreshBootstrap(), refresh()])
  }, [refresh, refreshBootstrap])

  // logout 的网络请求失败时仍须本地登出（fail-secure）：
  // 服务端不可达不等于会话仍有效，保守做法是始终清除本地状态。
  // finally 块中的 clear() 会递增 generationRef，使任何进行中的
  // refresh() 在 await 返回后检查代数时自动丢弃结果。
  // 撤销失败**不向外抛错**（#325）：调用点漏接 .catch 会产生 unhandled
  // rejection，且跳转行为与成功路径不一致。失败显式收进返回值 revoked，
  // 由调用方决定提示用户「未能完全登出」；本函数自身永不 reject。
  const logout = useCallback(async (): Promise<LogoutResult> => {
    let revoked = false
    try {
      await apiFetch<void>('/api/v1/auth/session', { method: 'DELETE', redirectOn401: false })
      revoked = true
    } catch (error) {
      // 401 表示服务端会话本就不存在（已过期或被并发撤销，见后端
      // SessionWrite 提取器），没有复活风险，按已撤销处理，不误报警告。
      if (error instanceof ApiError && error.status === 401) revoked = true
    } finally {
      clear()
    }
    return { revoked }
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
