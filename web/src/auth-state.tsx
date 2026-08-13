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

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserMe | null>(null)
  const [status, setStatus] = useState<AuthContextValue['status']>('loading')
  const [bootstrap, setBootstrap] = useState<BootstrapState>('loading')
  const loaded = useRef(false)
  // 每次 clear() 递增，用于丢弃在 logout 之后才落地的过期 refresh() 写入。
  // 使用 useRef 而非 useState：不触发重渲染，且读到的始终是最新值而非快照。
  const generationRef = useRef<number>(0)

  const clear = useCallback(() => {
    // 递增代数——所有正在进行的 refresh() await 返回后会发现代数不匹配，自动丢弃结果
    generationRef.current += 1
    setUser(null)
    setStatus('unauthenticated')
    clearApiCache()
  }, [])

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
    // 记录启动时的代数。若 clear() / logout() 在 await 期间运行，gen 会与
    // generationRef.current 不一致，届时应丢弃结果，不得覆盖已清除的认证状态。
    const gen = generationRef.current
    // 已认证页面刷新资料时保持现有内容；初次加载、登录完成和错误重试则进入 loading。
    setStatus((current) => current === 'authenticated' ? current : 'loading')
    try {
      // Issue #102：直接请求 /auth/me，移除冗余的 /auth/status 前置请求。
      // 未认证时 /auth/me 返回 401，由 catch 块处理；无需额外往返。
      const profile = await apiFetch<UserMe>('/api/v1/auth/me', { redirectOn401: false })

      // Issue #99：await 返回后检查代数。若 logout 已在 await 期间运行，则代数
      // 已被递增，此处丢弃结果避免将已登出的会话重新写回 authenticated 状态。
      if (gen !== generationRef.current) return null

      setUser(profile)
      setStatus('authenticated')
      return profile
    } catch (error) {
      // 竞态保护：若 logout 已在 await 期间完成，跳过后续 state 操作。
      // 不在此处再次调用 clear()，避免二次递增代数而使新一轮 refresh() 失效。
      if (gen !== generationRef.current) return null

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
