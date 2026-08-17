import { useCallback, useEffect, useRef, useState } from 'react'
import { apiFetch } from '../../../api'
import { setNavigationBlocker } from '../../../router'

export type SettingsMessageTone = 'success' | 'warning'
export type SettingsMessageSink = (message: string, tone?: SettingsMessageTone) => void

/** 所有设置面板的统一入参：面板只向工作区上报结果与未保存草稿状态，不自己渲染全局消息条。 */
export type SettingsPanelProps = {
  onMessage: SettingsMessageSink
  /**
   * 未保存草稿上报（#381）：dirty 为 true 表示面板存在尚未保存的编辑。
   * 引用必须跨渲染稳定（与 #268 的 onMessage 同约束），否则面板 effect 会重跑。
   */
  onDirtyChange: (dirty: boolean) => void
}

export type FlashMessage = { text: string; tone: SettingsMessageTone }

/**
 * 工作区侧的消息通道。`flash` 的引用必须跨渲染稳定（#268）：
 * 它作为 `onMessage` 下发给全部面板，一旦每次渲染都换新函数，任何以它为依赖的
 * 面板 effect 都会在别的面板发消息时重跑，把用户正在编辑的草稿冲掉。
 * setState 本身引用稳定，因此空依赖的 useCallback 就是正确且完整的锁定方式。
 */
export function useFlashMessage(): { flash: SettingsMessageSink; message: FlashMessage | null } {
  const [message, setMessage] = useState<FlashMessage | null>(null)
  const flash = useCallback((text: string, tone: SettingsMessageTone = 'success') => {
    setMessage({ text, tone })
  }, [])
  return { flash, message }
}

/** 面板草稿与已保存基线的结构比较；这些状态都是纯 JSON 形状的 API 值。 */
export function settingsEqual<T>(left: T, right: T): boolean {
  return JSON.stringify(left) === JSON.stringify(right)
}

/**
 * 正整数输入校验核心：设置面板的草稿一律以字符串保存（保留空串和输入中间态），
 * 保存前再按各自上限统一校验（从 security-limits 面板提取共享，#376）。
 * 错误文案必须保持稳定——它们被各面板的校验测试逐字断言。
 * JSON 请求使用 JavaScript number，因此上限与边界必须停在可精确表示的安全整数。
 */
export function validateIntegerWithinRange(
  rawValue: string,
  label: string,
  maximum: number,
): { value: number } | { error: string } {
  const raw = rawValue.trim()
  const positiveIntegerMessage = `「${label}」必须填写大于 0 的整数。`
  if (!raw) return { error: positiveIntegerMessage }

  const numeric = Number(raw)
  if (Number.isNaN(numeric)) {
    return { error: `「${label}」不是有效数字（NaN），请填写大于 0 的整数。` }
  }
  if (!Number.isFinite(numeric)) {
    return { error: `「${label}」必须是有限数字，不能为 ${numeric}。` }
  }
  if (!Number.isInteger(numeric)) {
    return { error: positiveIntegerMessage }
  }
  if (numeric <= 0) return { error: positiveIntegerMessage }
  if (!Number.isSafeInteger(numeric)) {
    return { error: `「${label}」超出 JavaScript 安全整数范围，最大为 ${Number.MAX_SAFE_INTEGER}。` }
  }
  if (numeric > maximum) {
    return { error: `「${label}」超出范围，必须在 1 到 ${maximum} 之间。` }
  }
  return { value: numeric }
}

/**
 * dirty 上报的公共通道（#381）：dirty 变化时通知工作区；卸载时上报 false，
 * 让工作区的聚合计数不会因面板卸载（如 OAuth 面板按权限条件渲染）残留脏标记。
 * `onDirtyChange` 必须跨渲染稳定，effect 才不会每次渲染重跑。
 */
export function useDirtyReport(dirty: boolean, onDirtyChange: (dirty: boolean) => void) {
  useEffect(() => {
    onDirtyChange(dirty)
    return () => onDirtyChange(false)
  }, [dirty, onDirtyChange])
}

const DRAFT_LEAVE_MESSAGE = '有未保存的设置修改，离开后这些修改将丢失。确定离开吗？'

/**
 * 工作区侧的未保存草稿离开守卫（#381）：dirty 为 true 时，
 * - SPA 路由跳转前用 window.confirm 拦截（navigate 的单例拦截器，见 router.tsx）；
 * - 刷新/关闭页面交给浏览器原生 beforeunload 提示（文案由浏览器决定，不可定制）。
 * 注意：浏览器前进/后退按钮直接触发 popstate、不经过 navigate，无法被这里拦截。
 */
export function useDraftLeaveGuard(dirty: boolean) {
  useEffect(() => {
    if (!dirty) return
    setNavigationBlocker(() => window.confirm(DRAFT_LEAVE_MESSAGE))
    const onBeforeUnload = (event: BeforeUnloadEvent) => { event.preventDefault() }
    window.addEventListener('beforeunload', onBeforeUnload)
    return () => {
      setNavigationBlocker(null)
      window.removeEventListener('beforeunload', onBeforeUnload)
    }
  }, [dirty])
}

type SettingsResourceOptions<T> = {
  /** 只读的加载端点；面板的保存请求各自处理，不走这里。 */
  path: string
  onMessage: SettingsMessageSink
  /** 加载失败时的兜底文案，非 Error 异常用它上报。 */
  failureMessage: string
  /** 把加载结果写进面板状态；仅在该次加载仍然有效时调用。 */
  apply: (value: T) => void
  /** 加载失败后的状态收尾，例如把列表置为空数组以渲染空态。 */
  onFailure?: () => void
}

export type SettingsResource = { loading: boolean; failed: boolean; reload: () => Promise<void> }

/**
 * 设置面板的加载生命周期。
 *
 * 关键约束（#268）：加载 effect 只依赖端点路径，不依赖 `onMessage`、`apply` 等回调。
 * 消息状态属于展示层，它的变化不能触发重新拉取——否则一个面板保存成功，其余面板
 * 的表单会被服务端值覆盖，用户未保存的编辑凭空消失。回调改为存放在 ref 里，
 * 异步回调始终读到最新实现，同时不进入依赖数组。
 */
export function useSettingsResource<T>(options: SettingsResourceOptions<T>): SettingsResource {
  const { path } = options
  const [loading, setLoading] = useState(true)
  const [failed, setFailed] = useState(false)
  const handlers = useRef(options)
  /** 每次加载持有一个代号；卸载或再次加载都会作废旧代号，避免过期响应写回状态。 */
  const generation = useRef(0)

  useEffect(() => {
    handlers.current = options
  })

  const reload = useCallback(async () => {
    const token = (generation.current += 1)
    setLoading(true)
    setFailed(false)
    try {
      const value = await apiFetch<T>(path)
      if (generation.current !== token) return
      handlers.current.apply(value)
    } catch (reason) {
      if (generation.current !== token) return
      handlers.current.onFailure?.()
      setFailed(true)
      handlers.current.onMessage(
        reason instanceof Error ? reason.message : handlers.current.failureMessage,
        'warning',
      )
    } finally {
      if (generation.current === token) setLoading(false)
    }
  }, [path])

  useEffect(() => {
    void reload()
    return () => { generation.current += 1 }
  }, [reload])

  return { loading, failed, reload }
}
