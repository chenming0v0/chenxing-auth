import { useCallback, useEffect, useRef, useState } from 'react'
import { apiFetch } from '../../../api'

export type SettingsMessageTone = 'success' | 'warning'
export type SettingsMessageSink = (message: string, tone?: SettingsMessageTone) => void

/** 所有设置面板的统一入参：面板只向工作区上报结果，不自己渲染全局消息条。 */
export type SettingsPanelProps = { onMessage: SettingsMessageSink }

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

export type SettingsResource = { loading: boolean; reload: () => Promise<void> }

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
  const handlers = useRef(options)
  /** 每次加载持有一个代号；卸载或再次加载都会作废旧代号，避免过期响应写回状态。 */
  const generation = useRef(0)

  useEffect(() => {
    handlers.current = options
  })

  const reload = useCallback(async () => {
    const token = (generation.current += 1)
    setLoading(true)
    try {
      const value = await apiFetch<T>(path)
      if (generation.current !== token) return
      handlers.current.apply(value)
    } catch (reason) {
      if (generation.current !== token) return
      handlers.current.onFailure?.()
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

  return { loading, reload }
}
