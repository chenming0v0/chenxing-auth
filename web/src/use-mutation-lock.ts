import { useCallback, useRef, useState } from 'react'

/**
 * 同步互斥锁，挡住「busy 尚未重渲染」窗口里的二次提交。
 *
 * `setBusy(true)` 要等下一帧才让按钮 disabled；同一事件循环里的第二次
 * submit / Enter 仍会看到 `busy === false` 并再发一条 POST/PATCH。
 * ref 在本次调用里立刻占住，不依赖渲染。
 */
export function useMutationLock() {
  const locked = useRef(false)
  const [busy, setBusy] = useState(false)

  const acquire = useCallback((): boolean => {
    if (locked.current) return false
    locked.current = true
    setBusy(true)
    return true
  }, [])

  const release = useCallback(() => {
    locked.current = false
    setBusy(false)
  }, [])

  const run = useCallback(async <T,>(fn: () => Promise<T>): Promise<T | undefined> => {
    if (!acquire()) return undefined
    try {
      return await fn()
    } finally {
      release()
    }
  }, [acquire, release])

  return { busy, acquire, release, run }
}
