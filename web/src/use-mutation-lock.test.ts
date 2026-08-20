import { describe, expect, it, vi } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import { useMutationLock } from './use-mutation-lock'

describe('useMutationLock', () => {
  it('第二次 acquire 在释放前必须失败', () => {
    const { result } = renderHook(() => useMutationLock())
    expect(result.current.busy).toBe(false)
    act(() => { expect(result.current.acquire()).toBe(true) })
    expect(result.current.busy).toBe(true)
    expect(result.current.acquire()).toBe(false)
    act(() => { result.current.release() })
    expect(result.current.busy).toBe(false)
    act(() => { expect(result.current.acquire()).toBe(true) })
  })

  it('run 在途时忽略第二次调用，结束后允许重试', async () => {
    const { result } = renderHook(() => useMutationLock())
    let resolveFirst!: (value: string) => void
    const firstWork = new Promise<string>((resolve) => { resolveFirst = resolve })
    const work = vi.fn(() => firstWork)

    let first: Promise<string | undefined>
    act(() => { first = result.current.run(work) })
    let second: Promise<string | undefined>
    act(() => { second = result.current.run(work) })
    expect(work).toHaveBeenCalledTimes(1)

    resolveFirst('ok')
    await expect(first!).resolves.toBe('ok')
    await expect(second!).resolves.toBeUndefined()

    const retry = vi.fn(async () => 'retry')
    await act(async () => { await expect(result.current.run(retry)).resolves.toBe('retry') })
    expect(retry).toHaveBeenCalledTimes(1)
  })

  it('run 在回调抛错后仍释放锁', async () => {
    const { result } = renderHook(() => useMutationLock())
    await act(async () => {
      await expect(result.current.run(async () => { throw new Error('boom') })).rejects.toThrow('boom')
    })
    expect(result.current.busy).toBe(false)
    act(() => { expect(result.current.acquire()).toBe(true) })
  })
})
