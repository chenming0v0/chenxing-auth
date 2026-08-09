import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { useState } from 'react'
import { useFlashMessage, useSettingsResource, type SettingsMessageSink } from './panel'

/* #268：设置工作区把同一个 onMessage 下发给所有面板。这里锁两条不变量：
   1. useFlashMessage 返回的 flash 引用跨渲染稳定；
   2. useSettingsResource 的加载 effect 只认端点，不认回调引用——
      任一条失守，别的面板发一条消息就会把本面板的草稿重新拉成服务端值。 */

const PATH = '/api/v1/admin/settings/smtp'

let getCount = 0
let failNext = false

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

/** apiFetch 内部还有 response.json() 等多级 await，单个 microtask 不足以走完。 */
async function flushMicrotasks() {
  for (let index = 0; index < 5; index += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0))
  }
}

beforeEach(() => {
  getCount = 0
  failNext = false
  vi.stubGlobal('fetch', () => {
    getCount += 1
    if (failNext) return Promise.resolve(jsonResponse({ code: 'internal' }, 500))
    return Promise.resolve(jsonResponse({ host: 'smtp.example.com' }))
  })
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function ResourceProbe({
  onMessage,
  onFailure,
}: {
  onMessage: SettingsMessageSink
  onFailure?: () => void
}) {
  const [host, setHost] = useState('')
  const { loading, reload } = useSettingsResource<{ host: string }>({
    path: PATH,
    onMessage,
    failureMessage: 'SMTP 设置加载失败。',
    apply: (value) => setHost(value.host),
    onFailure,
  })
  return (
    <div>
      <p data-testid="loading">{String(loading)}</p>
      <input aria-label="主机" value={host} onChange={(event) => setHost(event.target.value)} />
      <button type="button" onClick={() => void reload()}>重新加载</button>
    </div>
  )
}

function host(): HTMLInputElement {
  return screen.getByLabelText('主机') as HTMLInputElement
}

describe('useSettingsResource 加载生命周期', () => {
  it('onMessage 引用每次渲染都变时仍只加载一次，草稿不被覆盖', async () => {
    const { rerender } = render(<ResourceProbe onMessage={() => {}} />)
    await waitFor(() => expect(host().value).toBe('smtp.example.com'))
    expect(getCount).toBe(1)

    fireEvent.change(host(), { target: { value: 'draft.example.com' } })
    // 模拟工作区因为别的面板发消息而重渲染：每次都传一个新函数。
    for (let index = 0; index < 3; index += 1) {
      rerender(<ResourceProbe onMessage={() => {}} />)
    }

    expect(getCount).toBe(1)
    expect(host().value).toBe('draft.example.com')
  })

  it('只有显式 reload 才重新拉取并覆盖草稿', async () => {
    render(<ResourceProbe onMessage={() => {}} />)
    await waitFor(() => expect(host().value).toBe('smtp.example.com'))
    fireEvent.change(host(), { target: { value: 'draft.example.com' } })

    fireEvent.click(screen.getByRole('button', { name: '重新加载' }))
    await waitFor(() => expect(host().value).toBe('smtp.example.com'))
    expect(getCount).toBe(2)
  })

  it('加载失败时执行 onFailure 并按 warning 上报，且退出 loading', async () => {
    failNext = true
    const onMessage = vi.fn()
    const onFailure = vi.fn()
    render(<ResourceProbe onMessage={onMessage} onFailure={onFailure} />)

    await waitFor(() => expect(onMessage).toHaveBeenCalledWith('服务暂时不可用，请稍后重试。', 'warning'))
    expect(onFailure).toHaveBeenCalledTimes(1)
    await waitFor(() => expect(screen.getByTestId('loading').textContent).toBe('false'))
  })

  it('卸载后到达的失败响应不再上报消息，也不写回状态', async () => {
    let settle: ((value: Response) => void) | undefined
    vi.stubGlobal('fetch', () => new Promise<Response>((resolve) => { settle = resolve }))
    const onMessage = vi.fn()
    const onFailure = vi.fn()
    const { unmount } = render(<ResourceProbe onMessage={onMessage} onFailure={onFailure} />)
    unmount()
    settle?.(jsonResponse({ code: 'internal' }, 500))
    await flushMicrotasks()

    expect(onMessage).not.toHaveBeenCalled()
    expect(onFailure).not.toHaveBeenCalled()
  })
})

const flashIdentities: SettingsMessageSink[] = []

function FlashProbe() {
  const { flash, message } = useFlashMessage()
  flashIdentities.push(flash)
  return (
    <div>
      <button type="button" onClick={() => flash('已保存。')}>成功</button>
      <button type="button" onClick={() => flash('保存失败。', 'warning')}>失败</button>
      <p data-testid="message">{message ? `${message.tone}:${message.text}` : ''}</p>
    </div>
  )
}

describe('useFlashMessage', () => {
  beforeEach(() => { flashIdentities.length = 0 })

  it('消息状态变化不改变 flash 的引用', () => {
    render(<FlashProbe />)
    fireEvent.click(screen.getByRole('button', { name: '成功' }))
    expect(screen.getByTestId('message').textContent).toBe('success:已保存。')
    fireEvent.click(screen.getByRole('button', { name: '失败' }))
    expect(screen.getByTestId('message').textContent).toBe('warning:保存失败。')

    expect(flashIdentities.length).toBeGreaterThan(2)
    expect(new Set(flashIdentities).size).toBe(1)
  })
})
