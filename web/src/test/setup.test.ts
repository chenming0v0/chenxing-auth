import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, apiFetch } from '../api'

describe('vitest 全局 setup（#374）', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('不再往 document.cookie 注入 chenxing_csrf，缺 cookie 的 mutation 在 fetch 前被拦住', async () => {
    // 本文件没有自己写 cookie。若 setup.ts 仍无条件注入 test-csrf-token，
    // 这条路径会带着伪造 cookie 打到网络，缺 cookie 分支就测不到了。
    expect(document.cookie).not.toMatch(/(?:^|;\s*)(?:__Host-)?chenxing_csrf=/)

    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    const error = await apiFetch('/api/v1/auth/logout', { method: 'POST' })
      .catch((value: unknown) => value)
    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({ code: 'csrf_required' })
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
