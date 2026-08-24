import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { installCsrfCookie } from '../../../test/csrf-cookie'
import { InvitationCodesPanel } from './invitation-codes-panel'

installCsrfCookie()

const CODES_PATH = '/api/v1/admin/registration-invitation-codes'
const code = {
  id: 7,
  label: null,
  max_uses: 1,
  use_count: 0,
  expires_at: null,
  disabled_at: null,
  created_at: '2026-08-23T00:00:00Z',
}

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('InvitationCodesPanel 停用失败', () => {
  it('显示安全错误提示、解除 busy，且不把失败操作当成成功刷新', async () => {
    const requests: Array<{ path: string; method: string }> = []
    const confirm = vi.fn(() => true)
    vi.stubGlobal('confirm', confirm)
    vi.stubGlobal('fetch', (path: string, init?: RequestInit) => {
      const method = init?.method ?? 'GET'
      requests.push({ path: String(path), method })
      if (method === 'GET' && path === CODES_PATH) return Promise.resolve(jsonResponse([code]))
      if (method === 'POST' && path === `${CODES_PATH}/7/disable`) {
        return Promise.resolve(jsonResponse({ code: 'invitation_code_not_found' }, 404))
      }
      return Promise.resolve(jsonResponse({ code: 'internal' }, 500))
    })

    render(<InvitationCodesPanel />)
    const disableButton = await screen.findByRole('button', { name: '停用' })
    fireEvent.click(disableButton)

    await screen.findByText('邀请码不存在或已失效。')
    expect(confirm).toHaveBeenCalledWith('确认停用这个邀请码吗？停用后不可恢复。')
    await waitFor(() => expect((disableButton as HTMLButtonElement).disabled).toBe(false))
    expect(screen.getByText('#7 · 0/1 次 · 可用')).toBeTruthy()
    expect(requests).toEqual([
      { path: CODES_PATH, method: 'GET' },
      { path: `${CODES_PATH}/7/disable`, method: 'POST' },
    ])
  })
})
