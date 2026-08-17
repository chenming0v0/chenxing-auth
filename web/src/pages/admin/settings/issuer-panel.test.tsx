import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { IssuerPanel } from './issuer-panel'

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

describe('IssuerPanel loading failure', () => {
  beforeEach(() => {
    let attempts = 0
    vi.stubGlobal('fetch', () => {
      attempts += 1
      if (attempts === 1) return Promise.resolve(jsonResponse({ code: 'internal' }, 500))
      return Promise.resolve(jsonResponse({
        persisted: null,
        loaded: null,
        phase: 'awaiting_issuer',
      }))
    })
  })

  afterEach(() => {
    cleanup()
    vi.unstubAllGlobals()
  })

  it('shows a retry state and restores the form after a successful reload', async () => {
    const onMessage = vi.fn()
    render(<IssuerPanel onMessage={onMessage} onDirtyChange={() => {}} />)

    expect(await screen.findByText('Issuer 设置暂时无法加载。')).toBeTruthy()
    expect(screen.queryByLabelText('Issuer 根 URL')).toBeNull()
    expect(onMessage).toHaveBeenCalledWith('服务暂时不可用，请稍后重试。', 'warning')

    fireEvent.click(screen.getByRole('button', { name: '重新加载 Issuer 设置' }))

    await waitFor(() => expect(screen.getByLabelText('Issuer 根 URL')).toBeTruthy())
    expect(screen.queryByText('Issuer 设置暂时无法加载。')).toBeNull()
  })
})
