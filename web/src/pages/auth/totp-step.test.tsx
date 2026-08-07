import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import type { PendingLoginResponse } from '../../api'
import { TotpStep } from './totp-step'

function pendingWith(status: PendingLoginResponse['status']): PendingLoginResponse {
  return { status, methods: ['totp'] }
}

function invalidTicketResponse(): Response {
  return { ok: false, status: 400, json: async () => ({ code: 'invalid_login_ticket' }) } as Response
}

function invalidFactorResponse(): Response {
  return { ok: false, status: 400, json: async () => ({ code: 'invalid_factor' }) } as Response
}

function renderTotpStep(overrides: { onMessage?: () => void; onTicketInvalid?: () => void } = {}) {
  return render(
    <TotpStep
      pending={pendingWith('factor_required')}
      setup={null}
      busy={false}
      onSetup={() => {}}
      onComplete={async () => {}}
      onBusy={() => {}}
      onMessage={overrides.onMessage ?? (() => {})}
      onTicketInvalid={overrides.onTicketInvalid ?? (() => {})}
    />,
  )
}

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('unexpected fetch'))))
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('TotpStep login_ticket 失效处理（#195）', () => {
  it('验证码校验返回 invalid_login_ticket 时通知上层恢复登录', async () => {
    const onTicketInvalid = vi.fn()
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(invalidTicketResponse())))
    renderTotpStep({ onTicketInvalid })

    fireEvent.change(screen.getByLabelText('一次性验证码'), { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: /完成验证/ }))
    await waitFor(() => expect(onTicketInvalid).toHaveBeenCalledTimes(1))
  })

  it('普通因子错误只上报文案，不触发恢复登录', async () => {
    const onMessage = vi.fn()
    const onTicketInvalid = vi.fn()
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(invalidFactorResponse())))
    renderTotpStep({ onMessage, onTicketInvalid })

    fireEvent.change(screen.getByLabelText('一次性验证码'), { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: /完成验证/ }))
    await waitFor(() => expect(onMessage).toHaveBeenCalled())
    expect(onTicketInvalid).not.toHaveBeenCalled()
  })

  it('开始绑定时 login_ticket 失效同样通知上层恢复登录', async () => {
    const onTicketInvalid = vi.fn()
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(invalidTicketResponse())))
    render(
      <TotpStep
        pending={pendingWith('factor_setup_required')}
        setup={null}
        busy={false}
        onSetup={() => {}}
        onComplete={async () => {}}
        onBusy={() => {}}
        onMessage={() => {}}
        onTicketInvalid={onTicketInvalid}
      />,
    )

    fireEvent.click(screen.getByRole('button', { name: /开始绑定验证器/ }))
    await waitFor(() => expect(onTicketInvalid).toHaveBeenCalledTimes(1))
  })
})
