import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import type { PendingLoginResponse } from '../../api'
import { FactorOrchestrator } from './factor-orchestrator'

function pendingWith(methods: string[], status: PendingLoginResponse['status'] = 'factor_setup_required'): PendingLoginResponse {
  return { status, methods }
}

function renderOrchestrator(pending: PendingLoginResponse) {
  return render(
    <FactorOrchestrator
      pending={pending}
      busy={false}
      onComplete={async () => {}}
      onBusy={() => {}}
      onMessage={() => {}}
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

describe('FactorOrchestrator', () => {
  it('renders a factor choice when both totp and passkey are offered', () => {
    renderOrchestrator(pendingWith(['totp', 'passkey']))
    expect(screen.getByText('验证器 (TOTP)')).toBeTruthy()
    expect(screen.getByText('Passkey')).toBeTruthy()
    // 选择界面出现前不得直接进入任一流程
    expect(screen.queryByLabelText('一次性验证码')).toBeNull()
  })

  it('enters the passkey flow when passkey is chosen from a multi-factor response', () => {
    renderOrchestrator(pendingWith(['totp', 'passkey']))
    fireEvent.click(screen.getByText('Passkey'))
    expect(screen.getByText('创建并绑定 Passkey')).toBeTruthy()
    expect(screen.getByText('换用其他验证方式')).toBeTruthy()
  })

  it('enters the totp flow when totp is chosen from a multi-factor response', () => {
    renderOrchestrator(pendingWith(['totp', 'passkey']))
    fireEvent.click(screen.getByText('验证器 (TOTP)'))
    expect(screen.getByText('开始绑定验证器')).toBeTruthy()
  })

  it('can switch back to the factor choice after selecting one', () => {
    renderOrchestrator(pendingWith(['totp', 'passkey']))
    fireEvent.click(screen.getByText('Passkey'))
    fireEvent.click(screen.getByText('换用其他验证方式'))
    expect(screen.getByText('验证器 (TOTP)')).toBeTruthy()
    expect(screen.getByText('Passkey')).toBeTruthy()
  })

  it('goes straight to totp when it is the only method', () => {
    renderOrchestrator(pendingWith(['totp'], 'factor_required'))
    expect(screen.getByText('请输入验证器中的 6 位验证码。')).toBeTruthy()
    expect(screen.queryByText('换用其他验证方式')).toBeNull()
  })

  it('goes straight to passkey authentication when it is the only method', () => {
    renderOrchestrator(pendingWith(['passkey'], 'factor_required'))
    expect(screen.getByText('使用 Passkey 登录')).toBeTruthy()
    expect(screen.queryByText('换用其他验证方式')).toBeNull()
  })

  it('uses passkey registration wording during first-time setup', () => {
    renderOrchestrator(pendingWith(['passkey']))
    expect(screen.getByText('创建并绑定 Passkey')).toBeTruthy()
  })

  it('warns when no supported factor is returned', () => {
    renderOrchestrator(pendingWith(['sms']))
    expect(screen.getByText('当前账号没有可用的认证因子，请重新登录。')).toBeTruthy()
  })
})
