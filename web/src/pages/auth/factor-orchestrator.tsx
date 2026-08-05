import { useState } from 'react'
import type { PendingLoginResponse, TotpSetupResponse } from '../../api'
import { Icon, Notice } from '../../components/ui'
import { TotpStep } from './totp-step'
import { PasskeyStep } from './passkey-step'

type FactorMethod = 'totp' | 'passkey'

const FACTOR_LABELS: Record<FactorMethod, { icon: string; title: string; hint: string; setupHint: string }> = {
  totp: {
    icon: 'shield-check',
    title: '验证器 (TOTP)',
    hint: '输入验证器应用中的 6 位一次性验证码。',
    setupHint: '用验证器应用扫码绑定，之后每次登录输入 6 位验证码。',
  },
  passkey: {
    icon: 'key-round',
    title: 'Passkey',
    hint: '使用本设备的生物识别或安全密钥验证，抗钓鱼。',
    setupHint: '由本设备的生物识别或安全密钥创建凭据，无需记忆验证码。',
  },
}

/**
 * 因子编排器。后端可以同时返回多个可用方法，这里负责：单一方法直通、
 * 多方法先选择再进入对应流程。首次绑定与已绑定登录的差异只体现在
 * PasskeyStep 的 register 开关和 TotpStep 内部的 setupRequired 判断上。
 */
export function FactorOrchestrator({
  pending, busy, onComplete, onBusy, onMessage,
}: {
  pending: PendingLoginResponse
  busy: boolean
  onComplete: () => Promise<void>
  onBusy: (value: boolean) => void
  onMessage: (value: string) => void
}) {
  const [selected, setSelected] = useState<FactorMethod | null>(null)
  const [totpSetup, setTotpSetup] = useState<TotpSetupResponse | null>(null)

  const methods = availableFactors(pending.methods)
  const setupRequired = pending.status === 'factor_setup_required'
  const active = methods.length === 1 ? methods[0] : selected

  if (methods.length === 0) {
    return <Notice tone="warning">当前账号没有可用的认证因子，请重新登录。</Notice>
  }

  if (!active) {
    return (
      <div className="space-y-4">
        <Notice tone="info">{setupRequired ? '首次登录需要绑定一个认证因子，请选择绑定方式。' : '该账号有多种验证方式，请选择其中一种。'}</Notice>
        <div className="grid gap-3">
          {methods.map((method) => (
            <FactorOption
              key={method}
              method={method}
              setupRequired={setupRequired}
              disabled={busy}
              onSelect={() => { onMessage(''); setSelected(method) }}
            />
          ))}
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {active === 'totp' ? (
        <TotpStep pending={pending} setup={totpSetup} busy={busy} onSetup={setTotpSetup} onComplete={onComplete} onBusy={onBusy} onMessage={onMessage} />
      ) : (
        <PasskeyStep pending={pending} register={setupRequired} busy={busy} onComplete={onComplete} onBusy={onBusy} onMessage={onMessage} />
      )}
      {methods.length > 1 ? (
        <button
          type="button"
          className="chenxing-link inline-flex items-center gap-1.5 text-[0.8125rem] disabled:opacity-45"
          onClick={() => { onMessage(''); setSelected(null) }}
          disabled={busy}
        >
          <Icon name="rotate-ccw" size={14} />
          换用其他验证方式
        </button>
      ) : null}
    </div>
  )
}

function FactorOption({
  method, setupRequired, disabled, onSelect,
}: {
  method: FactorMethod
  setupRequired: boolean
  disabled: boolean
  onSelect: () => void
}) {
  const label = FACTOR_LABELS[method]
  return (
    <button type="button" className="cx-factor-option" onClick={onSelect} disabled={disabled}>
      <Icon name={label.icon} size={20} className="mt-0.5 shrink-0 text-[var(--chenxing-cyan)]" />
      <span className="min-w-0 flex-1">
        <span className="block text-sm font-medium text-[var(--chenxing-foreground)]">{label.title}</span>
        <span className="chenxing-caption mt-1 block">{setupRequired ? label.setupHint : label.hint}</span>
      </span>
      <Icon name="arrow-right" size={16} className="mt-0.5 shrink-0 text-[var(--chenxing-muted-foreground)]" />
    </button>
  )
}

/** 只接受本前端实现了的因子，未知方法忽略，避免渲染无法完成的流程。 */
function availableFactors(methods: readonly string[]): FactorMethod[] {
  const seen = new Set<FactorMethod>()
  for (const method of methods) {
    if (method === 'totp' || method === 'passkey') seen.add(method)
  }
  return [...seen]
}
