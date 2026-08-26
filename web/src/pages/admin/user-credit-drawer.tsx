import { useState, type FormEvent } from 'react'
import { apiFetch, type WalletCreditResult } from '../../api'
import { Drawer } from '../../components/drawer'
import { Button, Field, HudPanel, Notice, TextAreaField } from '../../components/ui'
import { useMutationLock } from '../../use-mutation-lock'

const MAX_CREDIT_AMOUNT = 1_000_000_000
const MAX_CREDIT_NOTE_CHARS = 256

/** 管理员向用户钱包发放辰星点。权限与用户写操作一致：manage_users。 */
export function UserCreditDrawer({ userId, userName, onCredited, onClose }: {
  userId: number
  userName: string
  onCredited: () => void
  onClose: () => void
}) {
  const [amount, setAmount] = useState('')
  const [note, setNote] = useState('')
  const [error, setError] = useState('')
  const { busy: saving, run } = useMutationLock()

  async function submit(event: FormEvent) {
    event.preventDefault()
    setError('')
    const value = Number(amount.trim())
    if (!amount.trim() || !Number.isInteger(value) || value < 1) {
      setError('充值数量必须是大于 0 的整数。')
      return
    }
    if (value > MAX_CREDIT_AMOUNT) {
      setError('充值数量超出上限。')
      return
    }
    const trimmedNote = note.trim()
    if (Array.from(trimmedNote).length > MAX_CREDIT_NOTE_CHARS) {
      setError('备注过长。')
      return
    }
    await run(async () => {
      try {
        await apiFetch<WalletCreditResult>(`/api/v1/admin/users/${userId}/wallet/credit`, {
          method: 'POST',
          body: JSON.stringify({ amount: value, note: trimmedNote || null }),
        })
        onCredited()
        onClose()
      } catch (reason) {
        setError(reason instanceof Error ? reason.message : '充值失败。')
      }
    })
  }

  return (
    <Drawer
      title={`为 ${userName} 充值`}
      description="发放辰星点到该用户的钱包。辰星点用于购买套餐，不是真实货币。"
      onClose={onClose}
      onSubmit={(event) => void submit(event)}
      busy={saving}
      footer={
        <>
          <Button type="button" variant="ghost" onClick={onClose} disabled={saving}>取消</Button>
          <Button type="submit" icon="wallet" disabled={saving}>{saving ? '充值中…' : '确认充值'}</Button>
        </>
      }
    >
      {error ? <Notice tone="warning">{error}</Notice> : null}
      <HudPanel className="space-y-4 !p-5">
        <Field
          label="数量（辰星点）"
          icon="wallet"
          type="number"
          min={1}
          step={1}
          value={amount}
          onChange={(event) => setAmount(event.target.value)}
          hint={`1 到 ${MAX_CREDIT_AMOUNT.toLocaleString('zh-CN')} 的整数`}
          required
        />
        <TextAreaField
          label="备注（可选）"
          value={note}
          onChange={(event) => setNote(event.target.value)}
          placeholder="例如活动发放、补偿。"
          hint={`最多 ${MAX_CREDIT_NOTE_CHARS} 字`}
        />
      </HudPanel>
    </Drawer>
  )
}
