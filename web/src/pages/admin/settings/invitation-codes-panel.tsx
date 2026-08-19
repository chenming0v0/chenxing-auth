import { useEffect, useState } from 'react'
import { apiFetch } from '../../../api'
import { Button, Field, HudPanel, Icon, Notice } from '../../../components/ui'

type CodeSummary = {
  id: number
  label: string | null
  max_uses: number
  use_count: number
  expires_at: string | null
  disabled_at: string | null
  created_at: string
}
type CreatedCode = CodeSummary & { code: string }

export function InvitationCodesPanel() {
  const [codes, setCodes] = useState<CodeSummary[]>([])
  const [created, setCreated] = useState<CreatedCode[]>([])
  const [count, setCount] = useState('1')
  const [maxUses, setMaxUses] = useState('1')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')

  async function load() {
    const value = await apiFetch<CodeSummary[]>('/api/v1/admin/registration-invitation-codes')
    setCodes(Array.isArray(value) ? value : [])
  }

  useEffect(() => { void load().catch(() => setMessage('邀请码列表加载失败。')) }, [])

  async function create() {
    setBusy(true)
    setMessage('')
    try {
      const value = await apiFetch<CreatedCode[]>('/api/v1/admin/registration-invitation-codes', {
        method: 'POST',
        body: JSON.stringify({ count: Number(count), max_uses: Number(maxUses), expires_at: null, label: null }),
      })
      setCreated(value)
      await load()
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : '邀请码生成失败。')
    } finally {
      setBusy(false)
    }
  }

  async function disable(id: number) {
    if (!window.confirm('确认停用这个邀请码吗？停用后不可恢复。')) return
    setBusy(true)
    try {
      await apiFetch(`/api/v1/admin/registration-invitation-codes/${id}/disable`, { method: 'POST' })
      await load()
    } finally {
      setBusy(false)
    }
  }

  return (
    <HudPanel>
      <h2 className="chenxing-h2 flex items-center gap-2"><Icon name="ticket" className="text-[var(--chenxing-cyan)]" size={18} />注册邀请码</h2>
      <p className="chenxing-caption mt-1.5">明文仅在生成后展示一次；列表只保留使用状态。</p>
      {message ? <div className="mt-4"><Notice tone="warning">{message}</Notice></div> : null}
      <div className="mt-5 grid gap-3 sm:grid-cols-2">
        <Field label="生成数量" type="number" min="1" max="100" value={count} onChange={(event) => setCount(event.target.value)} />
        <Field label="每码可用次数" type="number" min="1" max="10000" value={maxUses} onChange={(event) => setMaxUses(event.target.value)} />
      </div>
      <div className="mt-4"><Button icon="plus" disabled={busy} onClick={() => void create()}>生成邀请码</Button></div>
      {created.length ? <div className="mt-5"><Notice tone="warning">请立即保存以下邀请码，离开后无法再次查看。</Notice><div className="mt-3 space-y-2">{created.map((item) => <code key={item.id} className="block break-all chenxing-mono text-sm text-[var(--chenxing-ice)]">{item.code}</code>)}</div></div> : null}
      <div className="mt-5 space-y-2">{codes.map((item) => {
        const exhausted = item.use_count >= item.max_uses
        const inactive = Boolean(item.disabled_at) || exhausted || Boolean(item.expires_at && Date.parse(item.expires_at) <= Date.now())
        return <div key={item.id} className="flex items-center justify-between gap-3 border-t border-[var(--chenxing-border)] py-3"><span className="chenxing-caption">#{item.id} · {item.use_count}/{item.max_uses} 次 · {inactive ? '不可用' : '可用'}</span><Button variant="danger" disabled={busy || Boolean(item.disabled_at)} onClick={() => void disable(item.id)}>停用</Button></div>
      })}</div>
    </HudPanel>
  )
}
