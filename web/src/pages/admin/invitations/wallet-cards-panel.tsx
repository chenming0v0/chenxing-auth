import { useEffect, useState, type FormEvent } from 'react'
import { apiFetch, type CreatedWalletRedemptionCard, type WalletRedemptionCardSummary } from '../../../api'
import { Badge, Button, CopyValue, Field, HudPanel, Icon, Notice } from '../../../components/ui'
import { DataTable, TablePanel } from '../../../components/data-table'
import { formatDate } from '../../../data'

const CARDS_PATH = '/api/v1/admin/wallet/redemption-codes'

function cardStatus(card: WalletRedemptionCardSummary): { label: string; tone: 'success' | 'warning' | 'neutral' } {
  if (card.disabled_at) return { label: '已停用', tone: 'neutral' }
  if (card.expires_at && new Date(card.expires_at).getTime() <= Date.now()) return { label: '已过期', tone: 'warning' }
  if (card.use_count >= card.max_uses) return { label: '已用尽', tone: 'warning' }
  return { label: '可用', tone: 'success' }
}

export function WalletCardsPanel() {
  const [cards, setCards] = useState<WalletRedemptionCardSummary[] | null>(null)
  const [created, setCreated] = useState<CreatedWalletRedemptionCard[]>([])
  const [amount, setAmount] = useState('')
  const [count, setCount] = useState('1')
  const [maxUses, setMaxUses] = useState('1')
  const [label, setLabel] = useState('')
  const [expiresAt, setExpiresAt] = useState('')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')

  async function load() {
    const result = await apiFetch<WalletRedemptionCardSummary[]>(CARDS_PATH)
    setCards(Array.isArray(result) ? result : [])
  }

  useEffect(() => { void load().catch(() => { setCards([]); setMessage('兑换卡列表加载失败。') }) }, [])

  async function create(event: FormEvent) {
    event.preventDefault()
    const pointsValue = Number(amount)
    const countValue = Number(count)
    const usesValue = Number(maxUses)
    if (!Number.isInteger(pointsValue) || pointsValue < 1) { setMessage('面值必须是大于 0 的整数。'); return }
    if (!Number.isInteger(countValue) || countValue < 1 || countValue > 100) { setMessage('生成数量必须在 1 到 100 之间。'); return }
    if (!Number.isInteger(usesValue) || usesValue < 1 || usesValue > 10000) { setMessage('每码可用次数必须在 1 到 10000 之间。'); return }
    setBusy(true)
    setMessage('')
    try {
      const result = await apiFetch<CreatedWalletRedemptionCard[]>(CARDS_PATH, {
        method: 'POST',
        body: JSON.stringify({ points: pointsValue, count: countValue, max_uses: usesValue, label: label.trim() || null, expires_at: expiresAt ? new Date(expiresAt).toISOString() : null }),
      })
      setCreated(Array.isArray(result) ? result : [])
      await load()
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : '兑换卡生成失败。')
    } finally { setBusy(false) }
  }

  async function disable(id: number) {
    if (!window.confirm('确认停用这张兑换卡吗？停用后不可恢复。')) return
    setBusy(true)
    setMessage('')
    try { await apiFetch(`${CARDS_PATH}/${id}/disable`, { method: 'POST' }); await load() }
    catch (reason) { setMessage(reason instanceof Error ? reason.message : '兑换卡停用失败。') }
    finally { setBusy(false) }
  }

  return (
    <div className="flex flex-col gap-6">
      {message ? <Notice tone="warning">{message}</Notice> : null}
      <HudPanel as="section" aria-labelledby="wallet-cards-title">
        <h2 id="wallet-cards-title" className="chenxing-h2 flex items-center gap-2"><Icon name="wallet" className="text-[var(--chenxing-cyan)]" size={18} />生成兑换卡</h2>
        <p className="chenxing-caption mt-1.5">明文只在生成后展示一次，请立即交付或保存。</p>
        <form className="mt-5 grid gap-3 sm:grid-cols-2" onSubmit={create}>
          <Field label="面值（辰星点）" type="number" min="1" value={amount} onChange={(event) => setAmount(event.target.value)} required />
          <Field label="生成数量" type="number" min="1" max="100" value={count} onChange={(event) => setCount(event.target.value)} />
          <Field label="每码可用次数" type="number" min="1" max="10000" value={maxUses} onChange={(event) => setMaxUses(event.target.value)} />
          <Field label="标签" value={label} onChange={(event) => setLabel(event.target.value)} placeholder="可选" />
          <Field label="过期时间" type="datetime-local" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} />
          <div className="flex items-end"><Button type="submit" icon="plus" disabled={busy}>{busy ? '生成中…' : '生成兑换卡'}</Button></div>
        </form>
      </HudPanel>
      {created.length ? <HudPanel><Notice tone="warning">以下明文离开页面后无法再次查看，请立即保存。</Notice><div className="mt-4 space-y-2">{created.map((card) => <CopyValue key={card.id} value={card.code} ariaLabel={`复制兑换码 ${card.id}`} />)}</div></HudPanel> : null}
      <TablePanel icon="wallet" title="兑换卡列表" description="列表不包含明文。">
        <DataTable minWidth={760} columns={['ID', '面值', '已用/上限', '状态', '创建时间', { label: '操作', align: 'right' }]} empty={cards == null ? '正在加载兑换卡。' : cards.length ? null : '还没有兑换卡。'}>
          {cards?.map((card) => { const status = cardStatus(card); return <tr key={card.id}>
            <td className="chenxing-mono text-xs">#{card.id}</td><td className="chenxing-mono text-sm">{card.points.toLocaleString('zh-CN')} 点</td><td className="chenxing-mono text-xs">{card.use_count}/{card.max_uses}</td><td><Badge tone={status.tone}>{status.label}</Badge></td><td className="chenxing-caption">{formatDate(card.created_at)}</td><td className="text-right"><Button variant="danger" disabled={busy || Boolean(card.disabled_at)} onClick={() => void disable(card.id)}>停用</Button></td>
          </tr> })}
        </DataTable>
      </TablePanel>
    </div>
  )
}
