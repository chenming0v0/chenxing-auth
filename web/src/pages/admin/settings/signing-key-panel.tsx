import { useState } from 'react'
import { apiFetch, type KeyRotationResponse } from '../../../api'
import { Button, HudPanel, Icon } from '@chenxing/ui'
import type { SettingsMessageSink } from './panel'

/** 签名密钥不是设置资源：只有一个轮换动作（POST），没有草稿，也不参与脏状态聚合。 */
export function SigningKeyPanel({ canRotate, onMessage }: { canRotate: boolean; onMessage: SettingsMessageSink }) {
  const [result, setResult] = useState<KeyRotationResponse | null>(null)
  const [busy, setBusy] = useState(false)

  async function rotate() {
    if (!canRotate || !window.confirm('确认轮换签名密钥吗？\n轮换后新密钥立即用于签发；旧公钥会在 KEY_ROTATION_GRACE_SECONDS 配置的保留窗口内继续用于验签（该窗口需覆盖 Access Token 和 ID Token 有效期），过期的旧密钥材料将在后续启动或轮换时清理。')) return
    setBusy(true)
    try {
      setResult(await apiFetch<KeyRotationResponse>('/api/v1/admin/keys/rotate', { method: 'POST' }))
      onMessage('签名密钥已轮换。')
    } catch (reason) {
      onMessage(reason instanceof Error ? reason.message : '签名密钥轮换失败。', 'warning')
    } finally {
      setBusy(false)
    }
  }

  return (
    <HudPanel>
      <h2 className="chenxing-h2 flex items-center gap-2">
        <Icon name="key-round" className="text-[var(--chenxing-cyan)]" size={18} />
        签名密钥
      </h2>
      <p className="chenxing-caption mt-1.5">响应只返回 kid 和已发布公钥数量，不包含私钥材料。</p>
      {result ? (
        <div className="mt-5 grid gap-3 sm:grid-cols-2">
          <div className="rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(4,8,16,0.4)] px-4 py-3">
            <p className="chenxing-label mb-1">当前 key_id</p>
            <p className="chenxing-mono text-sm text-[var(--chenxing-ice)]">{result.key_id}</p>
          </div>
          <div className="rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(4,8,16,0.4)] px-4 py-3">
            <p className="chenxing-label mb-1">已发布公钥数量</p>
            <p className="chenxing-display text-2xl">{result.published_key_count}</p>
          </div>
        </div>
      ) : null}
      <div className="mt-5">
        <Button variant="danger" icon="refresh-cw" disabled={!canRotate || busy} onClick={() => void rotate()}>
          {canRotate ? '轮换签名密钥' : '缺少 rotate_keys 权限'}
        </Button>
      </div>
    </HudPanel>
  )
}
