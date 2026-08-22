import { useEffect, useRef, useState } from 'react'

/**
 * 开场闸门（lamalama 式打开动画）：整屏盖板 → 计数到 100 → 向上滑出揭示主页。
 * 是否播放由调用方决定（landing 按 sessionStorage + reduced-motion 门控）；
 * 滑出完成后经 onDone 卸载，盖板不留在 DOM 里。
 */
export function IntroGate({ onDone }: { onDone: () => void }) {
  const openerRef = useRef<HTMLElement | null>(null)
  const gateRef = useRef<HTMLDivElement>(null)
  const [count, setCount] = useState(0)
  const [leaving, setLeaving] = useState(false)

  useEffect(() => {
    openerRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null
    gateRef.current?.focus()
    return () => {
      if (openerRef.current?.isConnected) openerRef.current.focus()
    }
  }, [])

  useEffect(() => {
    const timer = window.setInterval(() => {
      setCount((value) => Math.min(100, value + Math.ceil(Math.random() * 7)))
    }, 40)
    return () => window.clearInterval(timer)
  }, [])

  useEffect(() => {
    if (count < 100) return
    const leaveTimer = window.setTimeout(() => setLeaving(true), 240)
    const doneTimer = window.setTimeout(onDone, 240 + 800)
    return () => {
      window.clearTimeout(leaveTimer)
      window.clearTimeout(doneTimer)
    }
  }, [count, onDone])

  return (
    <div ref={gateRef} className={`cx-intro${leaving ? ' is-leaving' : ''}`} role="dialog" aria-modal="true" aria-label="正在加载辰星通行证" tabIndex={-1}>
      <span className="cx-intro-tag chenxing-mono">[ Chenxing Auth ]</span>
      <div className="flex flex-col items-center">
        <span className="cx-intro-count chenxing-mono">{String(count).padStart(3, '0')}%</span>
        <p className="chenxing-mono mt-4 text-[10px] uppercase tracking-[0.3em] text-[var(--chenxing-muted-foreground)]">正在接入星门认证中枢</p>
      </div>
      <span className="cx-intro-bar" style={{ transform: `scaleX(${count / 100})` }} />
    </div>
  )
}
