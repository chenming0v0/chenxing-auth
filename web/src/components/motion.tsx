import { useEffect, useRef, useState, type CSSProperties, type ReactNode, type RefObject } from 'react'

/** Subscribe to MediaQueryList changes across modern and legacy browser APIs. */
export function subscribeToMediaQuery(mq: MediaQueryList, listener: (event: MediaQueryListEvent) => void): () => void {
  if (typeof mq.addEventListener === 'function' && typeof mq.removeEventListener === 'function') {
    mq.addEventListener('change', listener)
    return () => mq.removeEventListener('change', listener)
  }
  if (typeof mq.addListener === 'function' && typeof mq.removeListener === 'function') {
    mq.addListener(listener)
    return () => mq.removeListener(listener)
  }
  return () => {}
}

/** 当前用户是否要求减少动态效果。matchMedia 不可用时按「减少」处理，宁可静止不可晕眩。 */
export function usePrefersReducedMotion() {
  const [reduced, setReduced] = useState(
    () => typeof window.matchMedia !== 'function' || window.matchMedia('(prefers-reduced-motion: reduce)').matches,
  )
  useEffect(() => {
    if (typeof window.matchMedia !== 'function') return
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    const onChange = () => setReduced(mq.matches)
    return subscribeToMediaQuery(mq, onChange)
  }, [])
  return reduced
}

/** 元素进入视口一次后保持 true；IntersectionObserver 不可用时立即视为可见。 */
export function useInView<T extends HTMLElement>(threshold = 0.2): [RefObject<T | null>, boolean] {
  const ref = useRef<T>(null)
  const [inView, setInView] = useState(false)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    if (typeof IntersectionObserver === 'undefined') {
      setInView(true)
      return
    }
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setInView(true)
          observer.disconnect()
        }
      },
      { threshold, rootMargin: '0px 0px -6% 0px' },
    )
    observer.observe(el)
    return () => observer.disconnect()
  }, [threshold])
  return [ref, inView]
}

/**
 * 滚动进入视口后渐现的容器。variant="rise" 整体上移淡入；variant="mask" 内容
 * 从遮罩下方向上跳出（lamalama 式逐行揭示），适合标题/段落块。
 * 视觉状态全部在 landing.css，这里只切换 is-visible；reduced-motion 下 CSS 常显。
 */
export function Reveal({
  children,
  delay = 0,
  className = '',
  variant = 'rise',
}: {
  children: ReactNode
  delay?: number
  className?: string
  variant?: 'rise' | 'mask'
}) {
  const [ref, inView] = useInView<HTMLDivElement>(0.15)
  if (variant === 'mask') {
    return (
      <div ref={ref} className={`cx-mask-scroll${inView ? ' is-visible' : ''} ${className}`}>
        <div className="cx-mask-scroll-inner" style={{ '--reveal-delay': `${delay}ms` } as CSSProperties}>
          {children}
        </div>
      </div>
    )
  }
  return (
    <div
      ref={ref}
      className={`cx-reveal${inView ? ' is-visible' : ''} ${className}`}
      style={{ '--reveal-delay': `${delay}ms` } as CSSProperties}
    >
      {children}
    </div>
  )
}

/**
 * 滚动进入视口后从 0 计数到目标值的数字。格式化（小数位 / 千分位 / 后缀）由调用方声明，
 * 动画只推进一个 0→1 的进度，easeOutExpo 让末段减速。reduced-motion 直接落终值。
 */
export function CountUp({
  target,
  decimals = 0,
  suffix = '',
  grouping = false,
  duration = 1800,
  className = '',
}: {
  target: number
  decimals?: number
  suffix?: string
  grouping?: boolean
  duration?: number
  className?: string
}) {
  const reduced = usePrefersReducedMotion()
  const [ref, inView] = useInView<HTMLSpanElement>(0.4)
  const [progress, setProgress] = useState(reduced ? 1 : 0)
  useEffect(() => {
    if (reduced) {
      setProgress(1)
      return
    }
    if (!inView) return
    let raf = 0
    const start = performance.now()
    const tick = (now: number) => {
      const t = Math.min((now - start) / duration, 1)
      setProgress(t === 1 ? 1 : 1 - Math.pow(2, -10 * t))
      if (t < 1) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [reduced, inView, duration])
  const value = target * progress
  const text = (grouping ? Math.round(value).toLocaleString('en-US') : value.toFixed(decimals)) + suffix
  return (
    <span ref={ref} className={className}>
      {text}
    </span>
  )
}

/**
 * 打字机轮换词：逐字打出 → 停留 → 逐字删除 → 切换下一个词，循环播放。
 * 光标（.cx-caret）由 CSS 闪烁。reduced-motion 下静态显示第一个词。
 */
export function Typewriter({
  words,
  className = '',
  typeMs = 110,
  eraseMs = 45,
  holdMs = 1800,
}: {
  words: string[]
  className?: string
  typeMs?: number
  eraseMs?: number
  holdMs?: number
}) {
  const reduced = usePrefersReducedMotion()
  const [word, setWord] = useState(0)
  const [len, setLen] = useState(0)
  const [phase, setPhase] = useState<'typing' | 'holding' | 'erasing'>('typing')
  useEffect(() => {
    if (reduced) return
    const current = words[word]
    let timer: number
    if (phase === 'typing') {
      timer = window.setTimeout(() => (len < current.length ? setLen(len + 1) : setPhase('holding')), typeMs)
    } else if (phase === 'holding') {
      timer = window.setTimeout(() => setPhase('erasing'), holdMs)
    } else {
      timer = window.setTimeout(() => {
        if (len > 0) {
          setLen(len - 1)
        } else {
          setWord((word + 1) % words.length)
          setPhase('typing')
        }
      }, eraseMs)
    }
    return () => window.clearTimeout(timer)
  }, [reduced, words, word, len, phase, typeMs, eraseMs, holdMs])
  if (reduced) return <span className={className}>{words[0]}</span>
  return (
    <span className={className}>
      {words[word].slice(0, len)}
      <span className="cx-caret" aria-hidden="true" />
    </span>
  )
}

/** 进入视口后从左向右绘制展开的分割线（transform-origin: left 的 scaleX 展开）。 */
export function DrawLine({ className = '' }: { className?: string }) {
  const [ref, inView] = useInView<HTMLDivElement>(0.6)
  return <div ref={ref} aria-hidden="true" className={`cx-draw-line${inView ? ' is-visible' : ''} ${className}`} />
}

/**
 * 滚动触发的打字机式乱码解码（lamalama 顶栏微标签同款，见其 text reveal 实现）：
 * 出现 = 两道从左到右的波——第一道逐字「打出」该位置固定的乱码字符（打字机），
 * 稍后第二道波跟进把乱码逐位替换成真字；文字切换 = 旧字先从右往左退格删完，
 * 再打出新字。乱码字符每个位置只随机一次、不原地翻滚，这正是参考站的手感。
 * 槽位固定 1em 宽、按目标长度预留：绝对居中的容器不会因打字/退格而左右晃动。
 * 有意不接 prefers-reduced-motion：0.4s 原位字符替换，无位移无缩放，接了会让
 * 关闭系统动画的 Windows 设备整体丢失这个品牌入场效果。
 */
const SCRAMBLE_POOL = ['#', '#', '#', '#', '#', '$', '*', '@', '(', '0', '%', '1', '>']

export function ScrambleText({ text, active, className = '' }: {
  text: string
  active: boolean
  className?: string
}) {
  const [slots, setSlots] = useState<string[]>([])
  /* 跨 text 变更保留屏上状态：切换标签时才能从当前已显示的字数开始退格 */
  const shownRef = useRef(0)
  const currentRef = useRef('')
  useEffect(() => {
    if (!active) {
      shownRef.current = 0
      currentRef.current = ''
      setSlots([])
      return
    }
    const target = Array.from(text)
    /* 每个位置的乱码只随机一次（lamalama randomize 同款），打出后静止直到被真字替换 */
    const garbage = target.map(() => SCRAMBLE_POOL[Math.floor(Math.random() * SCRAMBLE_POOL.length)])
    const old = Array.from(currentRef.current)
    currentRef.current = text
    let shown = old.length > 0 && old.join('') !== text ? Math.min(shownRef.current, old.length) : 0
    let phase: 'deleting' | 'typing' = shown > 0 ? 'deleting' : 'typing'
    let frame = 0
    let resolved = 0
    /* 45ms/帧。打字波每帧 +1；解析波延迟 4 帧（≈0.2s，lamalama 的第二道波）后跟进。
       四字标签：打完 180ms，全部解析完 ≈360ms；退格 ≈180ms。 */
    const resolveDelayFrames = 4
    const paint = () => {
      if (phase === 'deleting') {
        setSlots(old.map((ch, i) => (i < shown ? ch : '')))
      } else {
        setSlots(target.map((ch, i) => (i < resolved ? ch : i < shown ? garbage[i] : '')))
      }
      shownRef.current = phase === 'deleting' ? shown : Math.max(shown, resolved)
    }
    paint()
    const id = window.setInterval(() => {
      if (phase === 'deleting') {
        shown -= 1
        if (shown <= 0) {
          shown = 0
          phase = 'typing'
          frame = 0
        }
      } else {
        frame += 1
        if (shown < target.length) shown += 1
        if (frame > resolveDelayFrames && resolved < shown) resolved += 1
        if (resolved >= target.length) window.clearInterval(id)
      }
      paint()
    }, 45)
    return () => window.clearInterval(id)
  }, [active, text])
  if (!active) return null
  return (
    <span className={className}>
      <span className="sr-only">{text}</span>
      {slots.map((ch, i) => (
        <span key={i} aria-hidden="true" className="cx-scramble-char">
          {ch}
        </span>
      ))}
    </span>
  )
}
