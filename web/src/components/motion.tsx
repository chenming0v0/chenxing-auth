import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from 'react'

/** 当前用户是否要求减少动态效果。matchMedia 不可用时按「减少」处理，宁可静止不可晕眩。 */
export function usePrefersReducedMotion() {
  const [reduced, setReduced] = useState(
    () => typeof window.matchMedia !== 'function' || window.matchMedia('(prefers-reduced-motion: reduce)').matches,
  )
  useEffect(() => {
    if (typeof window.matchMedia !== 'function') return
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    const onChange = () => setReduced(mq.matches)
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [])
  return reduced
}

/**
 * 滚动进入视口后渐现的容器：进入一次后保持可见，不反复播放。
 * 视觉状态全部在 landing.css 的 .cx-reveal 里，这里只负责切换 is-visible。
 * delay 经 CSS 变量传入，reduced-motion 下 CSS 侧直接无视过渡常显。
 */
export function Reveal({ children, delay = 0, className = '' }: { children: ReactNode; delay?: number; className?: string }) {
  const ref = useRef<HTMLDivElement>(null)
  const [visible, setVisible] = useState(false)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    if (typeof IntersectionObserver === 'undefined') {
      setVisible(true)
      return
    }
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setVisible(true)
          observer.disconnect()
        }
      },
      { threshold: 0.15, rootMargin: '0px 0px -6% 0px' },
    )
    observer.observe(el)
    return () => observer.disconnect()
  }, [])
  return (
    <div
      ref={ref}
      className={`cx-reveal${visible ? ' is-visible' : ''} ${className}`}
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
  const ref = useRef<HTMLSpanElement>(null)
  const reduced = usePrefersReducedMotion()
  const [progress, setProgress] = useState(reduced ? 1 : 0)
  useEffect(() => {
    if (reduced) {
      setProgress(1)
      return
    }
    const el = ref.current
    if (!el || typeof IntersectionObserver === 'undefined') {
      setProgress(1)
      return
    }
    let raf = 0
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (!entry.isIntersecting) return
        observer.disconnect()
        const start = performance.now()
        const tick = (now: number) => {
          const t = Math.min((now - start) / duration, 1)
          setProgress(t === 1 ? 1 : 1 - Math.pow(2, -10 * t))
          if (t < 1) raf = requestAnimationFrame(tick)
        }
        raf = requestAnimationFrame(tick)
      },
      { threshold: 0.4 },
    )
    observer.observe(el)
    return () => {
      observer.disconnect()
      cancelAnimationFrame(raf)
    }
  }, [reduced, duration])
  const value = target * progress
  const text = (grouping ? Math.round(value).toLocaleString('en-US') : value.toFixed(decimals)) + suffix
  return (
    <span ref={ref} className={className}>
      {text}
    </span>
  )
}
