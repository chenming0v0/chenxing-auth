import { useEffect, useRef, type ReactNode } from 'react'

function Starfield({ opacity = 0.7 }: { opacity?: number }) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return
    let frame = 0
    let stars: Array<{ x: number; y: number; z: number; r: number; tw: number }> = []
    let width = 0
    let height = 0
    let raf = 0
    let running = false
    /* 画一帧星野：frame 只参与闪烁相位。静态帧取 0，每颗星落在自身自然亮度上，
       视觉上与动画的某一瞬间等价，只是不再随时间变化。 */
    const paint = (f: number) => {
      ctx.clearRect(0, 0, width, height)
      for (const star of stars) {
        const twinkle = 0.45 + Math.sin(f * 0.02 + star.tw) * 0.35
        ctx.beginPath()
        ctx.fillStyle = `rgba(186, 230, 253, ${0.25 + star.z * 0.55 * twinkle})`
        ctx.arc(star.x, star.y, star.r * (0.6 + star.z), 0, Math.PI * 2)
        ctx.fill()
      }
    }
    const resize = () => {
      width = canvas.width = canvas.offsetWidth * devicePixelRatio
      height = canvas.height = canvas.offsetHeight * devicePixelRatio
      stars = []
      const count = Math.floor((width * height) / 8500)
      for (let i = 0; i < count; i += 1) {
        stars.push({
          x: Math.random() * width,
          y: Math.random() * height,
          z: Math.random(),
          r: Math.random() * 1.3 + 0.3,
          tw: Math.random() * Math.PI * 2,
        })
      }
      // 缩放会清空画布；静止模式下补一帧，避免星空变空白
      if (!running) paint(0)
    }
    const stop = () => {
      running = false
      cancelAnimationFrame(raf)
      paint(0)
    }
    const start = () => {
      if (running) return
      running = true
      const loop = () => {
        frame += 1
        paint(frame)
        raf = requestAnimationFrame(loop)
      }
      raf = requestAnimationFrame(loop)
    }
    /* prefers-reduced-motion: reduce 下只画一个静态星野，不跑 RAF 循环；
       偏好中途变化时跟随切换，无需刷新页面。 */
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    const sync = () => (mq.matches ? stop() : start())
    resize()
    sync()
    window.addEventListener('resize', resize)
    mq.addEventListener('change', sync)
    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener('resize', resize)
      mq.removeEventListener('change', sync)
    }
  }, [])
  return <canvas ref={canvasRef} className="absolute inset-0 h-full w-full" style={{ opacity }} aria-hidden="true" />
}

export function SpaceBackdrop({
  children,
  className = '',
  opacity = 0.7,
  dense = false,
}: {
  children: ReactNode
  className?: string
  opacity?: number
  dense?: boolean
}) {
  return (
    <main className={`cx-space-root ${className}`}>
      <div className={`chenxing-nebula ${dense ? 'left-[-14%] top-[-18%] h-[560px] w-[560px] opacity-15' : 'left-[-16%] top-[-14%] h-[580px] w-[580px] opacity-25'} bg-[var(--chenxing-primary)]`} />
      <div className={`chenxing-nebula ${dense ? 'right-[-12%] top-[30%] h-[480px] w-[480px] opacity-10' : 'right-[-12%] bottom-[-18%] h-[540px] w-[540px] opacity-15'} bg-[var(--chenxing-cyan)]`} />
      {!dense ? <div className="chenxing-nebula left-[30%] bottom-[-20%] h-[560px] w-[560px] bg-[var(--chenxing-primary)] opacity-15" /> : null}
      <Starfield opacity={opacity} />
      <div className={`chenxing-grid absolute inset-0 ${dense ? '-z-10' : ''}`} />
      <div className={`chenxing-vignette absolute inset-0 ${dense ? '-z-10' : ''}`} />
      {children}
    </main>
  )
}
