import { useEffect, useRef, type ReactNode } from 'react'
import { subscribeToMediaQuery } from './motion'

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
    const unsubscribe = subscribeToMediaQuery(mq, sync)
    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener('resize', resize)
      unsubscribe()
    }
  }, [])
  return <canvas ref={canvasRef} className="absolute inset-0 h-full w-full" style={{ opacity }} aria-hidden="true" />
}

/**
 * 曲速星野：星光从画面中心向外加速飞散成线条流光，仅用于落地页 hero。
 * 与 Starfield 同一套约定：DPR 感知、resize 重建、reduced-motion 下只画一帧
 * 静态星点（速度清零后拖线退化为圆点），不跑 RAF 循环。
 */
export function WarpField({ className = '', stars = 200 }: { className?: string; stars?: number }) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return
    type Star = { x: number; y: number; z: number; pz: number; gold: boolean }
    let width = 0
    let height = 0
    let raf = 0
    let running = false
    let field: Star[] = []
    /* z 是深度（1 最远，趋 0 贴脸）；pz 是上一帧深度，两点连线即拖尾 */
    const spawn = (): Star => ({
      x: Math.random() * 2 - 1,
      y: Math.random() * 2 - 1,
      z: Math.random() * 0.8 + 0.2,
      pz: 0,
      gold: Math.random() < 0.18,
    })
    const reset = () => {
      width = canvas.width = canvas.offsetWidth * devicePixelRatio
      height = canvas.height = canvas.offsetHeight * devicePixelRatio
      field = Array.from({ length: stars }, () => {
        const star = spawn()
        star.pz = star.z
        return star
      })
    }
    const project = (star: Star, z: number): [number, number] => [
      width / 2 + (star.x / z) * width * 0.5,
      height / 2 + (star.y / z) * height * 0.5,
    ]
    const respawn = (star: Star) => {
      Object.assign(star, spawn())
      star.pz = star.z
    }
    const paint = (animate: boolean) => {
      ctx.clearRect(0, 0, width, height)
      ctx.lineCap = 'round'
      for (const star of field) {
        if (animate) {
          star.pz = star.z
          star.z -= 0.006 + (1 - star.z) * 0.012
          if (star.z <= 0.04) respawn(star)
        }
        const [x1, y1] = project(star, star.pz)
        const [x2, y2] = project(star, star.z)
        if (x2 < 0 || x2 > width || y2 < 0 || y2 > height) {
          if (animate) respawn(star)
          continue
        }
        const depth = 1 - star.z
        ctx.strokeStyle = star.gold
          ? `rgba(245, 199, 106, ${0.12 + depth * 0.5})`
          : `rgba(165, 220, 255, ${0.1 + depth * 0.55})`
        ctx.lineWidth = (0.4 + depth * 2) * devicePixelRatio
        ctx.beginPath()
        ctx.moveTo(x1, y1)
        ctx.lineTo(x2, y2)
        ctx.stroke()
      }
    }
    const stop = () => {
      running = false
      cancelAnimationFrame(raf)
      paint(false)
    }
    const start = () => {
      if (running) return
      running = true
      const loop = () => {
        paint(true)
        raf = requestAnimationFrame(loop)
      }
      raf = requestAnimationFrame(loop)
    }
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    const sync = () => (mq.matches ? stop() : start())
    const resize = () => {
      reset()
      if (!running) paint(false)
    }
    resize()
    sync()
    window.addEventListener('resize', resize)
    const unsubscribe = subscribeToMediaQuery(mq, sync)
    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener('resize', resize)
      unsubscribe()
    }
  }, [stars])
  return <canvas ref={canvasRef} className={className} aria-hidden="true" />
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
      <div className={`chenxing-grid absolute inset-0 ${dense ? 'z-[var(--chenxing-z-backdrop)]' : ''}`} />
      <div className={`chenxing-vignette absolute inset-0 ${dense ? 'z-[var(--chenxing-z-backdrop)]' : ''}`} />
      {children}
    </main>
  )
}
