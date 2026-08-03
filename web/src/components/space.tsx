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
    }
    const draw = () => {
      frame += 1
      ctx.clearRect(0, 0, width, height)
      for (const star of stars) {
        const twinkle = 0.45 + Math.sin(frame * 0.02 + star.tw) * 0.35
        ctx.beginPath()
        ctx.fillStyle = `rgba(186, 230, 253, ${0.25 + star.z * 0.55 * twinkle})`
        ctx.arc(star.x, star.y, star.r * (0.6 + star.z), 0, Math.PI * 2)
        ctx.fill()
      }
      raf = requestAnimationFrame(draw)
    }
    resize()
    draw()
    window.addEventListener('resize', resize)
    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener('resize', resize)
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
