import { useEffect, useRef } from "react";

interface Star {
  x: number; y: number; z: number; r: number; tw: number; sp: number;
}

/** Animated canvas starfield with twinkling + slow parallax drift */
export default function Starfield({ density = 0.00014, className = "" }: { density?: number; className?: string }) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current!;
    const ctx = canvas.getContext("2d")!;
    let stars: Star[] = [];
    let raf = 0;
    let w = 0, h = 0;

    const resize = () => {
      w = canvas.width = canvas.offsetWidth * devicePixelRatio;
      h = canvas.height = canvas.offsetHeight * devicePixelRatio;
      const count = Math.floor(canvas.offsetWidth * canvas.offsetHeight * density);
      stars = Array.from({ length: count }, () => ({
        x: Math.random() * w,
        y: Math.random() * h,
        z: Math.random(),
        r: Math.random() * 1.4 + 0.3,
        tw: Math.random() * Math.PI * 2,
        sp: Math.random() * 0.06 + 0.01,
      }));
    };

    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(canvas);

    let t = 0;
    const draw = () => {
      t += 0.016;
      ctx.clearRect(0, 0, w, h);
      for (const s of stars) {
        s.y -= s.sp * (0.4 + s.z) * devicePixelRatio;
        if (s.y < -4) { s.y = h + 4; s.x = Math.random() * w; }
        const alpha = 0.25 + 0.75 * Math.abs(Math.sin(t * (0.5 + s.z) + s.tw));
        const hue = s.z > 0.75 ? "199, 210, 254" : s.z > 0.4 ? "224, 231, 255" : "165, 243, 252";
        ctx.beginPath();
        ctx.arc(s.x, s.y, s.r * devicePixelRatio, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${hue}, ${alpha * (0.35 + s.z * 0.65)})`;
        ctx.fill();
        if (s.r > 1.3 && alpha > 0.85) {
          ctx.beginPath();
          ctx.arc(s.x, s.y, s.r * 3 * devicePixelRatio, 0, Math.PI * 2);
          ctx.fillStyle = `rgba(${hue}, 0.06)`;
          ctx.fill();
        }
      }
      raf = requestAnimationFrame(draw);
    };
    raf = requestAnimationFrame(draw);

    return () => { cancelAnimationFrame(raf); ro.disconnect(); };
  }, [density]);

  return <canvas ref={ref} className={`absolute inset-0 h-full w-full ${className}`} />;
}
