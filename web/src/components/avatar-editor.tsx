import { useLayoutEffect, useRef, useState, type PointerEvent as ReactPointerEvent } from 'react'
import { createPortal } from 'react-dom'
import { Button, Icon } from './ui'
import { useDrawerFocus } from './drawer'
import {
  EXPORT_EDGE,
  MAX_SCALE,
  MIN_SCALE,
  clampOffset,
  clampScale,
  localRejectionMessage,
  previewTransform,
  rejectDecodedSize,
  rejectExportSize,
  sourceRect,
  type CropTransform,
  type SourceSize,
} from './avatar-crop'

/**
 * 首帧兜底边长，仅用于 ResizeObserver 尚未回调前的一帧，以及 jsdom 这类没有布局
 * 引擎的环境。真实边长一律由 `.chenxing-avatar-viewport` 的 CSS 决定并实测得出，
 * 这里不是「第二个尺寸来源」。
 */
const FALLBACK_EDGE = 288

type AvatarEditorProps = {
  /** 已解码的源图。由调用方负责解码，编辑器只做取景。 */
  image: HTMLImageElement
  source: SourceSize
  busy?: boolean
  onCancel: () => void
  onConfirm: (blob: Blob) => void
}

/**
 * 头像取景器：拖拽定位 + 滑块缩放，确认时把取景框内容导出为方图。
 *
 * 取景框边长必须实测而不能写常量：尺寸由 CSS 按视口算（矮窗口下会缩小），一旦
 * JS 侧另存一份常量，两者不一致时预览和导出就会错位。预览走 CSS transform、导出走
 * canvas，两条路径共用 `avatar-crop` 里的同一套换算并接收同一个实测边长，
 * 因此所见即所得。
 */
export function AvatarEditor({ image, source, busy = false, onCancel, onConfirm }: AvatarEditorProps) {
  const [transform, setTransform] = useState<CropTransform>({ scale: MIN_SCALE, offsetX: 0, offsetY: 0 })
  const [edge, setEdge] = useState(FALLBACK_EDGE)
  const [error, setError] = useState('')
  const [exporting, setExporting] = useState(false)
  const exportGenerationRef = useRef(0)
  const containerRef = useDrawerFocus(cancel, busy || exporting)
  const viewportRef = useRef<HTMLDivElement>(null)
  const dragRef = useRef<{ pointerId: number; startX: number; startY: number; originX: number; originY: number } | null>(null)
  // 原生 wheel 监听器只挂一次；必须从 ref 读最新取景状态，否则连滚会吃到过期 scale。
  const transformRef = useRef(transform)
  const edgeRef = useRef(edge)
  const sourceRef = useRef(source)
  const busyRef = useRef(busy)
  transformRef.current = transform
  edgeRef.current = edge
  sourceRef.current = source
  busyRef.current = busy || exporting

  useLayoutEffect(() => {
    return () => { exportGenerationRef.current += 1 }
  }, [])
  // 渲染一帧再跳到实际尺寸。
  useLayoutEffect(() => {
    const element = viewportRef.current
    if (!element) return

    const measure = () => {
      const rect = element.getBoundingClientRect()
      // 取宽高较小值：CSS 用 aspect-ratio 推正方形，但布局未稳定时两者可能短暂不等，
      // 取小值保证换算永远落在可视区域内。0 是无效测量（元素尚未布局），保留上一次结果。
      const measured = Math.min(rect.width, rect.height)
      if (measured > 0) setEdge(measured)
    }

    measure()
    // jsdom 没有 ResizeObserver。测过一次即可，测试环境不会发生窗口尺寸变化。
    if (typeof ResizeObserver === 'undefined') return
    const observer = new ResizeObserver(measure)
    observer.observe(element)
    return () => observer.disconnect()
  }, [])

  // React 19 把 onWheel 注册成 passive，preventDefault 会被浏览器直接丢掉，
  // 页面跟着滚。必须自己挂 { passive: false } 的原生监听（Issue #370）。
  useLayoutEffect(() => {
    const element = viewportRef.current
    if (!element) return
    const onWheel = (event: WheelEvent) => {
      if (busyRef.current) return
      event.preventDefault()
      const current = transformRef.current
      const next = { ...current, scale: current.scale - event.deltaY * 0.002 }
      const clamped = { scale: clampScale(next.scale), ...clampOffset(sourceRef.current, edgeRef.current, next) }
      transformRef.current = clamped
      setTransform(clamped)
    }
    element.addEventListener('wheel', onWheel, { passive: false })
    return () => element.removeEventListener('wheel', onWheel)
  }, [])

  const preview = previewTransform(source, edge, transform)
  // 方向键步长跟随边长：固定步长在小取景框上会一步跨掉可平移余量的一大截。
  const keyStep = Math.max(4, Math.round(edge * 0.04))

  function applyTransform(next: CropTransform) {
    // 缩放会改变可平移余量，因此每次变换后都重新夹取，避免取景框露出图像外部。
    const clamped = { scale: clampScale(next.scale), ...clampOffset(source, edge, next) }
    transformRef.current = clamped
    setTransform(clamped)
  }

  function onPointerDown(event: ReactPointerEvent<HTMLDivElement>) {
    if (busy) return
    // setPointerCapture 让指针移出取景框后仍能继续拖拽，避免拖到边缘就"脱手"。
    event.currentTarget.setPointerCapture(event.pointerId)
    dragRef.current = {
      pointerId: event.pointerId,
      startX: event.clientX,
      startY: event.clientY,
      originX: transform.offsetX,
      originY: transform.offsetY,
    }
  }

  function onPointerMove(event: ReactPointerEvent<HTMLDivElement>) {
    const drag = dragRef.current
    if (!drag || drag.pointerId !== event.pointerId) return
    applyTransform({
      scale: transform.scale,
      offsetX: drag.originX + (event.clientX - drag.startX),
      offsetY: drag.originY + (event.clientY - drag.startY),
    })
  }

  function endDrag(event: ReactPointerEvent<HTMLDivElement>) {
    if (dragRef.current?.pointerId !== event.pointerId) return
    dragRef.current = null
  }

  function onKeyDown(event: React.KeyboardEvent<HTMLDivElement>) {
    if (busy) return
    const moves: Record<string, [number, number]> = {
      ArrowLeft: [-keyStep, 0],
      ArrowRight: [keyStep, 0],
      ArrowUp: [0, -keyStep],
      ArrowDown: [0, keyStep],
    }
    const move = moves[event.key]
    if (!move) return
    event.preventDefault()
    applyTransform({ scale: transform.scale, offsetX: transform.offsetX + move[0], offsetY: transform.offsetY + move[1] })
  }

  function cancel(): void {
    exportGenerationRef.current += 1
    setExporting(false)
    onCancel()
  }

  function confirm() {
    if (busy || exporting) return
    const generation = ++exportGenerationRef.current
    setExporting(true)
    setError('')
    const rejection = rejectDecodedSize(source)
    if (rejection) {
      setError(localRejectionMessage(rejection))
      setExporting(false)
      return
    }
    const canvas = document.createElement('canvas')
    canvas.width = EXPORT_EDGE
    canvas.height = EXPORT_EDGE
    const context = canvas.getContext('2d')
    if (!context) {
      setError('当前浏览器不支持图片裁剪。')
      setExporting(false)
      return
    }
    const rect = sourceRect(source, edge, transform)
    context.imageSmoothingQuality = 'high'
    context.drawImage(image, rect.x, rect.y, rect.width, rect.height, 0, 0, EXPORT_EDGE, EXPORT_EDGE)
    /* 导出 PNG 而不是 JPEG：服务端会统一重编码成 JPEG，此处再压一次只会叠加两代
       有损压缩。PNG 无损上传把唯一的有损环节留给服务端。 */
    canvas.toBlob((blob) => {
      if (generation !== exportGenerationRef.current) return
      setExporting(false)
      if (!blob) {
        setError('图片导出失败，请重试。')
        return
      }
      // 固定 512x512 PNG 正常远小于上传额度，但极端高频噪声图仍可能超出。
      // 与其让服务端回一个前端读不出错误码的 413，不如在这里明确拦住。
      const exportRejection = rejectExportSize(blob.size)
      if (exportRejection) {
        setError(localRejectionMessage(exportRejection))
        return
      }
      onConfirm(blob)
    }, 'image/png')
  }

  return createPortal(
    <div className="chenxing-drawer-overlay is-open" onClick={() => { if (!busy && !exporting) cancel() }}>
      <div
        ref={containerRef}
        className="chenxing-drawer is-open"
        role="dialog"
        aria-modal="true"
        aria-label="调整头像"
        aria-busy={busy || undefined}
        tabIndex={-1}
        onClick={(event) => event.stopPropagation()}
      >
        <div className="chenxing-drawer-header">
          <div>
            <h2 className="chenxing-h2">调整头像</h2>
            <p className="chenxing-caption mt-1">拖拽移动位置，滑块调整缩放。取景框内的方形区域即最终头像。</p>
          </div>
          <button type="button" className="chenxing-icon-btn" aria-label="关闭" onClick={cancel} disabled={busy || exporting}>
            <Icon name="x" size={16} />
          </button>
        </div>

        <div className="chenxing-drawer-body space-y-5">
          {/* 取景框本身是可聚焦的操作控件：拖拽有键盘等价物（方向键），
              滚轮有滑块等价物，因此键盘用户不依赖指针也能完成取景。
              尺寸不写内联样式——内联会盖掉 CSS 的响应式边长。 */}
          <div
            ref={viewportRef}
            className="chenxing-avatar-viewport"
            role="application"
            aria-label="头像取景框，方向键移动位置"
            tabIndex={0}
            onPointerDown={onPointerDown}
            onPointerMove={onPointerMove}
            onPointerUp={endDrag}
            onPointerCancel={endDrag}
            onKeyDown={onKeyDown}
          >
            <img
              src={image.src}
              alt=""
              draggable={false}
              className="chenxing-avatar-viewport-image"
              style={{
                width: preview.width,
                height: preview.height,
                transform: `translate(-50%, -50%) translate(${preview.translateX}px, ${preview.translateY}px)`,
              }}
            />
            <span className="chenxing-avatar-viewport-mask" aria-hidden="true" />
          </div>

          <div>
            <label className="chenxing-label" htmlFor="avatar-scale">缩放</label>
            <div className="flex items-center gap-3">
              <Icon name="search" size={14} className="text-[var(--chenxing-muted-foreground)]" />
              <input
                id="avatar-scale"
                className="chenxing-range"
                type="range"
                min={MIN_SCALE}
                max={MAX_SCALE}
                step={0.01}
                value={transform.scale}
                disabled={busy}
                onChange={(event) => applyTransform({ ...transform, scale: Number(event.target.value) })}
              />
              <span className="chenxing-mono w-12 text-right text-xs text-[var(--chenxing-muted-foreground)]">
                {transform.scale.toFixed(2)}x
              </span>
            </div>
          </div>

          {error ? <p className="chenxing-field-message" role="alert"><Icon name="circle-alert" size={13} className="shrink-0" />{error}</p> : null}
        </div>

        <div className="chenxing-drawer-footer">
          <Button variant="ghost" onClick={cancel} disabled={busy || exporting}>取消</Button>
          <Button icon="check" onClick={confirm} disabled={busy}>{busy ? '上传中…' : '使用这张'}</Button>
        </div>
      </div>
    </div>,
    document.body
  )
}
