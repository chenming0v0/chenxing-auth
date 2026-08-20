import { describe, expect, it } from 'vitest'
import {
  EXPORT_EDGE,
  MAX_SCALE,
  MAX_SOURCE_FILE_BYTES,
  MAX_SOURCE_EDGE,
  MAX_SOURCE_PIXELS,
  MAX_UPLOAD_BYTES,
  MIN_SCALE,
  MIN_SOURCE_EDGE,
  clampOffset,
  clampScale,
  hasSupportedImageSignature,
  imageDimensionsFromBytes,
  localRejectionMessage,
  previewTransform,
  rejectDecodedSize,
  rejectExportSize,
  rejectFileBeforeDecode,
  renderedSize,
  sourceRect,
} from './avatar-crop'

const VIEWPORT = 288
const LANDSCAPE = { width: 1000, height: 600 }
const PORTRAIT = { width: 600, height: 1000 }

function file(size: number, type: string): File {
  // 只有 size / type 参与预检，用最小构造避免真的分配 5 MiB。
  return { size, type, name: 'avatar' } as File
}

describe('clampScale', () => {
  it('keeps the scale inside the usable range', () => {
    expect(clampScale(0.2)).toBe(MIN_SCALE)
    expect(clampScale(99)).toBe(MAX_SCALE)
    expect(clampScale(2.5)).toBe(2.5)
  })

  it('falls back to the minimum for non-finite input', () => {
    expect(clampScale(Number.NaN)).toBe(MIN_SCALE)
    expect(clampScale(Number.POSITIVE_INFINITY)).toBe(MAX_SCALE)
  })
})

describe('renderedSize', () => {
  it('covers the viewport on the short edge at the base scale', () => {
    const rendered = renderedSize(LANDSCAPE, VIEWPORT, MIN_SCALE)
    // cover 语义：短边正好铺满，长边溢出。留白边就意味着头像会出现透明角。
    expect(rendered.height).toBeCloseTo(VIEWPORT, 5)
    expect(rendered.width).toBeGreaterThan(VIEWPORT)
  })
})

describe('clampOffset', () => {
  it('never lets the viewport escape the image', () => {
    const clamped = clampOffset(LANDSCAPE, VIEWPORT, { scale: MIN_SCALE, offsetX: 99999, offsetY: 99999 })
    const rendered = renderedSize(LANDSCAPE, VIEWPORT, MIN_SCALE)

    expect(clamped.offsetX).toBeCloseTo((rendered.width - VIEWPORT) / 2, 5)
    // 短边在基准缩放下没有余量，纵向必须被夹成 0，否则会露出图像外部。
    expect(clamped.offsetY).toBe(0)
  })

  it('grows the pan budget as the scale grows', () => {
    const atBase = clampOffset(PORTRAIT, VIEWPORT, { scale: MIN_SCALE, offsetX: 99999, offsetY: 0 })
    const zoomed = clampOffset(PORTRAIT, VIEWPORT, { scale: 2, offsetX: 99999, offsetY: 0 })

    expect(atBase.offsetX).toBe(0)
    expect(zoomed.offsetX).toBeGreaterThan(0)
  })
})

describe('sourceRect', () => {
  it('selects a square window inside the source bounds', () => {
    const rect = sourceRect(LANDSCAPE, VIEWPORT, { scale: MIN_SCALE, offsetX: 0, offsetY: 0 })

    expect(rect.width).toBeCloseTo(rect.height, 5)
    expect(rect.width).toBeCloseTo(LANDSCAPE.height, 5)
    expect(rect.x).toBeGreaterThanOrEqual(0)
    expect(rect.y).toBeGreaterThanOrEqual(0)
    expect(rect.x + rect.width).toBeLessThanOrEqual(LANDSCAPE.width + 1e-6)
    expect(rect.y + rect.height).toBeLessThanOrEqual(LANDSCAPE.height + 1e-6)
  })

  it('stays inside the source even when asked to pan past the edge', () => {
    const rect = sourceRect(LANDSCAPE, VIEWPORT, { scale: 3, offsetX: -99999, offsetY: -99999 })

    expect(rect.x + rect.width).toBeLessThanOrEqual(LANDSCAPE.width + 1e-6)
    expect(rect.y + rect.height).toBeLessThanOrEqual(LANDSCAPE.height + 1e-6)
    expect(rect.x).toBeGreaterThanOrEqual(0)
    expect(rect.y).toBeGreaterThanOrEqual(0)
  })

  it('shrinks the source window as the user zooms in', () => {
    const wide = sourceRect(PORTRAIT, VIEWPORT, { scale: MIN_SCALE, offsetX: 0, offsetY: 0 })
    const tight = sourceRect(PORTRAIT, VIEWPORT, { scale: 3, offsetX: 0, offsetY: 0 })

    expect(tight.width).toBeLessThan(wide.width)
  })

  it('tracks the pan direction so preview and export agree', () => {
    // 预览把图像向右移，取景框相对图像即向左移，源矩形的 x 必须减小。
    const centered = sourceRect(PORTRAIT, VIEWPORT, { scale: 2, offsetX: 0, offsetY: 0 })
    const pannedRight = sourceRect(PORTRAIT, VIEWPORT, { scale: 2, offsetX: 40, offsetY: 0 })

    expect(pannedRight.x).toBeLessThan(centered.x)
  })
})

describe('previewTransform', () => {
  it('reports the same clamped offset the export path uses', () => {
    const transform = { scale: 1.5, offsetX: 99999, offsetY: 99999 }
    const preview = previewTransform(LANDSCAPE, VIEWPORT, transform)
    const clamped = clampOffset(LANDSCAPE, VIEWPORT, transform)

    // 预览与导出共用一套夹取，所见即所得就靠这条等式成立。
    expect(preview.translateX).toBeCloseTo(clamped.offsetX, 10)
    expect(preview.translateY).toBeCloseTo(clamped.offsetY, 10)
  })
})

describe('local pre-flight checks', () => {
  it('recognizes supported signatures and parses PNG dimensions', () => {
    const png = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0, 0x49, 0x48, 0x44, 0x52, 0, 0, 0xFA, 0, 0, 0, 0xFA, 8, 6])
    expect(hasSupportedImageSignature(png)).toBe(true)
    expect(imageDimensionsFromBytes(png)).toEqual({ width: 64000, height: 250 })
  })


  it('gates the source file on the source budget, not the upload budget', () => {
    /* 回归保护：源文件曾被按上传额度（5 MiB）判定，导致一张普通手机照片在打开
       编辑器之前就被拒。裁剪后的上传体与源文件大小几乎无关，两个预算必须分开。 */
    const phonePhoto = file(6 * 1024 * 1024, 'image/jpeg')
    expect(phonePhoto.size).toBeGreaterThan(MAX_UPLOAD_BYTES)
    expect(rejectFileBeforeDecode(phonePhoto)).toBeUndefined()

    expect(rejectFileBeforeDecode(file(MAX_SOURCE_FILE_BYTES + 1, 'image/png'))).toBe('source_too_large')
    expect(rejectFileBeforeDecode(file(MAX_SOURCE_FILE_BYTES, 'image/png'))).toBeUndefined()
  })

  it('gates the exported blob on the upload budget', () => {
    expect(rejectExportSize(MAX_UPLOAD_BYTES + 1)).toBe('export_too_large')
    expect(rejectExportSize(MAX_UPLOAD_BYTES)).toBeUndefined()
  })

  it('allows empty MIME metadata to reach byte/decode validation', () => {
    expect(rejectFileBeforeDecode(file(1024, ''))).toBeUndefined()
    expect(rejectFileBeforeDecode(file(1024, 'image/gif'))).toBe('unsupported_format')
  })

  it('rejects decoded dimensions that exceed browser memory budgets', () => {
    expect(rejectDecodedSize({ width: MAX_SOURCE_EDGE + 1, height: 1000 })).toBe('too_large_dimensions')
    expect(rejectDecodedSize({ width: 4097, height: 4097 })).toBe('too_large_dimensions')
    expect(rejectDecodedSize({ width: MAX_SOURCE_EDGE, height: 1000 })).toBeUndefined()
    expect(rejectDecodedSize({ width: MIN_SOURCE_EDGE, height: MIN_SOURCE_EDGE })).toBeUndefined()
  })

  it('rejects sources below the minimum edge', () => {
    expect(rejectDecodedSize({ width: MIN_SOURCE_EDGE - 1, height: 800 })).toBe('too_small')
    expect(rejectDecodedSize({ width: MIN_SOURCE_EDGE, height: MIN_SOURCE_EDGE })).toBeUndefined()
  })

  it('states the actual limits in its messages', () => {
    expect(localRejectionMessage('source_too_large')).toContain(String(MAX_SOURCE_FILE_BYTES / (1024 * 1024)))
    expect(localRejectionMessage('too_small')).toContain(String(MIN_SOURCE_EDGE))
    // 两条体积文案必须可区分：一条让用户换图，一条让用户改取景范围。
    expect(localRejectionMessage('export_too_large')).not.toBe(localRejectionMessage('source_too_large'))
  })
})

describe('geometry is driven by the measured edge', () => {
  /* 取景框边长由 CSS 按视口算，矮窗口下会缩小。这些断言锁定「几何只依赖传入的
     实测边长」这一契约——编辑器曾把边长写成常量并用内联样式覆盖 CSS，一旦两者
     不一致，预览与导出就会错位。 */
  const EDGES = [96, 180, 288, 420]

  it('keeps preview and export agreeing at any edge', () => {
    for (const edge of EDGES) {
      const transform = { scale: 2.2, offsetX: 55, offsetY: -40 }
      const preview = previewTransform(PORTRAIT, edge, transform)
      const clamped = clampOffset(PORTRAIT, edge, transform)

      expect(preview.translateX).toBeCloseTo(clamped.offsetX, 10)
      expect(preview.translateY).toBeCloseTo(clamped.offsetY, 10)
    }
  })

  it('keeps the source window square and in bounds at any edge', () => {
    for (const edge of EDGES) {
      const rect = sourceRect(LANDSCAPE, edge, { scale: 1.7, offsetX: 99999, offsetY: -99999 })

      expect(rect.width).toBeCloseTo(rect.height, 5)
      expect(rect.x).toBeGreaterThanOrEqual(0)
      expect(rect.y).toBeGreaterThanOrEqual(0)
      expect(rect.x + rect.width).toBeLessThanOrEqual(LANDSCAPE.width + 1e-6)
      expect(rect.y + rect.height).toBeLessThanOrEqual(LANDSCAPE.height + 1e-6)
    }
  })

  it('selects the same source region regardless of edge at the base scale', () => {
    // 基准缩放下取景框铺满短边，取到的源区域与显示尺寸无关。
    // 这条等式成立，才说明边长只影响显示、不影响裁剪语义。
    const small = sourceRect(LANDSCAPE, 96, { scale: MIN_SCALE, offsetX: 0, offsetY: 0 })
    const large = sourceRect(LANDSCAPE, 420, { scale: MIN_SCALE, offsetX: 0, offsetY: 0 })

    expect(small.width).toBeCloseTo(large.width, 5)
    expect(small.x).toBeCloseTo(large.x, 5)
    expect(small.y).toBeCloseTo(large.y, 5)
  })
})

describe('shared constants', () => {
  it('exports at least the server-side minimum edge', () => {
    // 导出边长若低于服务端下限，每次上传都会被服务端拒绝。
    expect(EXPORT_EDGE).toBeGreaterThanOrEqual(MIN_SOURCE_EDGE)
  })
})
