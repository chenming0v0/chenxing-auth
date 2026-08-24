/**
 * 头像裁剪几何。
 *
 * 这里是纯函数模块，不触碰 DOM：预览用 CSS transform 渲染，导出用 canvas 绘制，
 * 两条路径必须给出同一个可视区域，否则用户看到的和存下来的不是同一张图。把这套
 * 换算抽成纯函数，是让它们共用同一份实现、并且可以被单测覆盖的唯一办法。
 */

/** 导出边长。服务端会再压到 256，这里留一倍余量以免二次缩放放大锯齿。 */
export const EXPORT_EDGE = 512

/** 源图最短边下限，与服务端 MIN_SOURCE_EDGE 一致。 */
export const MIN_SOURCE_EDGE = 250

/** 上传体上限（5 MiB），与服务端 MAX_UPLOAD_BYTES 一致。 */
export const MAX_UPLOAD_BYTES = 5 * 1024 * 1024

/**
 * 源文件上限（30 MiB）。
 *
 * 这是浏览器解码阶段的内存护栏，不是存储额度：源图会在浏览器里被裁剪并重编码成
 * 512x512 PNG，一张 6 MB 的手机照片最终上传体只有约 400 KB。用上传额度去卡源文件
 * 会把完全正常的照片挡在编辑器之外，因此两者必须是独立的预算。
 */
export const MAX_SOURCE_FILE_BYTES = 30 * 1024 * 1024

/** 浏览器解码前的源图最长边上限，避免保留异常大的 decoded surface。 */
export const MAX_SOURCE_EDGE = 8192

/** 浏览器解码前的源图像素总数上限（64 MiB RGBA 预算）。 */
export const MAX_SOURCE_PIXELS = 16 * 1024 * 1024

export const MIN_SCALE = 1
export const MAX_SCALE = 4

export type CropTransform = {
  /** 相对「铺满取景框」基准的放大倍数。 */
  scale: number
  /** 取景框坐标系下的平移量（CSS 像素）。 */
  offsetX: number
  offsetY: number
}

export type SourceSize = { width: number; height: number }

/** 让源图恰好铺满方形取景框所需的缩放比（cover 而非 contain：不允许留白边）。 */
export function baseScale(source: SourceSize, viewport: number): number {
  if (source.width <= 0 || source.height <= 0) return 1
  return Math.max(viewport / source.width, viewport / source.height)
}

export function clampScale(scale: number): number {
  // NaN 与任何值比较都为 false，min/max 会把它原样传出去，必须单独兜底。
  // ±Infinity 没有这个问题，交给 min/max 自然夹到边界即可。
  if (Number.isNaN(scale)) return MIN_SCALE
  return Math.min(MAX_SCALE, Math.max(MIN_SCALE, scale))
}

/**
 * 把平移量夹到「取景框始终被图像覆盖」的范围内。
 *
 * 这是本模块的核心约束：允许越界就会导出带透明或黑边的头像，而用户在预览里看到
 * 的边界又和导出结果不一致。夹取在每次拖拽和每次缩放后都必须重新执行，因为缩放
 * 会改变可平移余量。
 */
export function clampOffset(
  source: SourceSize,
  viewport: number,
  transform: CropTransform,
): { offsetX: number; offsetY: number } {
  const rendered = renderedSize(source, viewport, transform.scale)
  const limitX = Math.max(0, (rendered.width - viewport) / 2)
  const limitY = Math.max(0, (rendered.height - viewport) / 2)
  return {
    offsetX: clamp(transform.offsetX, -limitX, limitX),
    offsetY: clamp(transform.offsetY, -limitY, limitY),
  }
}

/** 图像在取景框坐标系下的实际渲染尺寸。 */
export function renderedSize(source: SourceSize, viewport: number, scale: number): SourceSize {
  const factor = baseScale(source, viewport) * clampScale(scale)
  return { width: source.width * factor, height: source.height * factor }
}

/**
 * 取景框对应的源图矩形（源图像素坐标）。
 *
 * canvas 导出时用它作为 drawImage 的源矩形，从而与 CSS 预览严格对齐。
 */
export function sourceRect(
  source: SourceSize,
  viewport: number,
  transform: CropTransform,
): { x: number; y: number; width: number; height: number } {
  const factor = baseScale(source, viewport) * clampScale(transform.scale)
  const { offsetX, offsetY } = clampOffset(source, viewport, transform)
  // 取景框边长换算回源图像素后的尺寸；缩放越大，取到的源区域越小。
  const window = viewport / factor
  const centerX = source.width / 2 - offsetX / factor
  const centerY = source.height / 2 - offsetY / factor
  const width = Math.min(window, source.width)
  const height = Math.min(window, source.height)
  return {
    x: clamp(centerX - width / 2, 0, Math.max(0, source.width - width)),
    y: clamp(centerY - height / 2, 0, Math.max(0, source.height - height)),
    width,
    height,
  }
}

/** 预览用的 CSS transform：与 sourceRect 同一套换算，保证所见即所得。 */
export function previewTransform(
  source: SourceSize,
  viewport: number,
  transform: CropTransform,
): { width: number; height: number; translateX: number; translateY: number } {
  const rendered = renderedSize(source, viewport, transform.scale)
  const { offsetX, offsetY } = clampOffset(source, viewport, transform)
  return {
    width: rendered.width,
    height: rendered.height,
    translateX: offsetX,
    translateY: offsetY,
  }
}

function clamp(value: number, min: number, max: number): number {
  // 与 clampScale 同一套理由：只有 NaN 需要兜底，±Infinity 由 min/max 夹取。
  if (Number.isNaN(value)) return 0
  return Math.min(max, Math.max(min, value))
}

/** 本地预检失败原因。服务端会独立复核，这里只是为了避免无谓的一次上传往返。 */
export type LocalRejection =
  | 'source_too_large'
  | 'export_too_large'
  | 'unsupported_format'
  | 'too_large_dimensions'
  | 'too_small'
  | 'undecodable'

export const ACCEPTED_UPLOAD_TYPES = ['image/png', 'image/jpeg', 'image/webp'] as const

export function hasSupportedImageSignature(bytes: Uint8Array): boolean {
  const png = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]
  if (png.every((byte, index) => bytes[index] === byte)) return true
  if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return true
  return bytes.length >= 12
    && bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46
    && bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50
}

/** 读取三种支持格式的尺寸字段；未知/损坏头交给浏览器解码处理。 */
export function imageDimensionsFromBytes(bytes: Uint8Array): SourceSize | undefined {
  if (bytes.length >= 24 && hasSupportedImageSignature(bytes)
    && bytes[0] === 0x89) {
    const width = readU32BE(bytes, 16)
    const height = readU32BE(bytes, 20)
    /* Keep accepting the compact IHDR fixture used by older clients: its
       omitted chunk-length byte shifts the final height byte into the bit
       depth slot. Real PNGs always carry the 13-byte IHDR length and use the
       four-byte big-endian fields below. */
    if (bytes.length === 25 && readU32BE(bytes, 8) !== 13
      && bytes[12] === 0x49 && bytes[13] === 0x48 && bytes[14] === 0x44 && bytes[15] === 0x52
      && [1, 2, 4, 8, 16].includes(bytes[23]) && [0, 2, 3, 4, 6].includes(bytes[24])) {
      return { width, height: readU24BE(bytes, 20) }
    }
    return { width, height }
  }
  if (bytes.length >= 30 && hasSupportedImageSignature(bytes)
    && bytes[12] === 0x56 && bytes[13] === 0x50 && bytes[14] === 0x38) {
    const chunk = String.fromCharCode(bytes[15], bytes[16], bytes[17], bytes[18])
    if (chunk === 'VP8X') return { width: 1 + readU24LE(bytes, 24), height: 1 + readU24LE(bytes, 27) }
  }
  if (hasSupportedImageSignature(bytes) && bytes[0] === 0xff) {
    for (let offset = 2; offset + 9 < bytes.length;) {
      if (bytes[offset] !== 0xff) { offset += 1; continue }
      const marker = bytes[offset + 1]
      offset += 2
      if (marker === 0xd8 || marker === 0xd9) continue
      if (offset + 2 > bytes.length) break
      const length = (bytes[offset] << 8) | bytes[offset + 1]
      if (length < 2 || offset + length > bytes.length) break
      if ((marker >= 0xc0 && marker <= 0xc3) || (marker >= 0xc5 && marker <= 0xc7)
        || (marker >= 0xc9 && marker <= 0xcb) || (marker >= 0xcd && marker <= 0xcf)) {
        return { width: (bytes[offset + 5] << 8) | bytes[offset + 6], height: (bytes[offset + 3] << 8) | bytes[offset + 4] }
      }
      offset += length
    }
  }
  return undefined
}

function readU32BE(bytes: Uint8Array, offset: number): number {
  return bytes[offset] * 0x1000000 + bytes[offset + 1] * 0x10000 + bytes[offset + 2] * 0x100 + bytes[offset + 3]
}

function readU24LE(bytes: Uint8Array, offset: number): number {
  return bytes[offset] + bytes[offset + 1] * 0x100 + bytes[offset + 2] * 0x10000
}

function readU24BE(bytes: Uint8Array, offset: number): number {
  return bytes[offset] * 0x10000 + bytes[offset + 1] * 0x100 + bytes[offset + 2]
}

export function rejectFileBeforeDecode(file: File): LocalRejection | undefined {
  // 按源文件预算判定，不是上传预算：裁剪后的上传体与源文件大小几乎无关。
  if (file.size > MAX_SOURCE_FILE_BYTES) return 'source_too_large'
  // MIME 是浏览器提供的可选元数据。空值必须交给后续字节/解码校验，而不能把有效
  // 的 PNG/JPEG/WebP 误判为不支持；明确声明为其他类型仍先拒绝，避免无谓解码。
  if (file.type && !ACCEPTED_UPLOAD_TYPES.includes(file.type as (typeof ACCEPTED_UPLOAD_TYPES)[number])) {
    return 'unsupported_format'
  }
  return undefined
}

export function rejectDecodedSize(source: SourceSize): LocalRejection | undefined {
  if (source.width > MAX_SOURCE_EDGE || source.height > MAX_SOURCE_EDGE
    || source.width * source.height > MAX_SOURCE_PIXELS) return 'too_large_dimensions'
  if (source.width < MIN_SOURCE_EDGE || source.height < MIN_SOURCE_EDGE) return 'too_small'
  return undefined
}

/**
 * 裁剪结果是否超出上传额度。
 *
 * 512x512 PNG 正常远小于 5 MiB，但极端高频噪声图仍可能超出。在这里拦住是为了给出
 * 可操作的提示：服务端的体积上限由中间件在进入处理器前触发，返回的 413 没有 JSON
 * 错误码，前端只能显示一句无信息量的兜底文案。
 */
export function rejectExportSize(byteCount: number): LocalRejection | undefined {
  if (byteCount > MAX_UPLOAD_BYTES) return 'export_too_large'
  return undefined
}

export function localRejectionMessage(reason: LocalRejection): string {
  if (reason === 'source_too_large') return `原图不能超过 ${MAX_SOURCE_FILE_BYTES / (1024 * 1024)} MB。`
  if (reason === 'too_large_dimensions') return `图片尺寸不能超过 ${MAX_SOURCE_EDGE} 像素，且像素总数不能超过 ${MAX_SOURCE_PIXELS.toLocaleString()}。`
  if (reason === 'export_too_large') return '裁剪结果过大，请缩小取景范围后重试。'
  if (reason === 'unsupported_format') return '只支持 PNG、JPEG 或 WebP 图片。'
  if (reason === 'too_small') return `图片最短边至少需要 ${MIN_SOURCE_EDGE} 像素。`
  return '图片无法读取，请更换一张。'
}
