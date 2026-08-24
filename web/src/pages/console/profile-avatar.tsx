import { useEffect, useRef, useState, type ChangeEvent } from 'react'
import { apiFetch, avatarUrl, type UserMe } from '../../api'
import { AvatarContent, Button, Icon } from '../../components/ui'
import { AvatarEditor } from '../../components/avatar-editor'
import {
  ACCEPTED_UPLOAD_TYPES,
  localRejectionMessage,
  hasSupportedImageSignature,
  imageDimensionsFromBytes,
  rejectDecodedSize,
  rejectFileBeforeDecode,
  type SourceSize,
} from '../../components/avatar-crop'

export type MessageTone = 'success' | 'warning'

type LoadedSource = { image: HTMLImageElement; source: SourceSize; url: string }

async function hasSupportedBytes(file: File): Promise<boolean> {
  const bytes = new Uint8Array(await file.slice(0, 12).arrayBuffer())
  return hasSupportedImageSignature(bytes)
}

async function rejectOversizedHeader(file: File): Promise<boolean> {
  const bytes = new Uint8Array(await file.slice(0, 64).arrayBuffer())
  const dimensions = imageDimensionsFromBytes(bytes)
  return dimensions !== undefined && Boolean(rejectDecodedSize(dimensions))
}

/**
 * 在浏览器里解码待上传图片。
 *
 * 取景需要真实像素尺寸，而尺寸只有解码后才知道，因此「最短边下限」这条规则必须在
 * 解码之后才能判定，不能只看文件大小。
 */
function decodeFile(file: File): Promise<LoadedSource> {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file)
    const image = new Image()
    image.onload = () => {
      if (!image.naturalWidth || !image.naturalHeight) {
        URL.revokeObjectURL(url)
        reject(new Error('avatar_undecodable'))
        return
      }
      resolve({ image, source: { width: image.naturalWidth, height: image.naturalHeight }, url })
    }
    image.onerror = () => {
      URL.revokeObjectURL(url)
      reject(new Error('avatar_undecodable'))
    }
    image.src = url
  })
}

type ProfileAvatarProps = {
  user: UserMe | null
  name: string
  onMessage: (text: string, tone: MessageTone) => void
  refresh: () => Promise<UserMe | null>
}

/**
 * 个人资料页的头像入口：选图 → 取景 → 上传 → 刷新。
 *
 * 本地预检（大小、MIME、最短边）只是为了省掉一次无谓的上传往返；服务端会独立
 * 复核同样的规则并重新编码，因此这里的校验不构成安全边界。
 */
export function ProfileAvatar({ user, name, onMessage, refresh }: ProfileAvatarProps) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [loaded, setLoaded] = useState<LoadedSource | null>(null)
  const [avatarUser, setAvatarUser] = useState(user)
  const [busy, setBusy] = useState(false)
  const decodeRequestRef = useRef(0)
  const uploadRequestRef = useRef(0)

  useEffect(() => {
    setAvatarUser(user)
  }, [user])

  // Object URL 是显式分配的资源：状态更替和组件卸载都必须释放，否则每选一张图
  // 就泄漏一份图片内存，直到整页刷新。
  useEffect(() => {
    if (!loaded) return
    return () => URL.revokeObjectURL(loaded.url)
  }, [loaded])

  async function onPick(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    // 清空 value：否则用户重新选择同一个文件不会触发 change 事件。
    event.target.value = ''
    if (!file) return

    const rejection = rejectFileBeforeDecode(file)
    if (rejection) {
      onMessage(localRejectionMessage(rejection), 'warning')
      return
    }
    const requestId = ++decodeRequestRef.current
    try {
      if (!file.type && !(await hasSupportedBytes(file))) {
        onMessage(localRejectionMessage('unsupported_format'), 'warning')
        return
      }
      if (await rejectOversizedHeader(file)) {
        onMessage(localRejectionMessage('too_large_dimensions'), 'warning')
        return
      }
      const decoded = await decodeFile(file)
      if (requestId !== decodeRequestRef.current) {
        URL.revokeObjectURL(decoded.url)
        return
      }
      const sizeRejection = rejectDecodedSize(decoded.source)
      if (sizeRejection) {
        URL.revokeObjectURL(decoded.url)
        onMessage(localRejectionMessage(sizeRejection), 'warning')
        return
      }
      setLoaded(decoded)
    } catch {
      onMessage(localRejectionMessage('undecodable'), 'warning')
    }
  }

  async function upload(blob: Blob) {
    if (busy) return
    const requestId = ++uploadRequestRef.current
    setBusy(true)
    try {
      // 直接 PUT Blob：它自带 MIME，apiFetch 不会覆盖 Content-Type。
      await apiFetch<UserMe>('/api/v1/auth/me/avatar', { method: 'PUT', body: blob })
      if (requestId !== uploadRequestRef.current) return
      await refresh()
      if (requestId !== uploadRequestRef.current) return
      setLoaded(null)
      onMessage('头像已更新。', 'success')
    } catch (error) {
      if (requestId === uploadRequestRef.current) onMessage(error instanceof Error ? error.message : '头像上传失败。', 'warning')
    } finally {
      if (requestId === uploadRequestRef.current) setBusy(false)
    }
  }

  return (
    <div className="flex shrink-0 flex-col items-center gap-2">
      <div className="relative">
        <span className="pointer-events-none absolute inset-0 z-[var(--chenxing-z-backdrop)] m-auto block h-28 w-28 rounded-full bg-[var(--chenxing-cyan)] opacity-40 blur-2xl" />
        <button
          type="button"
          className="chenxing-avatar chenxing-avatar-editable h-24 w-24 text-3xl"
          onClick={() => inputRef.current?.click()}
          disabled={busy}
          aria-label="更换头像"
        >
          <AvatarContent src={avatarUrl(avatarUser)} name={name} />
          <span className="chenxing-avatar-overlay" aria-hidden="true"><Icon name="pencil" size={18} /></span>
        </button>
        <span className="absolute -bottom-1 -right-1 inline-flex h-8 w-8 items-center justify-center rounded-full border border-[rgba(103,232,249,0.4)] bg-[var(--chenxing-background)]">
          <Icon name="badge-check" className="text-[var(--chenxing-cyan)]" size={20} />
        </span>
        {/* display:none 而不是视觉隐藏：input 不该进入 Tab 序列，
            无障碍入口是上面那个带 aria-label 的按钮。 */}
        <input
          ref={inputRef}
          type="file"
          className="hidden"
          accept={ACCEPTED_UPLOAD_TYPES.join(',')}
          onChange={(event) => void onPick(event)}
        />
      </div>
      {loaded ? (
        <AvatarEditor
          image={loaded.image}
          source={loaded.source}
          busy={busy}
          onCancel={() => { if (!busy) setLoaded(null) }}
          onConfirm={(blob) => void upload(blob)}
        />
      ) : null}
    </div>
  )
}
