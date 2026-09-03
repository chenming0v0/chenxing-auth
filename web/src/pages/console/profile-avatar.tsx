import { useEffect, useRef, useState, type ChangeEvent } from 'react'
import { apiFetch, avatarUrl, type UserMe } from '../../api'
import { AvatarContent, Button, Icon } from '@chenxing/ui'
import { AvatarEditor } from '@chenxing/ui'
import {
  ACCEPTED_UPLOAD_TYPES,
  localRejectionMessage,
  hasSupportedImageSignature,
  imageDimensionsFromBytes,
  rejectDecodedSize,
  rejectFileBeforeDecode,
  type SourceSize,
} from '@chenxing/ui'

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

/** 在途解码的所有权记录：谁持有 URL，谁负责释放。 */
type PendingDecode = { id: number; url: string; cancel: () => void }

/**
 * 释放仍在解码中的 Object URL：先停掉解码，再 revoke，最后交还所有权（置空）。
 *
 * 幂等：ref 已被别人清空时什么都不做。传 `id` 表示「只释放属于这次 request 的 URL」，
 * 避免一个已被取代的旧 request 的收尾代码误杀新 request 刚建立的 URL。
 */
function releasePending(pendingRef: { current: PendingDecode | null }, id?: number) {
  const pending = pendingRef.current
  if (!pending) return
  if (id !== undefined && pending.id !== id) return
  pendingRef.current = null
  pending.cancel()
  URL.revokeObjectURL(pending.url)
}

/**
 * 在浏览器里解码一个已经创建好的 Object URL。
 *
 * 取景需要真实像素尺寸，而尺寸只有解码后才知道，因此「最短边下限」这条规则必须在
 * 解码之后才能判定，不能只看文件大小。
 *
 * 这里刻意不 revoke 任何 URL：解码是异步的，而 `image.onload` / `image.onerror` 有可能
 * 永远不到达（组件先卸载、或浏览器丢掉这次解码）。把释放放在 promise 的任一分支里，
 * 都存在「promise 尚未 settle 就卸载」的泄漏窗口。因此 URL 的唯一 owner 是调用方通过
 * `register` 拿到的取消句柄：成功后所有权转交给 loaded state，其余所有退出路径
 * （失败、尺寸拒绝、换图、卸载）都由调用方主动取消并释放。
 */
function decodeObjectUrl(url: string, register: (cancel: () => void) => void): Promise<LoadedSource> {
  return new Promise((resolve, reject) => {
    const image = new Image()
    const fail = () => reject(new Error('avatar_undecodable'))
    image.onload = () => {
      if (!image.naturalWidth || !image.naturalHeight) {
        fail()
        return
      }
      resolve({ image, source: { width: image.naturalWidth, height: image.naturalHeight }, url })
    }
    image.onerror = fail
    register(() => {
      // 摘掉 handler 并清空 src：停止继续解码，并让已经 settle 的 promise 不受影响。
      image.onload = null
      image.onerror = null
      image.src = ''
      // 已 settle 的 promise 忽略这次 reject；仍在途的则立刻结束，不留悬挂 continuation。
      fail()
    })
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
  // 尚未转交给 loaded state 的 Object URL 的唯一持有者。
  const pendingRef = useRef<PendingDecode | null>(null)

  useEffect(() => {
    setAvatarUser(user)
  }, [user])

  // 卸载时在途的解码没有任何后续 owner：loaded effect 不会再挂载，promise 也可能永远
  // 不 settle。因此这里既要让所有在途 continuation 变成 stale，也要主动停止解码并
  // 释放它持有的 Object URL（#690）。
  useEffect(() => {
    return () => {
      decodeRequestRef.current += 1
      releasePending(pendingRef)
    }
  }, [])

  // Object URL 是显式分配的资源：状态更替和组件卸载都必须释放，否则每选一张图
  // 就泄漏一份图片内存，直到整页刷新。
  //
  // 所有权在这里从 pendingRef 正式移交：只有 effect 真的挂载了，才说明 cleanup 一定会
  // 执行。若在 onPick 里提前放手，而这次渲染被随后的卸载丢弃（effect 从未挂载），
  // 就又回到没人释放的状态。
  useEffect(() => {
    if (!loaded) return
    // createObjectURL 保证 URL 唯一，因此 url 相等即同一次 pending。
    if (pendingRef.current?.url === loaded.url) pendingRef.current = null
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
    // 先让旧 request 失效再释放，保证旧 continuation 一定走 stale 分支。
    const requestId = ++decodeRequestRef.current
    releasePending(pendingRef)
    try {
      if (!file.type && !(await hasSupportedBytes(file))) {
        if (requestId === decodeRequestRef.current) onMessage(localRejectionMessage('unsupported_format'), 'warning')
        return
      }
      if (await rejectOversizedHeader(file)) {
        if (requestId === decodeRequestRef.current) onMessage(localRejectionMessage('too_large_dimensions'), 'warning')
        return
      }
      // 预检 await 期间可能已卸载或已换图。在这里拦住，避免为一个没人接手的
      // request 新建 Object URL。
      if (requestId !== decodeRequestRef.current) return
      const url = URL.createObjectURL(file)
      const decoded = await decodeObjectUrl(url, (cancel) => {
        pendingRef.current = { id: requestId, url, cancel }
      })
      if (requestId !== decodeRequestRef.current) {
        releasePending(pendingRef, requestId)
        return
      }
      const sizeRejection = rejectDecodedSize(decoded.source)
      if (sizeRejection) {
        releasePending(pendingRef, requestId)
        onMessage(localRejectionMessage(sizeRejection), 'warning')
        return
      }
      // 交给 loaded state。所有权在 loaded effect 真正挂载时才从 pendingRef 移交：
      // 若这次渲染被随后的卸载丢弃，pendingRef 仍持有 URL，卸载 cleanup 会释放它。
      setLoaded(decoded)
    } catch {
      // 解码失败、或本次 request 被取消（换图/卸载）。releasePending 幂等，且只认自己的
      // requestId，不会误杀取消路径已经清空的记录或新 request 新建的 URL。
      releasePending(pendingRef, requestId)
      if (requestId === decodeRequestRef.current) onMessage(localRejectionMessage('undecodable'), 'warning')
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
