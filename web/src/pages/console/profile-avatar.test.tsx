import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, waitFor } from '@testing-library/react'
import { ProfileAvatar } from './profile-avatar'

const USER = {
  id: 1,
  username: 'chenxing',
  email: 'user@chenxing.star',
  display_name: '辰星用户',
  status: 'active',
  role: 'user' as const,
  current_session_expires_at: '2099-01-01T00:00:00Z',
  avatar_updated_at: null,
}

/**
 * 受控的 Image 替身。
 *
 * #690 的泄漏窗口就是「解码尚未 settle」这段时间，只有手动掌握 onload / onerror
 * 的触发时机才能确定性地覆盖它；jsdom 自带的 Image 既不解码也不触发事件。
 */
class FakeImage {
  onload: (() => void) | null = null
  onerror: (() => void) | null = null
  naturalWidth = 0
  naturalHeight = 0
  src = ''

  constructor() {
    images.push(this)
  }
}

let images: FakeImage[] = []
let created: string[] = []
let revoked: string[] = []
let messages: Array<{ text: string; tone: string }> = []
let revokeMock = vi.fn((url: string) => { revoked.push(url) })

/**
 * jsdom 不实现 createObjectURL / revokeObjectURL，取到的原值是 undefined。
 * 因此收尾必须能「删掉」替身而不是写回一个 undefined 属性，否则本文件之后的用例
 * 会看到一个存在但不可调用的方法。
 */
type ObjectUrlApi = {
  createObjectURL?: typeof URL.createObjectURL
  revokeObjectURL?: typeof URL.revokeObjectURL
}
const urlApi = URL as ObjectUrlApi
const originalCreateObjectURL = urlApi.createObjectURL
const originalRevokeObjectURL = urlApi.revokeObjectURL

/** 内容刻意不是合法图片头：让预检落在「未知尺寸」分支，解码结果全由测试决定。 */
function pngFile(name: string): File {
  return new File([new Uint8Array(8)], name, { type: 'image/png' })
}

function renderAvatar() {
  const view = render(
    <ProfileAvatar
      user={USER}
      name="辰星用户"
      onMessage={(text, tone) => messages.push({ text, tone })}
      refresh={async () => USER}
    />,
  )
  const input = view.container.querySelector('input[type="file"]')
  if (!(input instanceof HTMLInputElement)) throw new Error('file input is missing')
  return { ...view, input }
}

/** 等待 onPick 里的预检 await 走完（File.arrayBuffer 在 jsdom 里跨宏任务 resolve）。 */
async function flush() {
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 0))
  })
}

beforeEach(() => {
  images = []
  created = []
  revoked = []
  messages = []
  urlApi.createObjectURL = vi.fn(() => {
    const url = `blob:avatar-pending-${created.length}`
    created.push(url)
    return url
  })
  revokeMock = vi.fn((url: string) => { revoked.push(url) })
  urlApi.revokeObjectURL = revokeMock
  vi.stubGlobal('Image', FakeImage)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  if (originalCreateObjectURL) urlApi.createObjectURL = originalCreateObjectURL
  else delete urlApi.createObjectURL
  if (originalRevokeObjectURL) urlApi.revokeObjectURL = originalRevokeObjectURL
  else delete urlApi.revokeObjectURL
})

describe('ProfileAvatar Object URL 生命周期（#690）', () => {
  it('解码尚未完成就卸载时释放在途 Object URL', async () => {
    const { input, unmount } = renderAvatar()
    fireEvent.change(input, { target: { files: [pngFile('avatar.png')] } })
    await waitFor(() => expect(images).toHaveLength(1))
    expect(created).toEqual(['blob:avatar-pending-0'])
    expect(revoked).toEqual([])

    unmount()

    expect(revoked).toEqual(['blob:avatar-pending-0'])
    expect(revokeMock).toHaveBeenCalledWith('blob:avatar-pending-0')
    expect(revokeMock).toHaveBeenCalledTimes(1)
  })

  it('卸载后迟到的 onload 不会重新申领已释放的 URL', async () => {
    const { input, unmount } = renderAvatar()
    fireEvent.change(input, { target: { files: [pngFile('avatar.png')] } })
    await waitFor(() => expect(images).toHaveLength(1))
    const image = images[0]

    unmount()

    // 卸载已经摘掉 handler：浏览器随后完成解码也不会有 continuation 接手。
    expect(image.onload).toBeNull()
    expect(image.onerror).toBeNull()
    image.naturalWidth = 400
    image.naturalHeight = 400
    await act(async () => {
      image.onload?.()
      await Promise.resolve()
    })
    await flush()

    expect(revoked).toEqual(['blob:avatar-pending-0'])
    expect(document.querySelector('[aria-label="调整头像"]')).toBeNull()
    // 卸载不是用户错误：取消在途解码不该弹出「图片无法读取」。
    expect(messages).toEqual([])
  })

  it('预检 await 期间卸载不会新建 Object URL', async () => {
    const { input, unmount } = renderAvatar()
    fireEvent.change(input, { target: { files: [pngFile('avatar.png')] } })

    unmount()
    await flush()

    expect(created).toEqual([])
    expect(images).toEqual([])
    expect(revoked).toEqual([])
  })

  it('解码失败时释放 Object URL 并给出提示', async () => {
    const { input } = renderAvatar()
    fireEvent.change(input, { target: { files: [pngFile('avatar.png')] } })
    await waitFor(() => expect(images).toHaveLength(1))

    await act(async () => {
      images[0].onerror?.()
      await Promise.resolve()
    })

    expect(revoked).toEqual(['blob:avatar-pending-0'])
    expect(messages).toEqual([{ text: '图片无法读取，请更换一张。', tone: 'warning' }])
  })

  it('连续换图会释放前一张仍在解码的 Object URL', async () => {
    const { input } = renderAvatar()
    fireEvent.change(input, { target: { files: [pngFile('first.png')] } })
    await waitFor(() => expect(images).toHaveLength(1))

    fireEvent.change(input, { target: { files: [pngFile('second.png')] } })
    expect(revoked).toEqual(['blob:avatar-pending-0'])

    await waitFor(() => expect(images).toHaveLength(2))
    expect(created).toEqual(['blob:avatar-pending-0', 'blob:avatar-pending-1'])
    expect(revoked).toEqual(['blob:avatar-pending-0'])
    // 被取代的选择是正常竞态，不是解码失败，不该弹出提示。
    expect(messages).toEqual([])
  })

  it('解码成功后由 loaded 状态接管，卸载时恰好释放一次', async () => {
    const { input, unmount } = renderAvatar()
    fireEvent.change(input, { target: { files: [pngFile('avatar.png')] } })
    await waitFor(() => expect(images).toHaveLength(1))

    const image = images[0]
    image.naturalWidth = 400
    image.naturalHeight = 400
    await act(async () => {
      image.onload?.()
      await Promise.resolve()
    })

    await waitFor(() => expect(document.querySelector('[aria-label="调整头像"]')).not.toBeNull())
    expect(revoked).toEqual([])

    unmount()

    expect(revoked).toEqual(['blob:avatar-pending-0'])
  })
})
