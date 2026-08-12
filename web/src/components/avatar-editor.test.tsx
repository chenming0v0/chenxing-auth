import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, render, screen } from '@testing-library/react'
import { AvatarEditor } from './avatar-editor'

function fakeImage(): HTMLImageElement {
  const image = document.createElement('img')
  image.src = 'data:image/gif;base64,R0lGODlhAQABAAAAACw='
  return image
}

function renderEditor(busy = false) {
  return render(
    <AvatarEditor
      image={fakeImage()}
      source={{ width: 800, height: 800 }}
      busy={busy}
      onCancel={() => {}}
      onConfirm={() => {}}
    />,
  )
}

afterEach(cleanup)

describe('AvatarEditor 原生滚轮监听（Issue #370）', () => {
  it('以 { passive: false } 注册 wheel，才能 preventDefault 挡住页面滚动', () => {
    const add = vi.spyOn(HTMLElement.prototype, 'addEventListener')
    try {
      renderEditor()
      const wheelCalls = add.mock.calls.filter((call) => call[0] === 'wheel')
      expect(wheelCalls.length).toBeGreaterThan(0)
      expect(wheelCalls.some((call) => {
        const options = call[2]
        return typeof options === 'object' && options !== null && (options as AddEventListenerOptions).passive === false
      })).toBe(true)
    } finally {
      add.mockRestore()
    }
  })

  function wheel(deltaY: number): WheelEvent {
    // jsdom 的 WheelEventInit 不一定把 deltaY 写到实例上，显式挂上去。
    const event = new WheelEvent('wheel', { bubbles: true, cancelable: true, deltaY })
    Object.defineProperty(event, 'deltaY', { value: deltaY })
    return event
  }

  it('滚轮改缩放并调用 preventDefault', () => {
    renderEditor()
    const viewport = screen.getByRole('application', { name: /头像取景框/ })
    expect(screen.getByText('1.00x')).toBeTruthy()
    const event = wheel(-200)
    act(() => {
      viewport.dispatchEvent(event)
    })
    expect(event.defaultPrevented).toBe(true)
    expect(screen.getByText('1.40x')).toBeTruthy()
  })

  it('busy 时滚轮不改缩放', () => {
    renderEditor(true)
    const viewport = screen.getByRole('application', { name: /头像取景框/ })
    const event = wheel(-200)
    act(() => {
      viewport.dispatchEvent(event)
    })
    expect(event.defaultPrevented).toBe(false)
    expect(screen.getByText('1.00x')).toBeTruthy()
  })
})
