import { describe, expect, it, afterEach } from 'vitest'
import { useState } from 'react'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import { Drawer } from './drawer'

/** 还原真实用法：页面上的触发按钮 + 条件渲染的抽屉。 */
function DrawerHarness({ busy = false }: { busy?: boolean }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <div data-testid="drawer-background">页面背景</div>
      <div>
        <button type="button" onClick={() => setOpen(true)}>打开抽屉</button>
        {open ? (
          <Drawer
            title="测试抽屉"
            description="用于验证焦点管理。"
            onClose={() => setOpen(false)}
            onSubmit={(event) => event.preventDefault()}
            busy={busy}
            footer={<button type="submit">提交</button>}
          >
            <input aria-label="第一个字段" />
          </Drawer>
        ) : null}
      </div>
    </>
  )
}

function openDrawer(busy = false) {
  render(<DrawerHarness busy={busy} />)
  const trigger = screen.getByText('打开抽屉')
  // 真实浏览器点击按钮会先聚焦它，fireEvent 不会；显式聚焦才能还原触发元素的焦点状态。
  trigger.focus()
  fireEvent.click(trigger)
  return trigger
}

afterEach(() => {
  cleanup()
  document.documentElement.style.removeProperty('overflow')
  document.body.style.removeProperty('overflow')
})

describe('Drawer', () => {
  it('exposes the dialog role labelled by its title', () => {
    openDrawer()
    const dialog = screen.getByRole('dialog')
    expect(dialog.getAttribute('aria-modal')).toBe('true')
    const labelId = dialog.getAttribute('aria-labelledby')
    expect(labelId).toBeTruthy()
    expect(document.getElementById(labelId as string)?.textContent).toBe('测试抽屉')
  })

  it('locks page scrolling and makes background branches inert while open', () => {
    const trigger = openDrawer()
    const background = screen.getByTestId('drawer-background')

    expect(document.documentElement.style.overflow).toBe('hidden')
    expect(document.body.style.overflow).toBe('hidden')
    for (const element of [background, trigger]) {
      expect(element.hasAttribute('inert')).toBe(true)
      expect(element.getAttribute('aria-hidden')).toBe('true')
    }

    fireEvent.click(screen.getByLabelText('关闭'))

    expect(document.documentElement.style.overflow).toBe('')
    expect(document.body.style.overflow).toBe('')
    for (const element of [background, trigger]) {
      expect(element.hasAttribute('inert')).toBe(false)
      expect(element.hasAttribute('aria-hidden')).toBe(false)
    }
  })

  it('restores existing overflow declarations and background attributes exactly', () => {
    document.documentElement.style.setProperty('overflow', 'clip', 'important')
    document.body.style.setProperty('overflow', 'scroll')
    render(<DrawerHarness />)

    const background = screen.getByTestId('drawer-background')
    const trigger = screen.getByText('打开抽屉')
    background.setAttribute('inert', 'preserved')
    background.setAttribute('aria-hidden', 'false')
    trigger.focus()
    fireEvent.click(trigger)
    fireEvent.click(screen.getByLabelText('关闭'))

    expect(document.documentElement.style.getPropertyValue('overflow')).toBe('clip')
    expect(document.documentElement.style.getPropertyPriority('overflow')).toBe('important')
    expect(document.body.style.getPropertyValue('overflow')).toBe('scroll')
    expect(document.body.style.getPropertyPriority('overflow')).toBe('')
    expect(background.getAttribute('inert')).toBe('preserved')
    expect(background.getAttribute('aria-hidden')).toBe('false')
    expect(trigger.hasAttribute('inert')).toBe(false)
    expect(trigger.hasAttribute('aria-hidden')).toBe(false)
  })

  it('moves focus into the drawer when it opens', () => {
    openDrawer()
    const dialog = screen.getByRole('dialog')
    expect(dialog.contains(document.activeElement)).toBe(true)
    // DOM 顺序上的首个可聚焦元素是关闭按钮。
    expect(document.activeElement).toBe(screen.getByLabelText('关闭'))
  })

  it('returns focus to the trigger after closing', () => {
    const trigger = openDrawer()
    fireEvent.click(screen.getByLabelText('关闭'))
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(document.activeElement).toBe(trigger)
  })

  it('closes on Escape', () => {
    const trigger = openDrawer()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(document.activeElement).toBe(trigger)
  })

  it('blocks the close button, overlay click, and Escape while busy', () => {
    const { rerender } = render(<DrawerHarness />)
    fireEvent.click(screen.getByText('打开抽屉'))
    rerender(<DrawerHarness busy />)

    const dialog = screen.getByRole('dialog')
    const overlay = dialog.parentElement
    const close = screen.getByLabelText('关闭') as HTMLButtonElement
    expect(close.disabled).toBe(true)
    expect(dialog.getAttribute('aria-busy')).toBe('true')

    fireEvent.click(close)
    if (!overlay) throw new Error('Drawer overlay is missing')
    fireEvent.click(overlay)
    fireEvent.keyDown(document, { key: 'Escape' })

    expect(screen.getByRole('dialog')).toBe(dialog)
  })

  it('stops listening for Escape once closed', () => {
    openDrawer()
    fireEvent.click(screen.getByLabelText('关闭'))
    // 监听器已在 cleanup 中移除，再按 Escape 不应抛错或重复触发关闭。
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('traps Tab inside the drawer', () => {
    openDrawer()
    const submit = screen.getByText('提交')
    const close = screen.getByLabelText('关闭')
    submit.focus()
    fireEvent.keyDown(document, { key: 'Tab' })
    expect(document.activeElement).toBe(close)
  })

  it('traps Shift+Tab inside the drawer', () => {
    openDrawer()
    const submit = screen.getByText('提交')
    const close = screen.getByLabelText('关闭')
    close.focus()
    fireEvent.keyDown(document, { key: 'Tab', shiftKey: true })
    expect(document.activeElement).toBe(submit)
  })

  it('leaves focus alone when the opener was not focusable', () => {
    // 「接入应用」列表行不可聚焦，此时不能把焦点硬塞回 document.body。
    render(<DrawerHarness />)
    fireEvent.click(screen.getByText('打开抽屉'))
    fireEvent.click(screen.getByLabelText('关闭'))
    expect(document.activeElement).toBe(document.body)
  })

  it('pulls focus back when it escaped the drawer', () => {
    const trigger = openDrawer()
    // 例如点击遮罩后焦点落在抽屉外，下一次 Tab 必须回到抽屉内。
    trigger.focus()
    fireEvent.keyDown(document, { key: 'Tab' })
    expect(document.activeElement).toBe(screen.getByLabelText('关闭'))
  })
})
