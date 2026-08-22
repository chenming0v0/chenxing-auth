import { afterEach, describe, expect, it } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { useState } from 'react'
import { createPortal } from 'react-dom'
import { useModalFocus } from './modal'

function ModalHarness() {
  const [open, setOpen] = useState(false)

  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>打开弹窗</button>
      {open ? createPortal(<ModalContents onClose={() => setOpen(false)} />, document.body) : null}
    </>
  )
}

function ModalContents({ onClose }: { onClose: () => void }) {
  const containerRef = useModalFocus<HTMLDivElement>(onClose, {
    initialFocusSelector: '#modal-first-field',
  })

  return (
    <div ref={containerRef} role="dialog" aria-modal="true" tabIndex={-1}>
      <button type="button" aria-label="关闭" onClick={onClose}>关闭</button>
      <input id="modal-first-field" aria-label="第一个字段" />
      <button type="button">最后一个操作</button>
    </div>
  )
}

function BusyModalHarness() {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>打开忙碌弹窗</button>
      {open ? <BusyModalContents busy={busy} onBusy={setBusy} onClose={() => setOpen(false)} /> : null}
    </>
  )
}

function StagedModalHarness() {
  const [open, setOpen] = useState(false)
  const [stage, setStage] = useState<'first' | 'second'>('first')

  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>打开分阶段弹窗</button>
      {open ? <StagedModalContents stage={stage} onStage={setStage} onClose={() => setOpen(false)} /> : null}
    </>
  )
}

function StagedModalContents({ stage, onStage, onClose }: { stage: 'first' | 'second'; onStage: (stage: 'first' | 'second') => void; onClose: () => void }) {
  const containerRef = useModalFocus<HTMLDivElement>(onClose, {
    initialFocusSelector: stage === 'first' ? '#staged-first-field' : '#staged-second-field',
    focusKey: stage,
  })

  return (
    <div ref={containerRef} role="dialog" aria-modal="true" tabIndex={-1}>
      <button type="button" onClick={onClose}>关闭分阶段弹窗</button>
      {stage === 'first' ? <input id="staged-first-field" aria-label="第一阶段字段" /> : <input id="staged-second-field" aria-label="第二阶段字段" />}
      <button type="button" onClick={() => onStage(stage === 'first' ? 'second' : 'first')}>切换阶段</button>
    </div>
  )
}

function BusyModalContents({ busy, onBusy, onClose }: { busy: boolean; onBusy: (busy: boolean) => void; onClose: () => void }) {
  const containerRef = useModalFocus<HTMLDivElement>(onClose, {
    initialFocusSelector: '#busy-modal-field',
    escapeDisabled: busy,
  })

  return (
    <div ref={containerRef} role="dialog" aria-modal="true" tabIndex={-1}>
      <button type="button" aria-label="关闭忙碌弹窗" onClick={onClose} disabled={busy}>关闭</button>
      <input id="busy-modal-field" aria-label="忙碌字段" disabled={busy} />
      <button type="button" aria-label="忙碌提交" onClick={() => onBusy(true)} disabled={busy}>提交</button>
      <button type="button" aria-label="完成忙碌操作" onClick={() => onBusy(false)}>完成忙碌操作</button>
    </div>
  )
}

afterEach(cleanup)

describe('useModalFocus', () => {
  it('moves initial focus into the modal and restores the opener after Escape', () => {
    render(<ModalHarness />)
    const opener = screen.getByRole('button', { name: '打开弹窗' })
    opener.focus()
    fireEvent.click(opener)

    expect(document.activeElement).toBe(screen.getByLabelText('第一个字段'))
    fireEvent.keyDown(document, { key: 'Escape' })

    expect(screen.queryByRole('dialog')).toBeNull()
    expect(document.activeElement).toBe(opener)
  })

  it('traps Tab and Shift+Tab at both modal boundaries', () => {
    render(<ModalHarness />)
    const opener = screen.getByRole('button', { name: '打开弹窗' })
    opener.focus()
    fireEvent.click(opener)

    const close = screen.getByRole('button', { name: '关闭' })
    const lastAction = screen.getByRole('button', { name: '最后一个操作' })
    lastAction.focus()
    fireEvent.keyDown(document, { key: 'Tab' })
    expect(document.activeElement).toBe(close)

    close.focus()
    fireEvent.keyDown(document, { key: 'Tab', shiftKey: true })
    expect(document.activeElement).toBe(lastAction)
  })

  it('pulls focus back into the modal when Tab starts outside it', () => {
    render(<ModalHarness />)
    const opener = screen.getByRole('button', { name: '打开弹窗' })
    opener.focus()
    fireEvent.click(opener)
    opener.focus()

    fireEvent.keyDown(document, { key: 'Tab' })
    expect(document.activeElement).toBe(screen.getByRole('button', { name: '关闭' }))
  })

  it('moves focus to the new initial target when a modal changes stage', () => {
    render(<StagedModalHarness />)
    const opener = screen.getByRole('button', { name: '打开分阶段弹窗' })
    opener.focus()
    fireEvent.click(opener)

    expect(document.activeElement).toBe(screen.getByLabelText('第一阶段字段'))
    fireEvent.click(screen.getByRole('button', { name: '切换阶段' }))

    expect(document.activeElement).toBe(screen.getByLabelText('第二阶段字段'))
  })

  it('keeps Escape disabled during a busy operation and excludes disabled controls from focus order', () => {
    render(<BusyModalHarness />)
    const opener = screen.getByRole('button', { name: '打开忙碌弹窗' })
    opener.focus()
    fireEvent.click(opener)

    const field = screen.getByLabelText('忙碌字段')
    expect(document.activeElement).toBe(field)
    fireEvent.click(screen.getByRole('button', { name: '忙碌提交' }))

    expect(field).toHaveProperty('disabled', true)
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.getByRole('dialog')).toBeTruthy()

    fireEvent.keyDown(document, { key: 'Tab' })
    expect(document.activeElement).toBe(screen.getByRole('button', { name: '完成忙碌操作' }))

    fireEvent.keyDown(document, { key: 'Tab', shiftKey: true })
    expect(document.activeElement).toBe(screen.getByRole('button', { name: '完成忙碌操作' }))
  })

  it('does not steal focus when busy changes', () => {
    render(<BusyModalHarness />)
    const opener = screen.getByRole('button', { name: '打开忙碌弹窗' })
    opener.focus()
    fireEvent.click(opener)

    const field = screen.getByLabelText('忙碌字段')
    const finish = screen.getByRole('button', { name: '完成忙碌操作' })
    finish.focus()
    fireEvent.click(screen.getByRole('button', { name: '忙碌提交' }))

    expect(document.activeElement).toBe(finish)
    expect(field).toHaveProperty('disabled', true)
  })

  it('keeps the dialog focusable when it has no enabled controls', () => {
    function EmptyModalHarness() {
      const [open, setOpen] = useState(false)
      return (
        <>
          <button type="button" onClick={() => setOpen(true)}>打开空弹窗</button>
          {open ? createPortal(
            <EmptyModalContents onClose={() => setOpen(false)} />,
            document.body,
          ) : null}
        </>
      )
    }

    function EmptyModalContents({ onClose }: { onClose: () => void }) {
      const containerRef = useModalFocus<HTMLDivElement>(onClose, {
        initialFocusSelector: '#empty-modal-field',
      })

      return (
        <div ref={containerRef} role="dialog" aria-modal="true" tabIndex={-1}>
          <input id="empty-modal-field" aria-label="空弹窗字段" disabled />
        </div>
      )
    }

    render(<EmptyModalHarness />)
    const opener = screen.getByRole('button', { name: '打开空弹窗' })
    opener.focus()
    fireEvent.click(opener)

    const dialog = screen.getByRole('dialog')
    expect(document.activeElement).toBe(dialog)
    fireEvent.keyDown(document, { key: 'Tab' })
    expect(document.activeElement).toBe(dialog)
  })
})
