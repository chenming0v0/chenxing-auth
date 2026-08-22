import { useEffect, useLayoutEffect, useRef } from 'react'

const FOCUSABLE_SELECTOR = [
  'button',
  '[href]',
  'input',
  'select',
  'textarea',
  '[tabindex]:not([tabindex="-1"])',
].join(', ')

function focusableWithin(container: HTMLElement): HTMLElement[] {
  return Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter((element) => (
    element.tabIndex >= 0
    && !element.matches(':disabled')
    && !element.closest('[hidden], [inert], [aria-hidden="true"]')
  ))
}

type ModalFocusOptions = {
  /** CSS selector for the field that should receive focus when the modal opens. */
  initialFocusSelector?: string
  /** Re-focus the dialog's initial target when an existing modal changes stage. */
  focusKey?: unknown
  /** Some existing dialogs intentionally remain open while an operation is busy. */
  escapeDisabled?: boolean
}

/**
 * Focus management for regular modal dialogs.
 *
 * This is deliberately separate from Drawer focus management: drawers also
 * isolate the page background and lock scrolling, while regular modals do not.
 */
export function useModalFocus<T extends HTMLElement>(
  onClose: () => void,
  { initialFocusSelector, focusKey, escapeDisabled = false }: ModalFocusOptions = {},
) {
  const containerRef = useRef<T>(null)
  const onCloseRef = useRef(onClose)
  const escapeDisabledRef = useRef(escapeDisabled)
  onCloseRef.current = onClose
  escapeDisabledRef.current = escapeDisabled

  useLayoutEffect(() => {
    const opener = document.activeElement
    const container = containerRef.current
    if (!container) return

    return () => {
      if (opener instanceof HTMLElement && opener !== document.body && opener.isConnected) {
        opener.focus()
      }
    }
  }, [])

  useLayoutEffect(() => {
    const container = containerRef.current
    if (!container) return

    const focusable = focusableWithin(container)
    const requestedTarget = initialFocusSelector
      ? container.querySelector<HTMLElement>(initialFocusSelector)
      : null
    const target = requestedTarget && focusable.includes(requestedTarget) ? requestedTarget : focusable[0]
    ;(target ?? container).focus()
  }, [initialFocusSelector, focusKey])

  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      const container = containerRef.current
      if (!container) return

      if (event.key === 'Escape') {
        event.preventDefault()
        if (!escapeDisabledRef.current) onCloseRef.current()
        return
      }
      if (event.key !== 'Tab') return

      const focusable = focusableWithin(container)
      if (focusable.length === 0) {
        event.preventDefault()
        container.focus()
        return
      }

      const first = focusable[0]
      const last = focusable[focusable.length - 1]
      const active = document.activeElement
      const outside = !container.contains(active)
      const activeIndex = active instanceof HTMLElement ? focusable.indexOf(active) : -1
      if (event.shiftKey) {
        if (outside || activeIndex <= 0) {
          event.preventDefault()
          last.focus()
        }
      } else if (outside || activeIndex === -1 || activeIndex === focusable.length - 1) {
        event.preventDefault()
        first.focus()
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [])

  return containerRef
}
