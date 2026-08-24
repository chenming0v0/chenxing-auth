import { useEffect, useId, useRef, type FormEventHandler, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { activateDrawerModal } from './drawer-modal-effects'
import { Icon } from './ui'

/**
 * ARIA Authoring Practices 的 dialog 模式要求模态内容自带焦点陷阱，
 * 这里是判定「可聚焦元素」的选择器；顺序即 DOM 顺序，用于取首尾两端。
 */
const FOCUSABLE_SELECTOR = [
  'button:not([disabled])',
  '[href]',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(', ')

function focusableWithin(container: HTMLElement): HTMLElement[] {
  return Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR))
}

/**
 * 抽屉的焦点管理：挂载即视为「打开」，卸载即视为「关闭」，
 * 因此调用方只需按开关状态条件渲染抽屉，不需要额外传 isOpen。
 *
 * 无障碍依据：
 * - WCAG 2.1 SC 2.4.3（焦点顺序）：打开时焦点必须移入抽屉，关闭后必须回到触发元素，
 *   否则键盘用户会被留在页面背景里，屏幕阅读器也不会朗读新出现的内容。
 * - ARIA APG dialog 模式：模态对话框期间 Tab / Shift+Tab 只在对话框内循环，Escape 关闭。
 */
export function useDrawerFocus(onClose: () => void, busy = false) {
  const containerRef = useRef<HTMLDivElement>(null)
  // 键盘监听器只注册一次；latest refs 让它读取当前关闭回调和提交状态，
  // 保证提交开始后 Escape 立即失效，卸载时监听器也能可靠移除。
  const onCloseRef = useRef(onClose)
  const busyRef = useRef(busy)
  onCloseRef.current = onClose
  busyRef.current = busy

  useEffect(() => {
    // 记录触发元素：抽屉是从某个按钮打开的，关闭后焦点必须还给它。
    const opener = document.activeElement
    const container = containerRef.current
    if (!container) return

    const restoreModalEffects = activateDrawerModal(container)
    const focusable = focusableWithin(container)
    // 首个可聚焦元素通常是关闭按钮；没有可聚焦内容时退回到容器自身（tabIndex=-1）。
    const target = focusable.length > 0 ? focusable[0] : container
    target.focus()

    return () => {
      restoreModalEffects()
      // document.body 不是真正的触发元素（例如点击不可聚焦的列表行打开抽屉），
      // 触发元素已从 DOM 移除时也不再强行聚焦。
      if (opener instanceof HTMLElement && opener !== document.body && opener.isConnected) {
        opener.focus()
      }
    }
  }, [])

  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      const container = containerRef.current
      if (!container) return

      if (event.key === 'Escape') {
        event.preventDefault()
        if (!busyRef.current) onCloseRef.current()
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
      // 到达边界或焦点已经逃出抽屉时，把焦点拉回另一端形成循环。
      if (event.shiftKey) {
        if (outside || active === first) {
          event.preventDefault()
          last.focus()
        }
      } else if (outside || active === last) {
        event.preventDefault()
        first.focus()
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [])

  return containerRef
}

type DrawerProps = {
  title: string
  description?: string
  /** 遮罩点击、关闭按钮和 Escape 共用的关闭回调。 */
  onClose: () => void
  onSubmit: FormEventHandler<HTMLFormElement>
  /** 提交期间阻止关闭按钮、遮罩点击和 Escape 关闭；默认不阻止。 */
  busy?: boolean
  /** 抽屉底部操作区，通常是「取消 + 提交」。 */
  footer: ReactNode
  children: ReactNode
}

/**
 * 右侧模态抽屉：包含遮罩、标题栏、可滚动表单主体和底部操作区。
 * 抽屉是真正的模态覆盖层，因此使用 role="dialog" + aria-modal + aria-labelledby，
 * 打开期间锁定页面滚动，并把抽屉祖先路径之外的背景分支标记为不可交互。
 */
export function Drawer({ title, description, onClose, onSubmit, busy = false, footer, children }: DrawerProps) {
  const titleId = useId()
  const descriptionId = useId()
  const containerRef = useDrawerFocus(onClose, busy)

  function requestClose() {
    if (!busy) onClose()
  }

  return createPortal(
    <div className="chenxing-drawer-overlay is-open" onClick={requestClose}>
      <div
        ref={containerRef}
        className="chenxing-drawer is-open"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description ? descriptionId : undefined}
        aria-busy={busy || undefined}
        tabIndex={-1}
        onClick={(event) => event.stopPropagation()}
      >
        <div className="chenxing-drawer-header">
          <div>
            <h2 className="chenxing-h2" id={titleId}>{title}</h2>
            {description ? <p className="chenxing-caption mt-1" id={descriptionId}>{description}</p> : null}
          </div>
          <button type="button" className="chenxing-icon-btn" aria-label="关闭" onClick={requestClose} disabled={busy}><Icon name="x" size={16} /></button>
        </div>
        {/* noValidate：抽屉的校验文案一律由 React 侧渲染（Field errorText + aria-describedby），
            原生约束校验会在提交前拦截（如 type="email" 的畸形值、required 空值），
            让浏览器气泡顶替应用自己的错误提示，甚至让 onSubmit 根本不触发。 */}
        <form className="flex min-h-0 flex-1 flex-col" onSubmit={onSubmit} noValidate>
          <div className="chenxing-drawer-body space-y-4">{children}</div>
          <div className="chenxing-drawer-footer">{footer}</div>
        </form>
      </div>
    </div>,
    document.body
  )
}
