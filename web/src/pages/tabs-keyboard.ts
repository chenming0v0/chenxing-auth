import type { KeyboardEvent } from 'react'

/**
 * ARIA Tabs 的键盘导航（#691）。
 *
 * 这里刻意只提供键盘逻辑，不提供 Tabs 组件：通用 UI 组件的唯一来源是 `@chenxing/ui`，
 * 页面侧不得再造一套同名容器。页面继续自己渲染 `role="tablist"` / `role="tab"`，
 * 只把按键处理挂到 tablist 上。
 *
 * 本项目的页签是「选中即切换」（automatic activation）：方向键移动焦点的同时立刻
 * 激活对应面板，因此焦点与选中项恒等，roving tabindex 只需按 `selected ? 0 : -1`
 * 渲染，不需要额外维护一份焦点索引。
 */

/**
 * 水平 tablist 中某个按键对应的目标索引；不属于 tabs 模式的按键返回 null。
 *
 * 方向键循环（首尾相接）是 WAI-ARIA Authoring Practices 允许的行为，
 * 两个页签的场景下它让 ArrowLeft 和 ArrowRight 都能到达另一个页签。
 */
export function nextTabIndex(key: string, current: number, count: number): number | null {
  if (count <= 0) return null
  const from = current >= 0 && current < count ? current : 0
  switch (key) {
    case 'ArrowRight':
      return (from + 1) % count
    case 'ArrowLeft':
      return (from - 1 + count) % count
    case 'Home':
      return 0
    case 'End':
      return count - 1
    default:
      return null
  }
}

/**
 * `role="tablist"` 容器的 onKeyDown 实现。
 *
 * `tabs` 的顺序必须与容器内 `role="tab"` 按钮的 DOM 顺序一致：目标索引由 DOM 中的
 * 按钮位置算出，再用同一索引取出要激活的页签值。焦点先移动、再调用 onSelect，
 * 保证重渲染后焦点仍在用户刚选中的按钮上（未选中项的 tabIndex 是 -1，但已获得
 * 焦点的元素不会因此失焦）。
 */
export function handleTabListKeyDown<T extends string>(
  event: KeyboardEvent<HTMLElement>,
  tabs: readonly T[],
  onSelect: (tab: T) => void,
): void {
  const buttons = Array.from(event.currentTarget.querySelectorAll<HTMLElement>('[role="tab"]'))
  if (!buttons.length) return
  const origin = event.target instanceof Element ? event.target.closest('[role="tab"]') : null
  const current = origin instanceof HTMLElement ? buttons.indexOf(origin) : -1
  const target = nextTabIndex(event.key, current, buttons.length)
  // 目标越界只可能是调用方传入的 tabs 与 DOM 中的页签数量不一致：此时什么都不做，
  // 也不吞掉按键，避免把页面的滚动键变成静默失败。
  if (target === null || target >= tabs.length) return
  // Home / End 与方向键在可滚动容器里都会滚动页面，tabs 模式下必须拦掉。
  event.preventDefault()
  buttons[target].focus()
  onSelect(tabs[target])
}
