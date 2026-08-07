import { useId } from 'react'
import { Icon } from './ui'

/* ── 全局「跳到主内容」（#225）─────────────────────────────
   每个 Shell 渲染一对元素：
   - SkipLink：Shell 内第一个可聚焦元素。样式（.chenxing-skip-link）默认把
     它移出视口之外，键盘聚焦（:focus-visible）时才滑入视口顶部，盖在
     topbar / 侧栏之上；鼠标与触摸不可见、不可点。
   - SkipTarget：紧跟重复导航之后、页面内容之前的空锚点。tabIndex={-1}
     让链接激活后能把焦点移进内容区，下一次 Tab 落在内容里的第一个控件上。
   链接与锚点通过同一个 targetId 配对。id 由 useId 派生并去掉冒号（保留
   实例唯一性，同时让「#cx-skip-…」成为干净的 CSS 选择器），因此即使未来
   出现嵌套 Shell，也不会产生重复 id。
   注意：必须用原生 <a href="#…">，不能用 router 的 Link —— 路由器会把片段
   地址当成页面路径 pushState，破坏「不重载、不改路径」的片段跳转语义。 */
export function useSkipTargetId() {
  const id = useId()
  return `cx-skip-${id.replace(/:/g, '')}`
}

export function SkipLink({ targetId }: { targetId: string }) {
  return (
    <a href={`#${targetId}`} className="chenxing-skip-link">
      <Icon name="arrow-down" size={14} />
      跳到主内容
    </a>
  )
}

export function SkipTarget({ targetId }: { targetId: string }) {
  return <div id={targetId} tabIndex={-1} className="chenxing-skip-target" />
}
