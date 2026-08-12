import type { ReactNode } from 'react'
import { Button, HudPanel, Icon } from './ui'

/**
 * 表头列定义。绝大多数列是左对齐文本，直接传字符串；
 * 只有需要对齐方式或自定义节点时才升级成对象，避免调用方为常见情况写样板。
 */
export type DataTableColumn =
  | string
  | {
      label: ReactNode
      align?: 'left' | 'right' | 'center'
      /**
       * label 不是字符串（或为空串）时的 key 基础名；
       * 组件会追加列下标保证唯一，见 columnKey。
       */
      key?: string
    }

type DataTableProps = {
  columns: DataTableColumn[]
  /** 低于该宽度时 .cx-table-wrap 出现横向滚动，不挤压列 */
  minWidth?: number
  /**
   * 无数据时渲染的内容，自动跨满所有列。
   * 「加载中 / 空结果 / 无权限」文案由调用方判断，组件只负责摆放位置，
   * 因此有数据时传 null。
   */
  empty?: ReactNode
  /** <tbody> 内容，由调用方渲染 <tr>；单元格无需再写 padding 与分隔线 */
  children?: ReactNode
  className?: string
}

const alignClass = { left: '', right: 'text-right', center: 'text-center' } as const

/**
 * React key 必须唯一：列名（或显式 key）只作可读基础名，
 * 统一追加下标消歧，否则两个同名列（如重复的「操作」）会触发
 * React duplicate key 警告并导致 DOM 复用错乱。
 */
function columnKey(column: DataTableColumn, index: number): string {
  const base =
    typeof column === 'string'
      ? column || 'col'
      : column.key ?? (typeof column.label === 'string' ? column.label : 'col')
  return `${base}-${index}`
}

/**
 * 表格唯一入口：`.cx-table-wrap` / `.cx-table` 的类名契约只在这里出现一次。
 * 页面不得自己拼表格外框、表头排版或分隔线，否则表格规范变更时无法统一跟随。
 */
export function DataTable({ columns, minWidth, empty, children, className = '' }: DataTableProps) {
  return (
    <div className={`cx-table-wrap mt-5 ${className}`}>
      <table className="cx-table" style={minWidth ? { minWidth: `${minWidth}px` } : undefined}>
        <thead>
          <tr>
            {columns.map((column, index) => {
              const isText = typeof column === 'string'
              const align = isText ? 'left' : column.align ?? 'left'
              return (
                <th key={columnKey(column, index)} scope="col" className={alignClass[align]}>
                  {isText ? column : column.label}
                </th>
              )
            })}
          </tr>
        </thead>
        <tbody>
          {children}
          {/* 空态留在表格内：表头与列结构保持可见，不会出现「空表框 + 下方孤立空态」两段式布局 */}
          {empty ? (
            <tr className="cx-table-empty-row">
              <td className="cx-table-empty" colSpan={columns.length}>{empty}</td>
            </tr>
          ) : null}
        </tbody>
      </table>
    </div>
  )
}

type TablePanelProps = {
  /** 标题左侧的青色图标，用于让列表面板之间保持同一视觉节奏 */
  icon?: string
  title: string
  description?: string
  /** 右上角操作区：主按钮，或筛选控件组 */
  action?: ReactNode
  /** 标题与表格之间的提示区，例如错误 Notice */
  notice?: ReactNode
  children: ReactNode
  className?: string
}

/**
 * 列表面板：统一「HudPanel + 图标标题 + 说明 + 右上操作 + 表格」的排版。
 * 表格类页面一律走这里，不要再用 `HudPanel !p-0` 做通栏表格。
 */
export function TablePanel({ icon, title, description, action, notice, children, className = '' }: TablePanelProps) {
  return (
    <HudPanel className={className}>
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <h2 className="chenxing-h2 flex items-center gap-2">
            {icon ? <Icon name={icon} className="shrink-0 text-[var(--chenxing-cyan)]" size={18} /> : null}
            {title}
          </h2>
          {description ? <p className="chenxing-caption mt-1.5">{description}</p> : null}
        </div>
        {action ? <div className="flex flex-wrap items-center gap-3">{action}</div> : null}
      </div>
      {notice ? <div className="mt-4">{notice}</div> : null}
      {children}
    </HudPanel>
  )
}

type TablePaginationProps = {
  page: number
  totalPages: number
  total: number
  onPageChange: (page: number) => void
}

/**
 * 分页控件：audit / clients / users 三处完全一样的翻页栏，抽到这里避免重复。
 */
export function TablePagination({ page, totalPages, total, onPageChange }: TablePaginationProps) {
  return (
    <div className="mt-5 flex items-center justify-between gap-3">
      <Button variant="ghost" disabled={page <= 1} onClick={() => onPageChange(page - 1)}>上一页</Button>
      <span className="chenxing-caption">第 {page} / {totalPages} 页 · 共 {total} 条</span>
      <Button variant="ghost" disabled={page >= totalPages} onClick={() => onPageChange(page + 1)}>下一页</Button>
    </div>
  )
}
