import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import type { ReactNode } from 'react'
import { SecurityLogsPage } from './security-logs'
import { ApiError } from '../../api'

const { apiFetchMock } = vi.hoisted(() => ({
  apiFetchMock: vi.fn((_path: string): Promise<unknown> => new Promise(() => {})),
}))

vi.mock('../../api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../api')>()),
  apiFetch: apiFetchMock,
}))

vi.mock('../../components/shells', () => ({
  ConsoleLayout: ({ children }: { children: ReactNode }) => <>{children}</>,
}))

const sampleEvents = {
  items: [
    { id: 1, action: 'login', resource_type: 'session', client_id: null, client_name: null, created_at: '2026-08-12T16:22:00Z' },
    { id: 2, action: 'oauth_consent', resource_type: 'client', client_id: 'cx_demo', client_name: '示例应用', created_at: '2026-08-12T17:13:23Z' },
    { id: 3, action: 'mystery_action', resource_type: null, client_id: null, client_name: null, created_at: '2026-08-12T18:00:00Z' },
  ],
  page: 1,
  page_size: 20,
  total: 3,
}

beforeEach(() => {
  apiFetchMock.mockReset()
  window.history.replaceState({}, '', '/console/logs')
})
afterEach(cleanup)

describe('SecurityLogsPage', () => {
  it('以分页参数请求用户级安全日志接口', async () => {
    apiFetchMock.mockResolvedValue(sampleEvents)
    render(<SecurityLogsPage />)
    await screen.findByText('共 3 条')
    expect(apiFetchMock).toHaveBeenCalledWith('/api/v1/auth/security-events?page=1&page_size=20')
  })

  it('桌面表格与移动卡片渲染同一份事件，已知 action 用友好文案', async () => {
    apiFetchMock.mockResolvedValue(sampleEvents)
    render(<SecurityLogsPage />)
    // 桌面表格与移动卡片各渲染一份（CSS 按断点隐藏其一）
    expect(await screen.findAllByText('登录')).toHaveLength(2)
    expect(screen.getAllByText('授权应用')).toHaveLength(2)
    expect(screen.getAllByText('示例应用')).toHaveLength(2)
    // 未知 action 原样展示，不猜文案
    expect(screen.getAllByText('mystery_action')).toHaveLength(2)
  })

  it('接口 404（尚未实现）时落到示例数据预览并标注 #307', async () => {
    apiFetchMock.mockRejectedValue(new ApiError('请求的资源不存在或已失效。', 404))
    render(<SecurityLogsPage />)
    const notice = await screen.findByText(/示例数据预览/)
    expect(notice.textContent).toContain('#307')
    // 示例事件已渲染（桌面表格 + 移动卡片各一份）
    expect(screen.getAllByText('WONG 公益站备用').length).toBeGreaterThan(0)
    expect(screen.getAllByText('登录').length).toBeGreaterThan(0)
  })

  it('其他错误展示警告信息', async () => {
    apiFetchMock.mockRejectedValue(new Error('服务器繁忙'))
    render(<SecurityLogsPage />)
    expect(await screen.findByText('服务器繁忙')).toBeTruthy()
  })

  it('列表行链接指向 ?id= 详情路由', async () => {
    apiFetchMock.mockResolvedValue(sampleEvents)
    render(<SecurityLogsPage />)
    const links = await screen.findAllByRole('link', { name: '查看日志 #2 详情' })
    for (const link of links) expect(link.getAttribute('href')).toBe('/console/logs?id=2')
  })
})

describe('SecurityLogDetail（经 ?id= 进入）', () => {
  it('以事件 id 请求详情接口', async () => {
    window.history.replaceState({}, '', '/console/logs?id=42')
    apiFetchMock.mockReturnValue(new Promise(() => {}))
    render(<SecurityLogsPage />)
    await screen.findByText('日志详情')
    expect(apiFetchMock).toHaveBeenCalledWith('/api/v1/auth/security-events/42')
  })

  it('404 落到示例详情：敏感字段默认打码，点眼睛才显示明文', async () => {
    window.history.replaceState({}, '', '/console/logs?id=11045978')
    apiFetchMock.mockRejectedValue(new ApiError('请求的资源不存在或已失效。', 404))
    render(<SecurityLogsPage />)
    await screen.findByText(/示例数据预览/)
    // 事件信息与应用信息面板（#11045978 是 oauth_consent，带 client）
    expect(screen.getByText('事件信息')).toBeTruthy()
    expect(screen.getByText('应用信息')).toBeTruthy()
    expect(screen.getByText('WONG 公益站备用')).toBeTruthy()
    // IP 默认打码
    expect(screen.queryByText(/203\.0\.113\./)).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: '显示IP 地址' }))
    expect(screen.getByText(/203\.0\.113\./)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: '隐藏IP 地址' }))
    expect(screen.queryByText(/203\.0\.113\./)).toBeNull()
  })

  it('404 且 id 不在示例数据中时提示记录不存在', async () => {
    window.history.replaceState({}, '', '/console/logs?id=99')
    apiFetchMock.mockRejectedValue(new ApiError('请求的资源不存在或已失效。', 404))
    render(<SecurityLogsPage />)
    expect(await screen.findByText('日志记录不存在或已失效。')).toBeTruthy()
  })

  it('详情页提供返回列表的链接', async () => {
    window.history.replaceState({}, '', '/console/logs?id=11045978')
    apiFetchMock.mockRejectedValue(new ApiError('请求的资源不存在或已失效。', 404))
    render(<SecurityLogsPage />)
    const back = await screen.findByRole('link', { name: /返回/ })
    expect(back.getAttribute('href')).toBe('/console/logs')
  })
})
