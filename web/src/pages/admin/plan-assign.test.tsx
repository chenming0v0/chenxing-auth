import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { AssignPlanDrawer } from './plan-assign'
import type { AdminPlan } from '../../api'

const { apiFetchMock } = vi.hoisted(() => ({
  apiFetchMock: vi.fn((_path: string, _init?: RequestInit): Promise<unknown> => new Promise(() => {})),
}))

vi.mock('../../api', () => ({
  apiFetch: apiFetchMock,
}))

const PLAN_BASIC: AdminPlan = {
  id: 1,
  code: 'basic',
  name: '基础版',
  description: null,
  oauth_clients_limit: 3,
  daily_auth_limit: 100,
  monthly_auth_limit: 1000,
  max_qps: 10,
  is_default: true,
  status: 'active',
  assigned_users: 2,
}

const PLAN_PRO: AdminPlan = {
  id: 2,
  code: 'pro',
  name: '专业版',
  description: null,
  oauth_clients_limit: 10,
  daily_auth_limit: 1000,
  monthly_auth_limit: null,
  max_qps: null,
  is_default: false,
  status: 'active',
  assigned_users: 0,
}

beforeEach(() => { apiFetchMock.mockReset() })
afterEach(cleanup)

function openDrawer() {
  return render(
    <AssignPlanDrawer
      userId={12}
      userName="星尘"
      onAssigned={() => {}}
      onClose={() => {}}
    />,
  )
}

async function openPlanSelect() {
  const trigger = await screen.findByRole('combobox')
  fireEvent.click(trigger)
  return trigger
}

describe('AssignPlanDrawer 每次打开都重新拉套餐（#373）', () => {
  it('关闭后再打开会重新请求，并展示新建的套餐', async () => {
    apiFetchMock
      .mockResolvedValueOnce([PLAN_BASIC])
      .mockResolvedValueOnce([PLAN_BASIC, PLAN_PRO])

    const first = openDrawer()
    await openPlanSelect()
    expect(screen.getByRole('option', { name: /基础版 · basic/ })).toBeTruthy()
    expect(screen.queryByRole('option', { name: /专业版 · pro/ })).toBeNull()
    first.unmount()

    openDrawer()
    await openPlanSelect()
    expect(screen.getByRole('option', { name: /基础版 · basic/ })).toBeTruthy()
    expect(screen.getByRole('option', { name: /专业版 · pro/ })).toBeTruthy()
    expect(apiFetchMock.mock.calls.filter(([path]) => path === '/api/v1/admin/plans')).toHaveLength(2)
  })

  it('再次打开时丢掉已归档套餐，只列出当前启用项', async () => {
    apiFetchMock
      .mockResolvedValueOnce([PLAN_BASIC, PLAN_PRO])
      .mockResolvedValueOnce([{ ...PLAN_BASIC, status: 'archived' }, PLAN_PRO])

    const first = openDrawer()
    await openPlanSelect()
    expect(screen.getByRole('option', { name: /基础版 · basic/ })).toBeTruthy()
    first.unmount()

    openDrawer()
    await openPlanSelect()
    expect(screen.queryByRole('option', { name: /基础版 · basic/ })).toBeNull()
    expect(screen.getByRole('option', { name: /专业版 · pro/ })).toBeTruthy()
    expect(apiFetchMock.mock.calls.filter(([path]) => path === '/api/v1/admin/plans')).toHaveLength(2)
  })
})

describe('AssignPlanDrawer 提交互斥（#586）', () => {
  it('busy 尚未重渲染时重复提交只发出一个分配请求', async () => {
    const assignPath = '/api/v1/admin/users/12/plan'
    apiFetchMock.mockImplementation((path: string) => {
      if (path === '/api/v1/admin/plans') return Promise.resolve([PLAN_BASIC, PLAN_PRO])
      if (path === assignPath) return new Promise(() => {})
      return Promise.reject(new Error(`unexpected ${path}`))
    })

    openDrawer()
    await openPlanSelect()
    fireEvent.click(screen.getByRole('option', { name: /基础版 · basic/ }))

    const form = screen.getByRole('button', { name: '分配套餐' }).closest('form') as HTMLFormElement
    fireEvent.submit(form)
    fireEvent.submit(form)

    await waitFor(() => {
      expect(apiFetchMock.mock.calls.filter(([path]) => path === assignPath)).toHaveLength(1)
    })
    expect(apiFetchMock.mock.calls.filter(([path]) => path === assignPath)).toHaveLength(1)
  })
})
