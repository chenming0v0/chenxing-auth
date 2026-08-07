import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { UsersTable } from './users'
import type { PublicUser } from '../../api'

// UsersTable 直接以 access 属性注入管理身份，绕过 AdminGate / useAdminAccess
// 的网络请求，只测表格本身的交互。fetch 只响应查询与变更接口。

type CapturedRequest = { path: string; method?: string; body?: Record<string, unknown> }

let requests: CapturedRequest[] = []
let confirmCalls = 0
let confirmMessage = ''
let confirmResult = true

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

const SELF: PublicUser = {
  id: 7, username: 'star_owner', email: 'owner@chenxing.star', display_name: '星主',
  status: 'active', role: 'owner', created_at: '2026-01-01T00:00:00Z',
}
const OWNER_2: PublicUser = {
  id: 13, username: 'co_owner', email: 'co_owner@chenxing.star', display_name: '副星主',
  status: 'active', role: 'owner', created_at: '2026-01-03T00:00:00Z',
}
const TARGET: PublicUser = {
  id: 12, username: 'stardust', email: 'stardust@example.com', display_name: '星尘',
  status: 'active', role: 'user', created_at: '2026-01-02T00:00:00Z',
}

const PAGE = { items: [TARGET, OWNER_2, SELF], page: 1, page_size: 20, total: 3 }

beforeEach(() => {
  window.history.replaceState({}, '', '/admin/users')
  requests = []
  confirmCalls = 0
  confirmMessage = ''
  confirmResult = true
  vi.stubGlobal('confirm', (message: string) => {
    confirmCalls += 1
    confirmMessage = message
    return confirmResult
  })
  vi.stubGlobal('fetch', (path: string, init?: RequestInit) => {
    if (path.startsWith('/api/v1/admin/users/query')) {
      requests.push({ path, method: init?.method })
      return Promise.resolve(jsonResponse(PAGE))
    }
    const raw = typeof init?.body === 'string' ? init.body : '{}'
    requests.push({ path, method: init?.method, body: JSON.parse(raw) as Record<string, unknown> })
    return Promise.resolve(jsonResponse(null, 204))
  })
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderTable(permissions: string[] = ['manage_users', 'manage_roles', 'manage_settings', 'read_audit']) {
  render(
    <UsersTable
      access={{
        data: { user_id: 7, username: 'star_owner', role: 'owner', permissions, status: 'active' },
        loading: false,
        error: '',
      }}
    />,
  )
}

function rowOf(name: string): HTMLElement {
  return screen.getByText(name).closest('tr') as HTMLElement
}

function roleSelectIn(name: string): HTMLButtonElement {
  return within(rowOf(name)).getByRole('combobox') as HTMLButtonElement
}

function pickRole(name: string, optionLabel: string) {
  fireEvent.click(roleSelectIn(name))
  fireEvent.click(screen.getByRole('option', { name: optionLabel }))
}

describe('UsersTable 角色修改两步提交（#194 / #203）', () => {
  it('选择新角色先弹确认框，确认后才发出角色变更请求', async () => {
    renderTable()
    await screen.findByText('星尘')
    pickRole('星尘', '管理员')
    expect(confirmCalls).toBe(1)
    const roleReq = requests.find((r) => r.path.endsWith('/role'))
    expect(roleReq?.method).toBe('POST')
    expect(roleReq?.body).toEqual({ role: 'admin' })
    // 成功后刷新列表
    await waitFor(() =>
      expect(requests.filter((r) => r.path.includes('/users/query')).length).toBeGreaterThanOrEqual(2),
    )
  })

  it('取消确认时不发请求，下拉保持原角色', async () => {
    confirmResult = false
    renderTable()
    await screen.findByText('星尘')
    pickRole('星尘', '管理员')
    expect(confirmCalls).toBe(1)
    expect(requests.filter((r) => r.path.endsWith('/role'))).toHaveLength(0)
    expect(roleSelectIn('星尘').textContent).toContain('普通用户')
  })

  it('选择当前已有角色时不弹确认也不发请求', async () => {
    renderTable()
    await screen.findByText('星尘')
    pickRole('星尘', '普通用户')
    expect(confirmCalls).toBe(0)
    expect(requests.filter((r) => r.path.endsWith('/role'))).toHaveLength(0)
  })

  it('提升为 Owner 的确认文案说明全部管理权限后果', async () => {
    confirmResult = false
    renderTable()
    await screen.findByText('星尘')
    pickRole('星尘', 'Owner')
    expect(confirmMessage).toContain('星尘')
    expect(confirmMessage).toContain('「普通用户」改为「Owner」')
    expect(confirmMessage).toContain('提升为 Owner')
    expect(confirmMessage).toContain('全部管理权限')
    expect(confirmMessage).toContain('管理其他管理员与 Owner')
  })

  it('降级 Owner 的确认文案说明移除其全部管理权限', async () => {
    confirmResult = false
    renderTable()
    await screen.findByText('副星主')
    pickRole('副星主', '普通用户')
    expect(confirmMessage).toContain('「Owner」改为「普通用户」')
    expect(confirmMessage).toContain('降级为普通用户')
    expect(confirmMessage).toContain('移除 Owner 的全部管理权限')
    expect(confirmMessage).toContain('仅保留普通用户权限')
  })

  it('Owner 降级为管理员的确认文案说明移除 Owner 独有权限', async () => {
    confirmResult = false
    renderTable()
    await screen.findByText('副星主')
    pickRole('副星主', '管理员')
    expect(confirmMessage).toContain('「Owner」改为「管理员」')
    expect(confirmMessage).toContain('降级为管理员')
    expect(confirmMessage).toContain('移除 Owner 独有的权限')
  })
})

describe('UsersTable 自己的角色不可修改（对齐 self_role_change_forbidden）', () => {
  it('当前登录用户自己的角色下拉被禁用，且带可访问说明', async () => {
    renderTable()
    await screen.findByText('星主')
    const select = roleSelectIn('星主')
    expect(select.disabled).toBe(true)
    expect(select.getAttribute('aria-label')).toContain('不能修改自己的角色')
    expect(within(rowOf('星主')).getByText('不能修改自己的角色')).toBeTruthy()
  })

  it('其他用户（非当前登录账号）的角色下拉可操作', async () => {
    renderTable()
    await screen.findByText('星尘')
    expect(roleSelectIn('星尘').disabled).toBe(false)
    expect(roleSelectIn('副星主').disabled).toBe(false)
  })

  it('缺少 manage_roles 权限时角色下拉禁用，且自己的行仍显示说明', async () => {
    renderTable(['manage_users', 'manage_settings'])
    await screen.findByText('星尘')
    expect(roleSelectIn('星尘').disabled).toBe(true)
    expect(within(rowOf('星尘')).queryByText('不能修改自己的角色')).toBeNull()
    expect(within(rowOf('星主')).getByText('不能修改自己的角色')).toBeTruthy()
  })
})

describe('UsersTable 保持既有行为', () => {
  it('禁用用户仍走原有确认流程并提交', async () => {
    renderTable()
    await screen.findByText('星尘')
    fireEvent.click(within(rowOf('星尘')).getByRole('button', { name: '禁用' }))
    expect(confirmMessage).toBe('确认将 星尘 的状态改为「已禁用」吗？\n禁用后将撤销该用户的全部会话，并阻止其登录。')
    const statusReq = requests.find((r) => r.path.endsWith('/disabled'))
    expect(statusReq?.method).toBe('POST')
  })

  it('角色请求进行中，该行下拉与操作按钮进入 busy 禁用', async () => {
    let release = () => {}
    const pending = new Promise<Response>((resolve) => { release = () => resolve(jsonResponse(null, 204)) })
    vi.stubGlobal('fetch', (path: string) => {
      if (path.startsWith('/api/v1/admin/users/query')) return Promise.resolve(jsonResponse(PAGE))
      return pending
    })
    renderTable()
    await screen.findByText('星尘')
    pickRole('星尘', '管理员')
    await waitFor(() => expect(roleSelectIn('星尘').disabled).toBe(true))
    expect((within(rowOf('星尘')).getByRole('button', { name: '禁用' }) as HTMLButtonElement).disabled).toBe(true)
    release()
    await pending
  })
})
