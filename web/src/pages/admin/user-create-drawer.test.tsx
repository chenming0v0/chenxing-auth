import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { UserCreateDrawer } from './user-create-drawer'

type CapturedRequest = { path: string; method?: string; body: Record<string, unknown> }

let requests: CapturedRequest[] = []
let respond: () => Response

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

const CREATED = {
  id: 7, username: 'stardust', email: 'stardust@example.com', display_name: '星尘',
  status: 'active', role: 'user', created_at: '2026-01-01T00:00:00Z',
}

beforeEach(() => {
  requests = []
  respond = () => jsonResponse(CREATED, 201)
  vi.stubGlobal('fetch', (path: string, init?: RequestInit) => {
    const raw = typeof init?.body === 'string' ? init.body : '{}'
    requests.push({ path, method: init?.method, body: JSON.parse(raw) as Record<string, unknown> })
    return Promise.resolve(respond())
  })
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderDrawer(options: { canManageRoles?: boolean; onCreated?: (user: unknown) => void; onClose?: () => void } = {}) {
  render(
    <UserCreateDrawer
      canManageRoles={options.canManageRoles ?? true}
      onClose={options.onClose ?? (() => {})}
      onCreated={options.onCreated ?? (() => {})}
    />,
  )
}

function fill(values: { username?: string; email?: string; password?: string; displayName?: string } = {}) {
  fireEvent.change(screen.getByLabelText('用户名'), { target: { value: values.username ?? 'stardust' } })
  fireEvent.change(screen.getByLabelText('邮箱'), { target: { value: values.email ?? 'stardust@example.com' } })
  fireEvent.change(screen.getByLabelText('初始密码'), { target: { value: values.password ?? 'sufficiently-long' } })
  if (values.displayName !== undefined) {
    fireEvent.change(screen.getByLabelText('显示名称（选填）'), { target: { value: values.displayName } })
  }
}

function submit() {
  fireEvent.click(screen.getByRole('button', { name: '创建用户' }))
}

describe('UserCreateDrawer 客户端校验', () => {
  it('必填项为空时不发请求，并聚焦第一个出错字段', () => {
    renderDrawer()
    submit()
    expect(requests).toEqual([])
    expect(screen.getByText('请填写用户名。')).toBeTruthy()
    expect(screen.getByText('请填写邮箱。')).toBeTruthy()
    expect(screen.getByText('请填写初始密码。')).toBeTruthy()
    expect(document.activeElement).toBe(screen.getByLabelText('用户名'))
  })

  it('拒绝含 @ 的用户名', () => {
    renderDrawer()
    fill({ username: 'star@dust' })
    submit()
    expect(requests).toEqual([])
    expect(screen.getByText('用户名不能包含 @ 或空格。')).toBeTruthy()
  })

  it('拒绝系统保留名和不安全字符', () => {
    renderDrawer()
    fill({ username: 'SYSTEM' })
    submit()
    expect(requests).toEqual([])
    expect(screen.getByText('该用户名为系统保留名称，请更换。')).toBeTruthy()

    fireEvent.change(screen.getByLabelText('用户名'), { target: { value: 'safe/name' } })
    submit()
    expect(requests).toEqual([])
    expect(screen.getByText('用户名只能包含字母、数字、点号、下划线和连字符。')).toBeTruthy()
  })

  it('拒绝过短的用户名', () => {
    renderDrawer()
    fill({ username: 'ab' })
    submit()
    expect(screen.getByText('用户名需要 3 到 64 个字符。')).toBeTruthy()
  })

  it('拒绝格式不正确的邮箱', () => {
    renderDrawer()
    fill({ email: 'stardust@example' })
    submit()
    expect(requests).toEqual([])
    expect(screen.getByText('邮箱格式不正确，例如 name@example.com。')).toBeTruthy()
  })

  it('拒绝少于 10 个字符的密码', () => {
    renderDrawer()
    fill({ password: 'short' })
    submit()
    expect(requests).toEqual([])
    expect(screen.getByText('密码至少需要 10 个字符。')).toBeTruthy()
  })

  it('密码长度按字符数计，不按字节数', () => {
    renderDrawer()
    // 10 个汉字是 30 字节，按字符计正好达到下限，不应报错
    fill({ password: '星尘长夜穹顶信标航' + '标' })
    submit()
    return waitFor(() => expect(requests.length).toBe(1))
  })

  it('显示名称超过 128 字符时报错', () => {
    renderDrawer()
    fill({ displayName: 'x'.repeat(129) })
    submit()
    expect(requests).toEqual([])
    expect(screen.getByText('显示名称最多 128 个字符。')).toBeTruthy()
  })

  it('把错误文案通过 aria-describedby 绑定到控件并标记 aria-invalid', () => {
    renderDrawer()
    submit()
    const username = screen.getByLabelText('用户名')
    expect(username.getAttribute('aria-invalid')).toBe('true')
    const describedBy = username.getAttribute('aria-describedby')
    expect(describedBy).toBeTruthy()
    expect(document.getElementById(describedBy as string)?.textContent).toContain('请填写用户名。')
  })

  it('修改字段后清掉该字段的旧错误', () => {
    renderDrawer()
    submit()
    expect(screen.getByText('请填写用户名。')).toBeTruthy()
    fireEvent.change(screen.getByLabelText('用户名'), { target: { value: 'stardust' } })
    expect(screen.queryByText('请填写用户名。')).toBeNull()
  })
})

describe('UserCreateDrawer 提交', () => {
  it('按契约发出 POST 请求并回调创建结果', async () => {
    const created: unknown[] = []
    renderDrawer({ onCreated: (user) => created.push(user) })
    fill({ displayName: '星尘' })
    submit()
    await waitFor(() => expect(created.length).toBe(1))
    expect(requests[0].path).toBe('/api/v1/admin/users')
    expect(requests[0].method).toBe('POST')
    expect(requests[0].body).toEqual({
      username: 'stardust',
      email: 'stardust@example.com',
      password: 'sufficiently-long',
      display_name: '星尘',
      role: 'user',
      status: 'active',
    })
    expect(created[0]).toEqual(CREATED)
  })

  it('显示名称留空时传 null', async () => {
    renderDrawer()
    fill({ displayName: '   ' })
    submit()
    await waitFor(() => expect(requests.length).toBe(1))
    expect(requests[0].body.display_name).toBeNull()
  })

  it('用户名和邮箱两端空格会被裁掉', async () => {
    renderDrawer()
    fill({ username: '  stardust  ', email: '  stardust@example.com  ' })
    submit()
    await waitFor(() => expect(requests.length).toBe(1))
    expect(requests[0].body.username).toBe('stardust')
    expect(requests[0].body.email).toBe('stardust@example.com')
  })

  it('409 用户名冲突落到用户名字段，且不清空已填内容', async () => {
    renderDrawer()
    fill()
    respond = () => jsonResponse({ code: 'username_already_registered' }, 409)
    submit()
    await waitFor(() => expect(screen.getByText('该用户名已被占用，请更换。')).toBeTruthy())
    expect((screen.getByLabelText('邮箱') as HTMLInputElement).value).toBe('stardust@example.com')
    expect((screen.getByLabelText('初始密码') as HTMLInputElement).value).toBe('sufficiently-long')
  })

  it('403 提示角色权限不足而不是通用无权限文案', async () => {
    renderDrawer()
    fill()
    respond = () => jsonResponse({ code: 'admin_forbidden' }, 403)
    submit()
    await waitFor(() => expect(screen.getByText(/不能创建该角色的账号/)).toBeTruthy())
  })

  it('提交期间禁用提交与取消按钮', async () => {
    renderDrawer()
    fill()
    // 请求悬挂在这个 Promise 上，断言完再放行，模拟「提交中」这一帧
    let release = () => {}
    const pending = new Promise<Response>((resolve) => { release = () => resolve(jsonResponse(CREATED, 201)) })
    vi.stubGlobal('fetch', () => pending)
    submit()
    await waitFor(() => expect((screen.getByRole('button', { name: '创建中…' }) as HTMLButtonElement).disabled).toBe(true))
    expect((screen.getByRole('button', { name: '取消' }) as HTMLButtonElement).disabled).toBe(true)
    release()
    await pending
  })
})

describe('UserCreateDrawer 角色权限', () => {
  it('有 manage_roles 时可以选管理员', async () => {
    renderDrawer()
    fill()
    fireEvent.click(screen.getByRole('combobox', { name: '角色' }))
    fireEvent.click(screen.getByRole('option', { name: '管理员' }))
    submit()
    await waitFor(() => expect(requests.length).toBe(1))
    expect(requests[0].body.role).toBe('admin')
  })

  it('缺少 manage_roles 时禁用管理员与 Owner 选项', () => {
    renderDrawer({ canManageRoles: false })
    fireEvent.click(screen.getByRole('combobox', { name: '角色' }))
    expect(screen.getByRole('option', { name: '管理员' }).getAttribute('aria-disabled')).toBe('true')
    expect(screen.getByRole('option', { name: 'Owner' }).getAttribute('aria-disabled')).toBe('true')
    expect(screen.getByRole('option', { name: '普通用户' }).getAttribute('aria-disabled')).toBeNull()
    expect(screen.getByText('当前管理身份没有 manage_roles 权限，只能创建普通用户。')).toBeTruthy()
  })

  it('状态可以改为已禁用', async () => {
    renderDrawer()
    fill()
    fireEvent.click(screen.getByRole('combobox', { name: '状态' }))
    fireEvent.click(screen.getByRole('option', { name: '已禁用' }))
    submit()
    await waitFor(() => expect(requests.length).toBe(1))
    expect(requests[0].body.status).toBe('disabled')
  })
})
